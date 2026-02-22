// M13 NODE — Orchestrator

mod engine;
mod cryptography;
mod network;

use crate::engine::protocol::*;
use crate::engine::protocol::{Assembler, FragHeader, FRAG_HDR_SIZE, send_fragmented_udp,
    alloc_asm_arena, ASM_SLOTS_PER_PEER};
use crate::engine::fec::{
    EncoderWindow, encode_parity_payload, AfecSubHeader, AFEC_SUB_HDR_SIZE, USO_MTU, MAX_K,
    SwRlncDecoder,
};
use crate::engine::runtime::{
    rdtsc_ns, calibrate_tsc,
    fatal, NodeState, HexdumpState};
use crate::cryptography::aead::{seal_frame, open_frame};
use crate::network::datapath::{create_tun, setup_tunnel_routes, teardown_tunnel_routes, teardown_all};
use crate::cryptography::handshake::{initiate_handshake, process_handshake_node};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::net::UdpSocket;
use std::os::unix::io::AsRawFd;

use ring::aead;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);
extern "C" fn signal_handler(_sig: i32) { SHUTDOWN.store(true, Ordering::Relaxed); }

/// Global Hub IP for panic hook cleanup. Set once before worker starts.
static HUB_IP_GLOBAL: Mutex<String> = Mutex::new(String::new());

/// Full teardown: tear down EVERYTHING — routes, TUN, IPv6, iptables.
/// Safe to call multiple times (idempotent). Safe to call from panic hook.
fn teardown_node() {
    teardown_all(&HUB_IP_GLOBAL);
}

// ── MAIN ───────────────────────────────────────────────────────────────────
fn main() {
    // Logs go to terminal (stderr)

    let args: Vec<String> = std::env::args().collect();
    // SAFETY: Caller ensures invariants documented at module level.
    unsafe {
        libc::signal(libc::SIGTERM, signal_handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, signal_handler as *const () as libc::sighandler_t);
    }

    // Panic hook: guarantee cleanup even on unwinding crash
    std::panic::set_hook(Box::new(|info| {
        eprintln!("[M13-NODE] PANIC: {}", info);
        teardown_node();
        std::process::exit(1);
    }));

    let echo = args.iter().any(|a| a == "--echo");
    let hexdump = args.iter().any(|a| a == "--hexdump");
    let tunnel = args.iter().any(|a| a == "--tunnel");

    // Create TUN interface if requested
    // Note: MUST be done before dropping privileges (if any)
    let tun_file = if tunnel {
        Some(create_tun("m13tun0").expect("Failed to create TUN interface"))
    } else {
        None
    };

    // Parse --hub-ip <ip:port> (required)
    let mut hub_ip = None;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--hub-ip" && i + 1 < args.len() {
            hub_ip = Some(args[i+1].clone());
        }
        i += 1;
    }

    if let Some(ip) = hub_ip {
        // Store Hub IP globally so panic hook can tear down routes
        if let Ok(mut g) = HUB_IP_GLOBAL.lock() {
            *g = ip.split(':').next().unwrap_or(&ip).to_string();
        }
        run_uring_worker(&ip, echo, hexdump, tun_file);
    } else {
         eprintln!("Usage: m13-node --hub-ip <ip:port> [--echo] [--hexdump] [--tunnel]");
         std::process::exit(1);
    }

    // Post-worker cleanup: teardown everything
    teardown_node();
}

// ── Shared RX Processing ────────────────────────────────────────────────
use std::io::{Read, Write};

/// What the transport-specific caller should do after shared RX processing.
enum RxAction {
    /// Drop the frame (invalid, failed AEAD, or consumed internally).
    Drop,
    /// Tunnel data: write payload at (start, len) to TUN device.
    TunWrite { start: usize, plen: usize },
    /// FEC parity: feed to decoder. Fields extracted from AfecSubHeader.
    Parity { base_seq: u32, k: u8, seed: u8, data_start: usize, data_len: usize },
    /// Echo: caller should build echo response using the frame.
    Echo,
    /// Handshake complete: send Finished payload, transition to Established.
    HandshakeComplete { session_key: [u8; 32], finished_payload: Vec<u8> },
    /// Handshake failed: transition to Disconnected.
    HandshakeFailed,
    /// Rekey needed: transition to Registering.
    RekeyNeeded,
    /// Registration trigger: caller should initiate handshake.
    NeedHandshakeInit,
}

/// Shared RX frame processing for both UDP and AF_XDP workers.
/// Handles: M13 validation, AEAD decrypt, rekey, flag re-read,
/// fragment reassembly, handshake processing, classify.
///
/// The frame must include the ETH header at offset 0 and M13 at ETH_HDR_SIZE.
/// For UDP, the outer UDP/IP headers are stripped before calling this.
fn process_rx_frame(
    buf: &mut [u8],
    state: &mut NodeState,
    assembler: &mut Assembler,
    _hexdump: &mut HexdumpState,
    now: u64,
    echo: bool,
    aead_fail_count: &mut u64,
) -> RxAction {
    let len = buf.len();

    if len < ETH_HDR_SIZE + M13_HDR_SIZE {
        return RxAction::Drop;
    }

    // SAFETY: Pointer arithmetic within UMEM bounds; offset validated by kernel ring descriptor.
    let m13 = unsafe { &*(buf.as_ptr().add(ETH_HDR_SIZE) as *const M13Header) };
    if m13.signature[0] != M13_WIRE_MAGIC || m13.signature[1] != M13_WIRE_VERSION {
        return RxAction::Drop;
    }

    // Registration trigger: initiate handshake on first valid Hub frame
    if matches!(state, NodeState::Registering) {
        return RxAction::NeedHandshakeInit;
    }

    // Initial flags (may be ciphertext — will re-read after decrypt)
    let flags_pre = m13.flags;

    // Pre-decrypted by batch AEAD — skip both decrypt and cleartext-reject.
    // PRE_DECRYPTED_MARKER (0x02) is stamped by decrypt_batch_ptrs on success.
    let pre_decrypted = buf[ETH_HDR_SIZE + 2] == crate::cryptography::aead::PRE_DECRYPTED_MARKER;

    if !pre_decrypted {
        // Mandatory encryption — reject cleartext data after session
        // Exempt: handshakes, fragments, and control frames (FIN/keepalive)
        if matches!(state, NodeState::Established { .. })
           && buf[ETH_HDR_SIZE + 2] != 0x01
           && flags_pre & FLAG_HANDSHAKE == 0 && flags_pre & FLAG_FRAGMENT == 0
           && flags_pre & FLAG_CONTROL == 0 {
            return RxAction::Drop; // drop cleartext data frame
        }

        // AEAD verification on encrypted frames (scalar fallback for non-batched frames)
        if buf[ETH_HDR_SIZE + 2] == 0x01 {
            if let NodeState::Established { ref cipher, ref mut frame_count, ref established_ns, ref mut highest_rx_seq, ref mut loss_q8, ref mut burst_q8, .. } = state {
                if !open_frame(buf, cipher, DIR_NODE_TO_HUB) {
                    *aead_fail_count += 1;
                    if cfg!(debug_assertions) && *aead_fail_count <= 3 {
                        eprintln!("[M13-NODE-AEAD] FAIL #{} len={} nonce={:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}:{:02x}{:02x}{:02x}{:02x}",
                            aead_fail_count, len,
                            buf[ETH_HDR_SIZE+20], buf[ETH_HDR_SIZE+21], buf[ETH_HDR_SIZE+22], buf[ETH_HDR_SIZE+23],
                            buf[ETH_HDR_SIZE+24], buf[ETH_HDR_SIZE+25], buf[ETH_HDR_SIZE+26], buf[ETH_HDR_SIZE+27],
                            buf[ETH_HDR_SIZE+28], buf[ETH_HDR_SIZE+29], buf[ETH_HDR_SIZE+30], buf[ETH_HDR_SIZE+31]);
                    }
                    return RxAction::Drop;
                }
                *frame_count += 1;

                // V3: CIF Sequence Gap Tracking — compute rx_loss_q8 and burst_q8
                {
                    let seq = m13.seq_id;
                    if *highest_rx_seq > 0 && seq > *highest_rx_seq {
                        let gap = seq - *highest_rx_seq;
                        if gap > 1 {
                            // Loss detected: (gap-1) packets missing.
                            // Exponential moving average in Q8 fixed-point.
                            let new_loss = ((gap - 1) as u16).min(255) as u8;
                            *loss_q8 = loss_q8.saturating_add(new_loss.saturating_sub(*loss_q8) >> 2);
                            *burst_q8 = burst_q8.saturating_add(new_loss.saturating_sub(*burst_q8) >> 3);
                        } else if *loss_q8 > 0 {
                            // No loss: decay towards zero
                            *loss_q8 = loss_q8.saturating_sub(1);
                        }
                    }
                    if seq > *highest_rx_seq {
                        *highest_rx_seq = seq;
                    }
                }

                // Rekey check — frame count or time limit
                if *frame_count >= REKEY_FRAME_LIMIT
                   || now.saturating_sub(*established_ns) > REKEY_TIME_LIMIT_NS {
                    eprintln!("[M13-NODE-PQC] Rekey threshold reached. Re-initiating handshake.");
                    return RxAction::RekeyNeeded;
                }
            } else {
                return RxAction::Drop; // encrypted frame but no session
            }
        }
    }
    // pre_decrypted frames: batch decrypt already verified AEAD, incremented
    // frame_count, and checked rekey. Proceed directly to flag re-read + classify.

    // CRITICAL: Re-read flags from decrypted buffer.
    // Original flags were read BEFORE decrypt — they hold ciphertext.
    let flags = buf[ETH_HDR_SIZE + 40];

    // Fragment handling
    if flags & FLAG_FRAGMENT != 0 && len >= ETH_HDR_SIZE + M13_HDR_SIZE + FRAG_HDR_SIZE {
        // SAFETY: Pointer arithmetic within valid bounds.
        let frag_hdr = unsafe { &*(buf.as_ptr().add(ETH_HDR_SIZE + M13_HDR_SIZE) as *const FragHeader) };
        // SAFETY: Using read_unaligned because FragHeader is repr(C, packed).
        let frag_msg_id = unsafe { std::ptr::addr_of!(frag_hdr.frag_msg_id).read_unaligned() };
        let frag_index = unsafe { std::ptr::addr_of!(frag_hdr.frag_index).read_unaligned() };
        let frag_total = unsafe { std::ptr::addr_of!(frag_hdr.frag_total).read_unaligned() };
        let frag_offset = unsafe { std::ptr::addr_of!(frag_hdr.frag_offset).read_unaligned() };
        let frag_data_len = unsafe { std::ptr::addr_of!(frag_hdr.frag_len).read_unaligned() } as usize;
        let frag_start = ETH_HDR_SIZE + M13_HDR_SIZE + FRAG_HDR_SIZE;
        if frag_start + frag_data_len <= len {
            // Closure IoC: capture action as Option, set inside closure on completion
            let mut action: Option<RxAction> = None;
            let has_handshake = flags & FLAG_HANDSHAKE != 0;
            assembler.feed(
                frag_msg_id, frag_index, frag_total, frag_offset, flags,
                &buf[frag_start..frag_start + frag_data_len], now,
                |reassembled| {
                    if has_handshake {
                        eprintln!("[M13-NODE] Reassembled handshake msg_id={} len={}",
                            frag_msg_id, reassembled.len());
                        if let NodeState::Established { .. } = state {
                            eprintln!("[M13-NODE-PQC] Duplicate handshake message dropped (already Established)");
                            action = Some(RxAction::Drop);
                        } else if let Some((session_key, finished_payload)) = process_handshake_node(reassembled, state) {
                            action = Some(RxAction::HandshakeComplete { session_key, finished_payload });
                        } else {
                            action = Some(RxAction::HandshakeFailed);
                        }
                    } else if cfg!(debug_assertions) {
                        eprintln!("[M13-NODE] Reassembled data msg_id={} len={}",
                            frag_msg_id, reassembled.len());
                    }
                },
            );
            if let Some(a) = action { return a; }
        }
        return RxAction::Drop; // Fragment consumed (or partial)
    }

    // Control frame — consume
    if flags & FLAG_CONTROL != 0 {
        return RxAction::Drop;
    }

    // Hub feedback — consume (node TX pacing not yet implemented)
    if flags & FLAG_FEEDBACK != 0 {
        return RxAction::Drop;
    }

    // FEC parity → extract AfecSubHeader, feed to decoder
    if flags & FLAG_FEC != 0 {
        let afec_off = ETH_HDR_SIZE + M13_HDR_SIZE;
        if len >= afec_off + AFEC_SUB_HDR_SIZE {
            let sub_hdr: AfecSubHeader = unsafe {
                std::ptr::read_unaligned(buf.as_ptr().add(afec_off) as *const AfecSubHeader)
            };
            let plen_raw = u32::from_le_bytes(buf[55..59].try_into().unwrap()) as usize;
            let parity_len = plen_raw.saturating_sub(AFEC_SUB_HDR_SIZE);
            let data_start = afec_off + AFEC_SUB_HDR_SIZE;
            if sub_hdr.k > 0 && data_start + parity_len <= len {
                return RxAction::Parity {
                    base_seq: sub_hdr.base_seq_low,
                    k: sub_hdr.k, seed: sub_hdr.seed,
                    data_start, data_len: parity_len,
                };
            }
        }
        return RxAction::Drop;
    }

    // Graceful close from hub
    if flags & FLAG_FIN != 0 {
        return RxAction::Drop;
    }

    // Tunnel data → TUN write
    if flags & FLAG_TUNNEL != 0 {
        let start = ETH_HDR_SIZE + M13_HDR_SIZE;
        let plen_bytes = &buf[55..59];
        let plen = u32::from_le_bytes(plen_bytes.try_into().unwrap()) as usize;
        if start + plen <= len {
            return RxAction::TunWrite { start, plen };
        }
        return RxAction::Drop;
    }

    // Echo
    if echo && matches!(state, NodeState::Established { .. }) {
        return RxAction::Echo;
    }

    RxAction::Drop
}

/// Read a sysctl value from /proc/sys (e.g. "net.core.rmem_max" → "/proc/sys/net/core/rmem_max").
fn read_sysctl(key: &str) -> Option<String> {
    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    std::fs::read_to_string(&path).ok().map(|s| s.trim().to_string())
}

/// Apply a sysctl and verify it took effect. Returns true if verified.
fn apply_sysctl(key: &str, value: &str) -> bool {
    let arg = format!("{}={}", key, value);
    let _ = std::process::Command::new("sysctl").args(["-w", &arg]).output();
    // Read back to verify
    match read_sysctl(key) {
        Some(actual) => actual == value,
        None => false,
    }
}

/// Pre-flight system tuning — applied once per startup (requires root).
/// Symmetric counterpart: Hub does the same in `setup_nat()`.
fn tune_system_buffers() {
    eprintln!("[M13-TUNE] Applying kernel + NIC tuning...");
    let mut ok = 0u32;
    let mut fail = 0u32;

    // 1. WiFi power save off — eliminates 20-100ms wake latency on RX.
    //    Auto-detect wireless interface from /sys/class/net/*/wireless.
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let iface = name.to_string_lossy().to_string();
            let wireless_path = format!("/sys/class/net/{}/wireless", iface);
            if std::path::Path::new(&wireless_path).exists() {
                let r = std::process::Command::new("iw")
                    .args(["dev", &iface, "set", "power_save", "off"]).output();
                if r.map(|o| o.status.success()).unwrap_or(false) {
                    eprintln!("[M13-TUNE] WiFi power_save OFF on {}", iface);
                    ok += 1;
                } else {
                    eprintln!("[M13-TUNE] WARN: WiFi power_save off failed on {}", iface);
                    fail += 1;
                }
            }
        }
    }

    // 2. Socket buffer ceiling
    for (k, v) in [
        ("net.core.rmem_max", "8388608"), ("net.core.wmem_max", "8388608"),
        ("net.core.rmem_default", "4194304"), ("net.core.wmem_default", "4194304"),
    ] { if apply_sysctl(k, v) { ok += 1; } else { fail += 1; eprintln!("[M13-TUNE] WARN: {} failed", k); } }

    // 3. NAPI budget
    for (k, v) in [("net.core.netdev_budget", "600"), ("net.core.netdev_budget_usecs", "8000")] {
        if apply_sysctl(k, v) { ok += 1; } else { fail += 1; eprintln!("[M13-TUNE] WARN: {} failed", k); }
    }

    // 4. Backlog queue
    if apply_sysctl("net.core.netdev_max_backlog", "10000") { ok += 1; } else { fail += 1; }

    // 5. BBR congestion control
    if apply_sysctl("net.ipv4.tcp_congestion_control", "bbr") { ok += 1; } else { fail += 1; eprintln!("[M13-TUNE] WARN: BBR not available"); }

    // 6. Don't cache stale TCP metrics
    if apply_sysctl("net.ipv4.tcp_no_metrics_save", "1") { ok += 1; } else { fail += 1; }

    // 7. MTU probing (mode 1 = probe on black hole detection)
    if apply_sysctl("net.ipv4.tcp_mtu_probing", "1") { ok += 1; } else { fail += 1; }

    if fail == 0 {
        eprintln!("[M13-TUNE] ✓ Optimisation Applied ({} sysctls verified)", ok);
    } else {
        eprintln!("[M13-TUNE] ⚠ Optimisation Partial ({}/{} applied, {} failed)", ok, ok + fail, fail);
    }
}

#[allow(dead_code)] // Legacy recvmmsg/sendmmsg fallback — retained for systems without Kernel 6.12+.
fn run_udp_worker(hub_addr: &str, echo: bool, hexdump_mode: bool, mut tun: Option<std::fs::File>) {
    let cal = calibrate_tsc();

    // ── Pre-flight: kernel + NIC tuning (before socket creation) ─────────
    tune_system_buffers();

    let sock = UdpSocket::bind("0.0.0.0:0")
        .unwrap_or_else(|_| fatal(0x30, "UDP bind failed"));
    sock.connect(hub_addr)
        .unwrap_or_else(|_| fatal(0x31, "UDP connect failed"));
    // O_NONBLOCK for recvmmsg busy-drain
    // Preserve existing flags (F_GETFL) then OR in O_NONBLOCK — never clobber.
    let raw_fd = sock.as_raw_fd();
    // SAFETY: Caller ensures invariants documented at module level.
    unsafe {
        let flags = libc::fcntl(raw_fd, libc::F_GETFL);
        libc::fcntl(raw_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);

        // Socket buffer tuning — prevent burst drops.
        // Hub sends via AF_XDP at wire speed (bursts of 64+ packets per tick).
        // Default SO_RCVBUF (~208KB) overflows → silent UDP drops → TCP loss
        // → cwnd collapse → stall → slow start → "ticking" behavior.
        // 8MB absorbs ~5400 packets of burst at 1500B each.
        // SO_RCVBUFFORCE bypasses net.core.rmem_max (requires CAP_NET_ADMIN / root).
        let buf_sz: libc::c_int = 8 * 1024 * 1024; // 8MB
        libc::setsockopt(
            raw_fd, libc::SOL_SOCKET, libc::SO_RCVBUFFORCE,
            &buf_sz as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        libc::setsockopt(
            raw_fd, libc::SOL_SOCKET, libc::SO_SNDBUFFORCE,
            &buf_sz as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );

        const SO_BUSY_POLL: i32 = 46;
        let poll_us: i32 = 100; // 100µs busy poll
        let ret = libc::setsockopt(raw_fd, libc::SOL_SOCKET, SO_BUSY_POLL, &poll_us as *const _ as *const libc::c_void, 4);
        if ret != 0 {
            libc::write(2, b"[M13-WARN] SO_BUSY_POLL not supported. Latency variance increased.\n".as_ptr() as _, 68);
        }
    }

    // Extract Hub IP (without port) for routing
    let hub_ip = hub_addr.split(':').next().unwrap_or(hub_addr).to_string();

    let mut seq_tx: u64 = 0;
    let mut rx_count: u64 = 0;
    let mut tx_count: u64 = 0;
    let mut aead_fail_count: u64 = 0;
    let mut aead_ok_count: u64 = 0;
    let mut tun_read_count: u64 = 0;
    let mut tun_write_count: u64 = 0;

    let mut hexdump = HexdumpState::new(hexdump_mode);
    let asm_arena = alloc_asm_arena(ASM_SLOTS_PER_PEER);
    let mut assembler = Assembler::init(asm_arena);

    let mut last_report_ns: u64 = rdtsc_ns(&cal);
    let mut last_keepalive_ns: u64 = 0;
    let mut gc_counter: u64 = 0;
    let mut routes_installed = false;
    let start_ns = rdtsc_ns(&cal);
    
    // Encoder window (reused between batches)
    let mut tx_window = EncoderWindow::new();

    let src_mac: [u8; 6] = detect_mac(None); // No local NIC in UDP mode
    let hub_mac: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]; // broadcast — Hub identifies by addr

    eprintln!("[M13-NODE-UDP] Connected to {}. Echo={} Hexdump={}", hub_addr, echo, hexdump_mode);

    // Registration: send first frame to establish return path
    let reg = build_m13_frame(&src_mac, &hub_mac, seq_tx, FLAG_CONTROL);
    seq_tx += 1;
    if sock.send(&reg).is_ok() { tx_count += 1; }
    hexdump.dump_tx(&reg, rdtsc_ns(&cal));
    let mut state = NodeState::Registering;

    // 128KB rx_bufs + iovecs + mmsghdr — init once, not per-tick (cache thrashing prevention)
    const RX_BATCH: usize = 64;
    let mut rx_bufs = Box::new([[0u8; 2048]; RX_BATCH]);
    // SAFETY: Type is repr(C) and all-zeroes is a valid bit pattern.
    let mut rx_iovecs: [libc::iovec; RX_BATCH] = unsafe { std::mem::zeroed() };
    let mut rx_msgs: [libc::mmsghdr; RX_BATCH] = unsafe { std::mem::zeroed() };
    for i in 0..RX_BATCH {
        rx_iovecs[i].iov_base = rx_bufs[i].as_mut_ptr() as *mut libc::c_void;
        rx_iovecs[i].iov_len = 2048;
        rx_msgs[i].msg_hdr.msg_iov = &mut rx_iovecs[i] as *mut libc::iovec;
        rx_msgs[i].msg_hdr.msg_iovlen = 1;
    }

    // 100KB tx_bufs + iovecs + mmsghdr — pre-allocated for single-syscall flush
    const TUN_BATCH: usize = 64;
    let mut tx_bufs = Box::new([[0u8; 1600]; TUN_BATCH]);
    let mut tx_lens: [usize; TUN_BATCH] = [0; TUN_BATCH];
    // SAFETY: Type is repr(C) and all-zeroes is a valid bit pattern.
    let mut tx_iovecs: [libc::iovec; TUN_BATCH] = unsafe { std::mem::zeroed() };
    let mut tx_msgs: [libc::mmsghdr; TUN_BATCH] = unsafe { std::mem::zeroed() };

    // Avoids per-packet fill(0) of 30-byte signature region + 6 field writes.
    let mut hdr_template = [0u8; 62];
    hdr_template[0..6].copy_from_slice(&hub_mac);
    hdr_template[6..12].copy_from_slice(&src_mac);
    hdr_template[12] = (ETH_P_M13 >> 8) as u8;
    hdr_template[13] = (ETH_P_M13 & 0xFF) as u8;
    hdr_template[14] = M13_WIRE_MAGIC;
    hdr_template[15] = M13_WIRE_VERSION;
    // bytes 16..62 already 0 from array init

    // Gather-defer-flush: collect (rx_index, start, len) during RX classify,
    // flush all TUN writes in a tight sequential loop AFTER classify completes.
    // Eliminates syscall/classify interleaving — keeps L1d cache hot.
    const TUN_WR_BATCH: usize = 64; // matches RX_BATCH
    let mut tun_wr_indices: [u8; TUN_WR_BATCH] = [0; TUN_WR_BATCH];
    let mut tun_wr_starts: [u16; TUN_WR_BATCH] = [0; TUN_WR_BATCH];
    let mut tun_wr_lens: [u16; TUN_WR_BATCH] = [0; TUN_WR_BATCH];

    let mut fec_pacing_counter: usize = 0; // State for Sliding Window RLNC Parity Injection

    loop {
        if SHUTDOWN.load(Ordering::Relaxed) { break; }
        let now = rdtsc_ns(&cal);

        // Connection timeout (30s) if not established
        if !matches!(state, NodeState::Established { .. })
            && now.saturating_sub(start_ns) > 30_000_000_000 {
                eprintln!("[M13-NODE-UDP] Connection timed out (30s). Exiting.");
                break;
            }

        // Arrays pre-allocated outside loop — no per-tick memset (cache-friendly).
        // SAFETY: Caller ensures invariants documented at module level.
        let rx_n = unsafe {
            libc::recvmmsg(raw_fd, rx_msgs.as_mut_ptr(), RX_BATCH as u32,
                           libc::MSG_DONTWAIT, std::ptr::null_mut())
        };
        let rx_batch_count = if rx_n > 0 { rx_n as usize } else { 0 };
        let mut tun_wr_count: usize = 0; // reset per tick
        // FEC tracking arrays — stack-allocated, zero heap allocation
        let mut fec_data_count: usize = 0;
        let mut fec_parity_count: usize = 0;
        let mut fec_data_seq: [u32; RX_BATCH] = [0; RX_BATCH];
        let mut fec_data_buf: [u8; RX_BATCH] = [0; RX_BATCH];
        let mut fec_data_start: [u16; RX_BATCH] = [0; RX_BATCH];
        let mut fec_data_len: [u16; RX_BATCH] = [0; RX_BATCH];
        let mut fec_parity_k = [0u8; RX_BATCH];
    let mut fec_parity_seed = [0u8; RX_BATCH];
    let mut fec_parity_base_seq = [0u32; RX_BATCH];
        let mut fec_parity_buf: [u8; RX_BATCH] = [0; RX_BATCH];
        let mut fec_parity_start: [u16; RX_BATCH] = [0; RX_BATCH];
        let mut fec_parity_len: [u16; RX_BATCH] = [0; RX_BATCH];

        // Phase 1: Vectorized AEAD batch decrypt pre-pass
        // Identify encrypted frames, batch-decrypt with 4-at-a-time AES-NI/ARMv8-CE prefetch.
        // decrypt_one stamps PRE_DECRYPTED_MARKER (0x02) on success — process_rx_frame
        // recognizes it and skips both decrypt and cleartext-reject.
        if rx_batch_count > 0 {
            if let NodeState::Established { ref cipher, ref mut frame_count, ref established_ns, .. } = state {
                // Stack-allocated: zero heap allocation on hot path
                let mut enc_ptrs: [*mut u8; RX_BATCH] = [std::ptr::null_mut(); RX_BATCH];
                let mut enc_lens: [usize; RX_BATCH] = [0; RX_BATCH];
                let mut enc_count: usize = 0;
                for rx_i in 0..rx_batch_count {
                    let len = rx_msgs[rx_i].msg_len as usize;
                    if len >= ETH_HDR_SIZE + 40 && rx_bufs[rx_i][ETH_HDR_SIZE + 2] == 0x01 {
                        enc_ptrs[enc_count] = rx_bufs[rx_i].as_mut_ptr();
                        enc_lens[enc_count] = len;
                        enc_count += 1;
                    }
                }

                if enc_count > 0 {
                    let mut decrypt_results = [false; RX_BATCH];
                    let ok = crate::cryptography::aead::decrypt_batch_ptrs(
                        &enc_ptrs, &enc_lens, enc_count, cipher, DIR_NODE_TO_HUB,
                        &mut decrypt_results[..enc_count],
                    );
                    // decrypt_one stamps PRE_DECRYPTED_MARKER on successes automatically.
                    // Failures keep 0x01 → process_rx_frame scalar fallback.
                    *frame_count += ok as u64;
                    aead_ok_count += ok as u64;

                    // Rekey check after batch
                    if *frame_count >= REKEY_FRAME_LIMIT
                       || now.saturating_sub(*established_ns) > REKEY_TIME_LIMIT_NS {
                        eprintln!("[M13-NODE-PQC] Rekey threshold reached (batch). Re-initiating handshake.");
                        state = NodeState::Registering;
                    }
                }
            }
        }

        for rx_i in 0..rx_batch_count {
            let len = rx_msgs[rx_i].msg_len as usize;
            let buf = &mut rx_bufs[rx_i][..len];
            rx_count += 1;

            hexdump.dump_rx(buf, now);

            // Disconnected → Registering on any valid frame
            if matches!(state, NodeState::Disconnected) {
                state = NodeState::Registering;
            }

            let action = process_rx_frame(buf, &mut state, &mut assembler,
                &mut hexdump, now, echo, &mut aead_fail_count);

            match action {
                RxAction::NeedHandshakeInit => {
                    state = initiate_handshake(
                        &sock, &src_mac, &hub_mac, &mut seq_tx, &mut hexdump, &cal,
                    );
                    if cfg!(debug_assertions) { eprintln!("[M13-NODE-UDP] → Handshaking (PQC ClientHello sent)"); }
                }
                RxAction::TunWrite { start, plen } => {
                    if tun.is_some() && tun_wr_count < TUN_WR_BATCH {
                        tun_wr_indices[tun_wr_count] = rx_i as u8;
                        tun_wr_starts[tun_wr_count] = start as u16;
                        tun_wr_lens[tun_wr_count] = plen as u16;
                        tun_wr_count += 1;
                        tun_write_count += 1;
                    }
                    // Track data frame for FEC decoder (seq_id from decrypted M13 header)
                    if fec_data_count < RX_BATCH {
                        let seq_bytes: [u8; 8] = rx_bufs[rx_i][ETH_HDR_SIZE + 32..ETH_HDR_SIZE + 40]
                            .try_into().unwrap_or([0; 8]);
                        fec_data_seq[fec_data_count] = u64::from_le_bytes(seq_bytes) as u32;
                        fec_data_buf[fec_data_count] = rx_i as u8;
                        fec_data_start[fec_data_count] = start as u16;
                        fec_data_len[fec_data_count] = plen as u16;
                        fec_data_count += 1;
                    }
                }
                RxAction::Echo => {
                    if let Some(mut echo_frame) = build_echo_frame(buf, seq_tx) {
                        if let NodeState::Established { ref cipher, ref session_key, .. } = state {
                            if *session_key != [0u8; 32] {
                                seal_frame(&mut echo_frame, cipher, seq_tx, DIR_NODE_TO_HUB);
                            }
                        }
                        seq_tx += 1;
                        hexdump.dump_tx(&echo_frame, now);
                        if sock.send(&echo_frame).is_ok() { tx_count += 1; }
                    }
                }
                RxAction::HandshakeComplete { session_key, finished_payload } => {
                    let hs_flags = FLAG_CONTROL | FLAG_HANDSHAKE;
                    // DEFECT β FIXED: Closure captures sock, hexdump, tx_count.
                    let mut sent_frags = 0u64;
                    send_fragmented_udp(
                        &src_mac, &hub_mac,
                        &finished_payload, hs_flags,
                        &mut seq_tx,
                        |frame| {
                            hexdump.dump_tx(frame, now);
                            let _ = sock.send(frame);
                            tx_count += 1;
                            sent_frags += 1;
                        }
                    );
                    if cfg!(debug_assertions) {
                        eprintln!("[M13-NODE-PQC] Finished sent: {}B, {} fragments",
                            finished_payload.len(), sent_frags);
                    }

                    state = NodeState::Established {
                        session_key,
                        cipher: Box::new(aead::LessSafeKey::new(
                            aead::UnboundKey::new(&aead::AES_256_GCM, &session_key).unwrap()
                        )),
                        frame_count: 0,
                        established_ns: now,
                        fec_decoder: SwRlncDecoder::new_boxed(),
                        highest_rx_seq: 0,
                        loss_q8: 0,
                        burst_q8: 0,
                    };
                    if cfg!(debug_assertions) { eprintln!("[M13-NODE-PQC] → Established (session key derived, AEAD active)"); }

                    if tun.is_some() && !routes_installed {
                        setup_tunnel_routes(&hub_ip);
                        routes_installed = true;
                    }
                }
                RxAction::HandshakeFailed => {
                    eprintln!("[M13-NODE-PQC] Handshake processing failed → Disconnected");
                    state = NodeState::Disconnected;
                }
                RxAction::RekeyNeeded => {
                    state = NodeState::Registering;
                }
                RxAction::Parity { base_seq, k, seed, data_start, data_len } => {
                    if fec_parity_count < RX_BATCH {
                        fec_parity_base_seq[fec_parity_count] = base_seq;
                        fec_parity_k[fec_parity_count] = k;
                        fec_parity_seed[fec_parity_count] = seed;
                        fec_parity_buf[fec_parity_count] = rx_i as u8;
                        fec_parity_start[fec_parity_count] = data_start as u16;
                        fec_parity_len[fec_parity_count] = data_len as u16;
                        fec_parity_count += 1;
                    }
                }
                RxAction::Drop => {} // consumed or invalid
            }
        }

        // All tunnel packets collected during classify are written here.
        // Tight sequential loop — cache-friendly, branch-predictor-friendly.
        if tun_wr_count > 0 {
            if let Some(ref mut tun_file) = tun {
                for ti in 0..tun_wr_count {
                    let ri = tun_wr_indices[ti] as usize;
                    let s = tun_wr_starts[ti] as usize;
                    let l = tun_wr_lens[ti] as usize;
                    let _ = tun_file.write(&rx_bufs[ri][s..s + l]);
                }
            }
        }

        // FEC recovery pass — attempt to recover lost data frames from parity
        if fec_parity_count > 0 && fec_data_count > 0 {
            if let NodeState::Established { ref mut fec_decoder, .. } = state {
                // Force-align decoder window to the exact VPP block bounds
                let ref_base = fec_parity_base_seq[0];
                if fec_decoder.base_seq != ref_base
                    && ref_base.wrapping_sub(fec_decoder.base_seq) as i32 > 0 {
                        // Forward jump: clear decode matrix for new block
                        fec_decoder.row_present = 0;
                        fec_decoder.deliver_next = 0;
                        fec_decoder.base_seq = ref_base;
                }

                // Feed systematic (data) frames — marks slots as received
                for di in 0..fec_data_count {
                    let seq = fec_data_seq[di];
                    let rel = seq.wrapping_sub(fec_decoder.base_seq) as usize;
                    if rel < MAX_K {
                        let bi = fec_data_buf[di] as usize;
                        let s = fec_data_start[di] as usize;
                        let l = fec_data_len[di] as usize;
                        fec_decoder.ingest_systematic(rel, &rx_bufs[bi][s..s + l]);
                    }
                }
                let pre_mask = fec_decoder.row_present;

                // Feed parity frames — enables recovery of missing systematic slots
                for pi in 0..fec_parity_count {
                    let bi = fec_parity_buf[pi] as usize;
                    let s = fec_parity_start[pi] as usize;
                    let l = fec_parity_len[pi] as usize;
                    fec_decoder.ingest_parity(
                        fec_parity_seed[pi], fec_parity_k[pi] as usize,
                        &rx_bufs[bi][s..s + l],
                    );
                }

                let recovered_mask = fec_decoder.row_present & !pre_mask;

                // Deliver purely recovered frames to TUN
                if let Some(ref mut tun_file) = tun {
                    for rel in 0..MAX_K {
                        if (recovered_mask & (1u8 << rel)) != 0 {
                            let recovered = fec_decoder.get_payload(rel);
                            // Extract IP total length for correct TUN write size
                            let ip_ver = recovered[0] >> 4;
                            let ip_len = match ip_ver {
                                4 => u16::from_be_bytes([recovered[2], recovered[3]]) as usize,
                                6 => 40 + u16::from_be_bytes([recovered[4], recovered[5]]) as usize,
                                _ => 0,
                            };
                            if ip_len > 0 && ip_len <= recovered.len() {
                                let _ = tun_file.write(&recovered[..ip_len]);
                                tun_write_count += 1;
                            }
                        }
                    }
                }
            }
        }

        if let NodeState::Handshaking { ref mut started_ns, ref client_hello_bytes, .. } = state {
            // SURGICAL PATCH: Replace 5-second constant with 250ms Micro-ARQ boundary.
            // Eradicates the 5-second dead-trap and ensures rapid retransmission.
            if now.saturating_sub(*started_ns) > HANDSHAKE_RETX_INTERVAL_NS {
                eprintln!("[M13-NODE-PQC] Handshake timeout (2000ms). Retransmitting...");

                let hs_flags = FLAG_CONTROL | FLAG_HANDSHAKE;
                let mut seq_cap = seq_tx;

                send_fragmented_udp(
                    &src_mac, &hub_mac,
                    client_hello_bytes, hs_flags,
                    &mut seq_cap,
                    |frame| {
                        hexdump.dump_tx(frame, now);
                        let _ = sock.send(frame);
                        tx_count += 1;
                    }
                );

                seq_tx = seq_cap;
                *started_ns = now; // Reset timer without recomputing NTT math
            }
        }

        // === Keepalive — only during registration/handshake (100ms) ===
        // Once Established, TUN data traffic maintains NAT hole naturally.
        // Keepalives STOP when session is up.
        if !matches!(state, NodeState::Established { .. })
            && (now.saturating_sub(last_keepalive_ns) > 100_000_000 || tx_count == 0) {
                last_keepalive_ns = now;
                let ka = build_m13_frame(&src_mac, &hub_mac, seq_tx, FLAG_CONTROL);
                seq_tx += 1;
                if sock.send(&ka).is_ok() { tx_count += 1; }
            }

        // === Telemetry: report every second ===
        if now.saturating_sub(last_report_ns) > 1_000_000_000 {
            let state_label = match &state {
                NodeState::Registering => "Reg",
                NodeState::Handshaking { .. } => "HS",
                NodeState::Established { .. } => "Est",
                NodeState::Disconnected => "Disc",
            };
            eprintln!("[M13-N0] RX:{} TX:{} TUN_R:{} TUN_W:{} AEAD_OK:{} FAIL:{} State:{} Up:{}s",
                rx_count, tx_count, tun_read_count, tun_write_count, aead_ok_count, aead_fail_count, state_label,
                match &state { NodeState::Established { established_ns, .. } => (now - established_ns) / 1_000_000_000, _ => (now - start_ns) / 1_000_000_000 });
            last_report_ns = now;
            gc_counter += 1;
            if gc_counter.is_multiple_of(5) { assembler.gc(now); }
        }

        if let Some(ref mut tun_file) = tun {
            // Only forward if session established
            if let NodeState::Established { ref cipher, .. } = state {
                // TX arrays pre-allocated outside loop — no per-tick memset.
                let mut tx_count_batch: usize = 0;

                // Phase 1: Batch TUN read — collect all frames before encrypting
                for _ in 0..TUN_BATCH {
                    let frame = &mut tx_bufs[tx_count_batch];
                    // Zero-copy TUN → tx_buf: read directly into payload region (offset 62)
                    match tun_file.read(&mut frame[62..1562]) {
                        Ok(n) if n > 0 => {
                            // Copy pre-built header template (static 46 bytes)
                            frame[0..46].copy_from_slice(&hdr_template[0..46]);
                            let frame_seq = seq_tx + tx_count_batch as u64;
                            frame[46..54].copy_from_slice(&frame_seq.to_le_bytes());
                            frame[54] = FLAG_TUNNEL;
                            frame[55..59].copy_from_slice(&(n as u32).to_le_bytes());
                            // V3: CIF telemetry stamp — loss_q8 at [59], burst_q8 at [60]
                            if let NodeState::Established { loss_q8, burst_q8, .. } = &state {
                                frame[59] = *loss_q8;
                                frame[60] = *burst_q8;
                                frame[61] = 0;
                            } else {
                                frame[59..62].copy_from_slice(&hdr_template[59..62]);
                            }

                            tx_lens[tx_count_batch] = 62 + n;
                            tun_read_count += 1;
                            tx_count_batch += 1;
                        }
                        _ => break, // WouldBlock or EOF — drain complete
                    }
                }

                // Phase 2: Vectorized AEAD encrypt — 4-at-a-time prefetch saturates AES-NI/ARMv8-CE
                // Then batch flush via sendmmsg — single syscall for all TUN packets
                if tx_count_batch > 0 {
                    let seq_base = seq_tx;
                    // Stack-allocated: zero heap allocation on hot path
                    let mut enc_ptrs: [*mut u8; TUN_BATCH] = [std::ptr::null_mut(); TUN_BATCH];
                    for i in 0..tx_count_batch {
                        enc_ptrs[i] = tx_bufs[i].as_mut_ptr();
                    }

                    // ── FEC ENCODE: Sliding Window RLNC Parity Generation ───
                    // Replaces the stale block-based m=(k+7)/8 logic. 
                    // Maintains a continuous window over the stream, paced at 25% max overhead
                    // (1 parity per 4 data frames) to prevent self-DOS.
                    let k = tx_count_batch;
                    let mut parity_count: usize = 0;
                    
                    // V6: DYNAMIC REDUNDANCY BOUNDS (Inverted Physics)
                    let target_pacing = if let NodeState::Established { loss_q8, burst_q8, .. } = &state {
                        if (*loss_q8 == 0 && *burst_q8 == 0) || *loss_q8 > 12 {
                            1 // 100% Redundancy baseline (Perfect Link OR High-Loss Regime)
                        } else {
                            // Scale down parity as loss goes up (assuming bufferbloat caused it)
                            // This matches the Hub's DRL behavior before it kicks in completely.
                            std::cmp::max(1, *loss_q8 as usize / 4)
                        }
                    } else {
                        1 // Max redundancy before telemetry establishes
                    };
                    
                    if k > 0 && target_pacing > 0 {
                        for wi in 0..k {
                            // Push systematic packet into sliding window
                            let payload_ptr = tx_bufs[wi].as_ptr().wrapping_add(62);
                            let plen = (tx_lens[wi] - 62).min(USO_MTU);
                            // SAFETY: payload_ptr computed from bounds-checked tx_bufs.
                            unsafe { tx_window.push(payload_ptr, plen); }
                            
                            fec_pacing_counter += 1;
                            // Inject parity if pacing threshold met and there's buffer space
                            if fec_pacing_counter >= target_pacing && k + parity_count < TUN_BATCH {
                                fec_pacing_counter = 0;
                                
                                // V5: Verbose Terminal Tracker
                                if std::env::var("M13_DRL_DEBUG").is_ok() {
                                    eprintln!("[M13-N-DRL] Event: Parity Generated | Threshold Pacing: 1 per {}", target_pacing);
                                }
                            
                            let seed = (parity_count + 1) as u8;
                            let slot = k + parity_count;
                            let fec_payload_len = USO_MTU.min(1600 - 62 - AFEC_SUB_HDR_SIZE);
                            let frame = &mut tx_bufs[slot];
                            
                            // Build M13 header from template
                            frame[0..46].copy_from_slice(&hdr_template[0..46]);
                            let parity_seq = seq_tx + slot as u64;
                            frame[46..54].copy_from_slice(&parity_seq.to_le_bytes());
                            frame[54] = FLAG_FEC | FLAG_TUNNEL;
                            let total_payload = (AFEC_SUB_HDR_SIZE + fec_payload_len) as u32;
                            frame[55..59].copy_from_slice(&total_payload.to_le_bytes());
                            frame[59..62].copy_from_slice(&hdr_template[59..62]);
                            
                            // Write AfecSubHeader at payload start
                            let sub_hdr = AfecSubHeader {
                                base_seq_low: seq_base as u32,
                                k: tx_window.count,
                                parity_idx: parity_count as u8,
                                seed,
                                density: 0xFF,
                            };
                            unsafe {
                                std::ptr::write_unaligned(
                                    frame.as_mut_ptr().add(62) as *mut AfecSubHeader,
                                    sub_hdr,
                                );
                            }
                            
                            // Zero + generate FEC parity data from the current Sliding Window
                            let parity_data = &mut frame[62 + AFEC_SUB_HDR_SIZE..62 + AFEC_SUB_HDR_SIZE + fec_payload_len];
                            for b in parity_data.iter_mut() { *b = 0; }
                            encode_parity_payload(parity_data, &tx_window, tx_window.count as usize, seed);
                            
                            tx_lens[slot] = 62 + AFEC_SUB_HDR_SIZE + fec_payload_len;
                            enc_ptrs[slot] = tx_bufs[slot].as_mut_ptr();
                            parity_count += 1;
                        }
                    }
                }
                    let total_frames = tx_count_batch + parity_count;

                    crate::cryptography::aead::encrypt_batch_ptrs(
                        &enc_ptrs, &tx_lens, total_frames,
                        cipher, DIR_NODE_TO_HUB, seq_base,
                    );
                    seq_tx += total_frames as u64;

                    for i in 0..total_frames {
                        tx_iovecs[i].iov_base = tx_bufs[i].as_mut_ptr() as *mut libc::c_void;
                        tx_iovecs[i].iov_len = tx_lens[i];
                        tx_msgs[i].msg_hdr.msg_iov = &mut tx_iovecs[i] as *mut libc::iovec;
                        tx_msgs[i].msg_hdr.msg_iovlen = 1;
                    }
                    // SAFETY: Caller ensures invariants documented at module level.
                    let sent = unsafe {
                        libc::sendmmsg(raw_fd, tx_msgs.as_mut_ptr(), total_frames as u32, 0)
                    };
                    if sent > 0 { tx_count += sent as u64; }
                }
            }
        }
    }
    // Teardown routes on exit
    if routes_installed {
        teardown_tunnel_routes(&hub_ip);
    }
    let final_up_s = match &state { NodeState::Established { established_ns, .. } => (rdtsc_ns(&cal) - established_ns) / 1_000_000_000, _ => (rdtsc_ns(&cal) - start_ns) / 1_000_000_000 };
    eprintln!("[M13-N0] Shutdown. RX:{} TX:{} TUN_R:{} TUN_W:{} AEAD_OK:{} FAIL:{} Up:{}s",
        rx_count, tx_count, tun_read_count, tun_write_count, aead_ok_count, aead_fail_count, final_up_s);
}

// ── io_uring SQPOLL Worker (R-02B: Zero-Syscall Datapath) ──────────────
// Replaces run_udp_worker. Uses UringReactor for ALL network I/O.
// CQE-driven event loop: multishot recv for UDP RX, staged SQEs for TX.
// State machine (handshake, keepalive, rekey, route install) is identical.
fn run_uring_worker(hub_addr: &str, echo: bool, hexdump_mode: bool, tun: Option<std::fs::File>) {
    use crate::network::uring_reactor::*;

    let cal = calibrate_tsc();
    tune_system_buffers();

    // UDP socket — connected mode for sendto-free operation
    let sock = UdpSocket::bind("0.0.0.0:0")
        .unwrap_or_else(|_| fatal(0x30, "UDP bind failed"));
    sock.connect(hub_addr)
        .unwrap_or_else(|_| fatal(0x31, "UDP connect failed"));

    let raw_fd = sock.as_raw_fd();
    unsafe {
        let flags = libc::fcntl(raw_fd, libc::F_GETFL);
        libc::fcntl(raw_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        let buf_sz: libc::c_int = 8 * 1024 * 1024;
        libc::setsockopt(raw_fd, libc::SOL_SOCKET, libc::SO_RCVBUFFORCE,
            &buf_sz as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t);
        libc::setsockopt(raw_fd, libc::SOL_SOCKET, libc::SO_SNDBUFFORCE,
            &buf_sz as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t);
            
        const SO_BUSY_POLL: i32 = 46;
        let poll_us: i32 = 100; // 100µs busy poll
        let ret = libc::setsockopt(raw_fd, libc::SOL_SOCKET, SO_BUSY_POLL, &poll_us as *const _ as *const libc::c_void, 4);
        if ret != 0 {
            libc::write(2, b"[M13-WARN] SO_BUSY_POLL not supported. Latency variance increased.\n".as_ptr() as _, 68);
        }
    }

    let hub_ip = hub_addr.split(':').next().unwrap_or(hub_addr).to_string();

    // Initialize io_uring reactor (SQPOLL on CPU 0)
    let mut reactor = UringReactor::new(raw_fd, 0);
    eprintln!("[M13-NODE-URING] io_uring PBR reactor initialized. SQPOLL active.");

    // TUN fd for io_uring ops
    let tun_fd: i32 = tun.as_ref().map(|f| f.as_raw_fd()).unwrap_or(-1);

    // Arm initial TUN reads using BIDs in [UDP_RING_ENTRIES .. TOTAL_BIDS)
    if tun_fd >= 0 {
        for bid in UDP_RING_ENTRIES as u16..(UDP_RING_ENTRIES + TUN_RX_ENTRIES) as u16 {
            reactor.arm_tun_read(tun_fd, bid);
        }
        reactor.submit();
    }

    let mut seq_tx: u64 = 0;
    let mut rx_count: u64 = 0;
    let mut tx_count: u64 = 0;
    let mut aead_fail_count: u64 = 0;
    let mut aead_ok_count: u64 = 0;
    let mut tun_read_count: u64 = 0;
    let mut tun_write_count: u64 = 0;
    let mut fec_pacing_counter: usize = 0;
    
    let mut hexdump = HexdumpState::new(hexdump_mode);
    let asm_arena = alloc_asm_arena(ASM_SLOTS_PER_PEER);
    let mut assembler = Assembler::init(asm_arena);
    let mut last_report_ns: u64 = rdtsc_ns(&cal);
    let mut last_keepalive_ns: u64 = 0;
    let mut gc_counter: u64 = 0;
    let mut routes_installed = false;
    let start_ns = rdtsc_ns(&cal);

    let src_mac: [u8; 6] = detect_mac(None);
    let hub_mac: [u8; 6] = [0xFF; 6];

    // Registration frame via legacy send (before main CQE loop)
    let reg = build_m13_frame(&src_mac, &hub_mac, seq_tx, FLAG_CONTROL);
    seq_tx += 1;
    if sock.send(&reg).is_ok() { tx_count += 1; }
    hexdump.dump_tx(&reg, rdtsc_ns(&cal));
    let mut state = NodeState::Registering;

    // Pre-built M13 header template for TUN TX path
    let mut hdr_template = [0u8; 62];
    hdr_template[0..6].copy_from_slice(&hub_mac);
    hdr_template[6..12].copy_from_slice(&src_mac);
    hdr_template[12] = (ETH_P_M13 >> 8) as u8;
    hdr_template[13] = (ETH_P_M13 & 0xFF) as u8;
    hdr_template[14] = M13_WIRE_MAGIC;
    hdr_template[15] = M13_WIRE_VERSION;

    eprintln!("[M13-NODE-URING] Connected to {}. Echo={} Hexdump={}", hub_addr, echo, hexdump_mode);

    loop {
        if SHUTDOWN.load(Ordering::Relaxed) { break; }
        let now = rdtsc_ns(&cal);

        // Connection timeout
        if !matches!(state, NodeState::Established { .. })
            && now.saturating_sub(start_ns) > 30_000_000_000 {
            eprintln!("[M13-NODE-URING] Connection timed out (30s). Exiting.");
            break;
        }

        // ══════════════════════════════════════════════════════════
        // VPP (Vector Packet Processing) — Three-Pass CQE Pipeline
        // Industry pattern (DPDK, FD.io/VPP, Cloudflare flowtrackd):
        //   Pass 0: Drain CQEs, classify (recv batch vs non-recv inline)
        //   Pass 1: Vectorized AEAD batch decrypt (4-at-a-time AES-NI)
        //   Pass 2: Per-frame process_rx_frame → RxAction dispatch
        // Never interleave classify → crypto → I/O. Each phase runs
        // over the full batch, keeping the functional unit thermally hot.
        // ══════════════════════════════════════════════════════════

        // ── Pass 0: CQE Drain + Classify ───────────────────────
        reactor.ring.completion().sync();
        const MAX_CQE: usize = 128;
        let mut cqe_batch: [(i32, u32, u64); MAX_CQE] = [(0, 0, 0); MAX_CQE];
        let mut cqe_count = 0usize;
        for cqe in reactor.ring.completion() {
            if cqe_count < MAX_CQE {
                cqe_batch[cqe_count] = (cqe.result(), cqe.flags(), cqe.user_data());
                cqe_count += 1;
            }
        }

        // Separate recv CQEs (batch-processable) from non-recv (handle inline)
        let mut recv_bids: [u16; MAX_CQE] = [0; MAX_CQE];
        let mut recv_lens: [usize; MAX_CQE] = [0; MAX_CQE];
        let mut recv_flags: [u32; MAX_CQE] = [0; MAX_CQE];
        let mut recv_count: usize = 0;
        let mut multishot_needs_rearm = false;

        // V3 Vectorized Staging for TUN read -> UDP send
        const TUN_STAGE_MAX: usize = 64;
        let mut tun_stage_bids: [u16; TUN_STAGE_MAX] = [0; TUN_STAGE_MAX];
        let mut tun_stage_lens: [usize; TUN_STAGE_MAX] = [0; TUN_STAGE_MAX];
        let mut tun_stage_count: usize = 0;

        for &(result, flags, user_data) in cqe_batch.iter().take(cqe_count) {
            let tag = user_data & 0xFFFF_FFFF;
            let bid_from_ud = ((user_data >> 32) & 0xFFFF) as u16;

            match tag {
                TAG_UDP_RECV_MULTISHOT => {
                    if result <= 0 {
                        reactor.multishot_active = false;
                        multishot_needs_rearm = true;
                        continue;
                    }
                    let bid = if flags & IORING_CQE_F_BUFFER != 0 {
                        ((flags >> 16) & 0xFFFF) as u16
                    } else { continue; };

                    recv_bids[recv_count] = bid;
                    recv_lens[recv_count] = result as usize;
                    recv_flags[recv_count] = flags;
                    recv_count += 1;
                    rx_count += 1;

                    if flags & IORING_CQE_F_MORE == 0 {
                        reactor.multishot_active = false;
                        multishot_needs_rearm = true;
                    }
                }

                // Non-recv CQEs: cheap, handle inline. TAG_TUN_READ is staged for Batch Crypto + FEC.
                TAG_TUN_READ => {
                    if result <= 0 {
                        reactor.arm_tun_read(tun_fd, bid_from_ud);
                        continue;
                    }
                    let payload_len = result as usize;
                    tun_read_count += 1;
                    
                    if tun_stage_count < TUN_STAGE_MAX {
                        tun_stage_bids[tun_stage_count] = bid_from_ud;
                        tun_stage_lens[tun_stage_count] = 62 + payload_len;
                        tun_stage_count += 1;
                    } else {
                        // Unlikely to exceed MAX_CQE, but drop if it overflows staging.
                        reactor.arm_tun_read(tun_fd, bid_from_ud); 
                    }
                }

                TAG_TUN_WRITE => {
                    reactor.add_buffer_to_pbr(bid_from_ud);
                    reactor.commit_pbr();
                }

                TAG_UDP_SEND_ECHO | TAG_UDP_SEND_TUN => {
                    if tag == TAG_UDP_SEND_TUN && tun_fd >= 0 {
                        reactor.arm_tun_read(tun_fd, bid_from_ud);
                    }
                    reactor.submit();
                }

                TAG_UDP_SEND_PARITY => {
                    reactor.release_bid(bid_from_ud);
                }

                _ => {}
            }
        }

        // ── Pass 0.5: Vectorized AEAD Encrypt & FEC over staged TUN reads ──
        if tun_stage_count > 0 {
            if let NodeState::Established { ref cipher, .. } = state {
                let seq_base = seq_tx;
                let k = tun_stage_count;
                
                let mut enc_ptrs: [*mut u8; MAX_CQE] = [std::ptr::null_mut(); MAX_CQE];
                let mut enc_lens: [usize; MAX_CQE] = [0; MAX_CQE];
                
                let mut tx_window = EncoderWindow::new();

                // 1. Build headers and staging arrays for Data Frames
                let mut wi = 0;
                while wi + 3 < k {
                    if wi + 7 < k {
                        unsafe {
                            crate::cryptography::aead::prefetch_read_l1(reactor.arena_base_ptr().add((tun_stage_bids[wi + 4] as usize) * FRAME_SIZE + 62));
                            crate::cryptography::aead::prefetch_read_l1(reactor.arena_base_ptr().add((tun_stage_bids[wi + 5] as usize) * FRAME_SIZE + 62));
                            crate::cryptography::aead::prefetch_read_l1(reactor.arena_base_ptr().add((tun_stage_bids[wi + 6] as usize) * FRAME_SIZE + 62));
                            crate::cryptography::aead::prefetch_read_l1(reactor.arena_base_ptr().add((tun_stage_bids[wi + 7] as usize) * FRAME_SIZE + 62));
                        }
                    }
                    for j in 0..4 {
                        let i = wi + j;
                        let bid = tun_stage_bids[i];
                        let flen = tun_stage_lens[i];
                        let frame_base = unsafe {
                            reactor.arena_base_ptr().add((bid as usize) * FRAME_SIZE)
                        };
                        let frame = unsafe {
                            std::slice::from_raw_parts_mut(frame_base, flen)
                        };
                        
                        frame[0..46].copy_from_slice(&hdr_template[0..46]);
                        frame[46..54].copy_from_slice(&(seq_tx + i as u64).to_le_bytes());
                        frame[54] = FLAG_TUNNEL;
                        let payload_len = flen - 62;
                        frame[55..59].copy_from_slice(&(payload_len as u32).to_le_bytes());
                        // V3: CIF telemetry stamp — loss_q8 at [59], burst_q8 at [60]
                        if let NodeState::Established { loss_q8, burst_q8, .. } = &state {
                            frame[59] = *loss_q8;
                            frame[60] = *burst_q8;
                            frame[61] = 0;
                        } else {
                            frame[59..62].copy_from_slice(&hdr_template[59..62]);
                        }

                        enc_ptrs[i] = frame_base;
                        enc_lens[i] = flen;
                    }
                    wi += 4;
                }
                while wi < k {
                    let i = wi;
                    let bid = tun_stage_bids[i];
                    let flen = tun_stage_lens[i];
                    let frame_base = unsafe {
                        reactor.arena_base_ptr().add((bid as usize) * FRAME_SIZE)
                    };
                    let frame = unsafe {
                        std::slice::from_raw_parts_mut(frame_base, flen)
                    };
                    
                    frame[0..46].copy_from_slice(&hdr_template[0..46]);
                    frame[46..54].copy_from_slice(&(seq_tx + i as u64).to_le_bytes());
                    frame[54] = FLAG_TUNNEL;
                    let payload_len = flen - 62;
                    frame[55..59].copy_from_slice(&(payload_len as u32).to_le_bytes());
                    // V3: CIF telemetry stamp — loss_q8 at [59], burst_q8 at [60]
                    if let NodeState::Established { loss_q8, burst_q8, .. } = &state {
                        frame[59] = *loss_q8;
                        frame[60] = *burst_q8;
                        frame[61] = 0;
                    } else {
                        frame[59..62].copy_from_slice(&hdr_template[59..62]);
                    }

                    enc_ptrs[i] = frame_base;
                    enc_lens[i] = flen;
                    wi += 1;
                }

                // 2. Bounded Rateless RLNC Parity Generation
                let mut parity_bids: [u16; 8] = [0; 8];
                let mut parity_count = 0;
                
                // V6: DYNAMIC REDUNDANCY BOUNDS (Inverted Physics)
                let target_pacing = if let NodeState::Established { loss_q8, burst_q8, .. } = &state {
                    if (*loss_q8 == 0 && *burst_q8 == 0) || *loss_q8 > 12 {
                        1 // 100% Redundancy baseline (Perfect Link OR High-Loss Regime)
                    } else {
                        // Scale down parity as loss goes up (assuming bufferbloat caused it)
                        std::cmp::max(1, *loss_q8 as usize / 4)
                    }
                } else {
                    1 // Max redundancy before telemetry establishes
                };

                if k > 0 && target_pacing > 0 {
                    tx_window.reset();
                    for wi in 0..k {
                        let frame_base = enc_ptrs[wi];
                        let payload_len = (enc_lens[wi] - 62).min(USO_MTU);
                        // SAFETY: frame_base from reactor arena, offset 62 within FRAME_SIZE.
                        unsafe { tx_window.push(frame_base.add(62), payload_len); }
                        
                        fec_pacing_counter += 1;
                        if fec_pacing_counter >= target_pacing && parity_count < 8 {
                            fec_pacing_counter = 0;
                            
                            // V5: Verbose Terminal Tracker
                            if std::env::var("M13_DRL_DEBUG").is_ok() {
                                eprintln!("[M13-N-DRL] Event: Parity Generated | Threshold Pacing: 1 per {}", target_pacing);
                            }

                            if let Some(p_bid) = reactor.get_free_bid() {
                                let seed = (parity_count + 1) as u8;
                                let slot = k + parity_count;
                                let fec_payload_len = USO_MTU.min(1600 - 62 - AFEC_SUB_HDR_SIZE);
                                let parity_base = unsafe {
                                    reactor.arena_base_ptr().add((p_bid as usize) * FRAME_SIZE)
                                };
                                let frame = unsafe {
                                    std::slice::from_raw_parts_mut(parity_base, 62 + AFEC_SUB_HDR_SIZE + fec_payload_len)
                                };
    
                                frame[0..46].copy_from_slice(&hdr_template[0..46]);
                                frame[46..54].copy_from_slice(&(seq_tx + slot as u64).to_le_bytes());
                                frame[54] = FLAG_FEC | FLAG_TUNNEL;
                                let parity_payload_len = (AFEC_SUB_HDR_SIZE + fec_payload_len) as u32;
                                frame[55..59].copy_from_slice(&parity_payload_len.to_le_bytes());
                                frame[59..62].copy_from_slice(&hdr_template[59..62]);
    
                                let sub_hdr = AfecSubHeader {
                                    base_seq_low: seq_base as u32,
                                    k: tx_window.count,
                                    parity_idx: parity_count as u8,
                                    seed,
                                    density: 0xFF,
                                };
                                unsafe {
                                    std::ptr::write_unaligned(
                                        parity_base.add(62) as *mut AfecSubHeader,
                                        sub_hdr,
                                    );
                                }
    
                                let parity_data = unsafe {
                                    std::slice::from_raw_parts_mut(
                                        parity_base.add(62 + AFEC_SUB_HDR_SIZE),
                                        fec_payload_len,
                                    )
                                };
                                for b in parity_data.iter_mut() { *b = 0; }
                                encode_parity_payload(parity_data, &tx_window, tx_window.count as usize, seed);
    
                                enc_ptrs[slot] = parity_base;
                                enc_lens[slot] = 62 + AFEC_SUB_HDR_SIZE + fec_payload_len;
                                parity_bids[parity_count] = p_bid;
                                parity_count += 1;
                            }
                        }
                    }
                }

                let total_encrypt = k + parity_count;

                // 3. One single Vectorized AEAD call for Data + Parity!
                crate::cryptography::aead::encrypt_batch_ptrs(
                    &enc_ptrs, &enc_lens, total_encrypt, cipher, DIR_NODE_TO_HUB, seq_base
                );

                // 4. Submit array to io_uring for UDP transmission
                for i in 0..k {
                    reactor.stage_udp_send(
                        enc_ptrs[i], enc_lens[i] as u32, 
                        tun_stage_bids[i], TAG_UDP_SEND_TUN,
                    );
                }
                for i in 0..parity_count {
                    reactor.stage_udp_send(
                        enc_ptrs[k+i], enc_lens[k+i] as u32, 
                        parity_bids[i], TAG_UDP_SEND_PARITY,
                    );
                }
                reactor.submit();

                seq_tx += total_encrypt as u64;
                tx_count += total_encrypt as u64;

            } else {
                // Not Established, just drop TUN traffic and rearm
                for &bid in tun_stage_bids.iter().take(tun_stage_count) {
                    reactor.arm_tun_read(tun_fd, bid);
                }
            }
        }


        // ── Pass 1: Vectorized AEAD Batch Decrypt ──────────────
        // 4-at-a-time AES-NI/ARMv8-CE prefetch saturates crypto pipeline.
        // decrypt_one stamps PRE_DECRYPTED_MARKER (0x02) on success —
        // process_rx_frame recognizes it and skips both decrypt and
        // cleartext-reject. Failures keep 0x01 → scalar fallback.
        if recv_count > 0 {
            if let NodeState::Established { ref cipher, ref mut frame_count, ref established_ns, .. } = state {
                let mut enc_ptrs: [*mut u8; MAX_CQE] = [std::ptr::null_mut(); MAX_CQE];
                let mut enc_lens: [usize; MAX_CQE] = [0; MAX_CQE];
                let mut enc_count: usize = 0;

                for ri in 0..recv_count {
                    let bid = recv_bids[ri];
                    let len = recv_lens[ri];
                    let ptr = unsafe {
                        reactor.arena_base_ptr().add((bid as usize) * FRAME_SIZE)
                    };
                    // Encrypted frame: len >= ETH_HDR + 40, crypto flag == 0x01
                    if len >= ETH_HDR_SIZE + 40 {
                        let crypto_flag = unsafe { *ptr.add(ETH_HDR_SIZE + 2) };
                        if crypto_flag == 0x01 {
                            enc_ptrs[enc_count] = ptr;
                            enc_lens[enc_count] = len;
                            enc_count += 1;
                        }
                    }
                }

                if enc_count > 0 {
                    let mut decrypt_results = [false; MAX_CQE];
                    let ok = crate::cryptography::aead::decrypt_batch_ptrs(
                        &enc_ptrs, &enc_lens, enc_count, cipher, DIR_NODE_TO_HUB,
                        &mut decrypt_results[..enc_count],
                    );
                    *frame_count += ok as u64;
                    aead_ok_count += ok as u64;

                    // Rekey check after batch
                    if *frame_count >= REKEY_FRAME_LIMIT
                       || now.saturating_sub(*established_ns) > REKEY_TIME_LIMIT_NS {
                        eprintln!("[M13-NODE-PQC] Rekey threshold reached (batch). Re-initiating handshake.");
                        state = NodeState::Registering;
                    }
                }
            }
        }

        // ── Pass 2: Per-Frame RxAction Dispatch ────────────────
        // Frames with PRE_DECRYPTED_MARKER skip decrypt entirely.
        let mut fec_data_count: usize = 0;
        let mut fec_parity_count: usize = 0;
        let mut fec_data_seq: [u32; MAX_CQE] = [0; MAX_CQE];
        let mut fec_data_bid: [u16; MAX_CQE] = [0; MAX_CQE];
        let mut fec_data_start: [u16; MAX_CQE] = [0; MAX_CQE];
        let mut fec_data_len: [u16; MAX_CQE] = [0; MAX_CQE];
        let mut fec_parity_k = [0u8; MAX_CQE];
    let mut fec_parity_seed = [0u8; MAX_CQE];
    let mut fec_parity_base_seq = [0u32; MAX_CQE];
        let mut fec_parity_bid: [u16; MAX_CQE] = [0; MAX_CQE];
        let mut fec_parity_start: [u16; MAX_CQE] = [0; MAX_CQE];
        let mut fec_parity_len: [u16; MAX_CQE] = [0; MAX_CQE];
        for ri in 0..recv_count {
            let bid = recv_bids[ri];
            let pkt_len = recv_lens[ri];

            let mut frame = reactor.get_frame(bid, pkt_len);
            let buf = frame.as_mut();

            hexdump.dump_rx(buf, now);

            if matches!(state, NodeState::Disconnected) {
                state = NodeState::Registering;
            }

            let action = process_rx_frame(buf, &mut state, &mut assembler,
                &mut hexdump, now, echo, &mut aead_fail_count);

            let mut bid_deferred = false;
            match action {
                RxAction::NeedHandshakeInit => {
                    state = initiate_handshake(
                        &sock, &src_mac, &hub_mac, &mut seq_tx, &mut hexdump, &cal,
                    );
                }
                RxAction::TunWrite { start, plen } => {
                    if tun_fd >= 0 {
                        let write_ptr = unsafe {
                            reactor.arena_base_ptr().add((bid as usize) * FRAME_SIZE + start)
                        };
                        reactor.stage_tun_write(tun_fd, write_ptr, plen as u32, bid);
                        reactor.submit();
                        tun_write_count += 1;
                        bid_deferred = true;
                    }
                    // Track for FEC decoder
                    if fec_data_count < MAX_CQE {
                        let seq_bytes: [u8; 8] = buf[ETH_HDR_SIZE + 32..ETH_HDR_SIZE + 40]
                            .try_into().unwrap_or([0; 8]);
                        fec_data_seq[fec_data_count] = u64::from_le_bytes(seq_bytes) as u32;
                        fec_data_bid[fec_data_count] = bid;
                        fec_data_start[fec_data_count] = start as u16;
                        fec_data_len[fec_data_count] = plen as u16;
                        fec_data_count += 1;
                    }
                }
                RxAction::Echo => {
                    if let Some(mut echo_frame) = build_echo_frame(buf, seq_tx) {
                        if let NodeState::Established { ref cipher, ref session_key, .. } = state {
                            if *session_key != [0u8; 32] {
                                seal_frame(&mut echo_frame, cipher, seq_tx, DIR_NODE_TO_HUB);
                            }
                        }
                        seq_tx += 1;
                        hexdump.dump_tx(&echo_frame, now);
                        if sock.send(&echo_frame).is_ok() { tx_count += 1; }
                    }
                }
                RxAction::HandshakeComplete { session_key, finished_payload } => {
                    let hs_flags = FLAG_CONTROL | FLAG_HANDSHAKE;
                    // DEFECT β FIXED: Closure captures sock, hexdump, tx_count.
                    let mut sent_frags = 0u64;
                    send_fragmented_udp(
                        &src_mac, &hub_mac,
                        &finished_payload, hs_flags,
                        &mut seq_tx,
                        |frame| {
                            hexdump.dump_tx(frame, now);
                            let _ = sock.send(frame);
                            tx_count += 1;
                            sent_frags += 1;
                        }
                    );
                    if cfg!(debug_assertions) {
                        eprintln!("[M13-NODE-PQC] Finished sent: {}B, {} fragments",
                            finished_payload.len(), sent_frags);
                    }
                    state = NodeState::Established {
                        session_key,
                        cipher: Box::new(aead::LessSafeKey::new(
                            aead::UnboundKey::new(&aead::AES_256_GCM, &session_key).unwrap()
                        )),
                        frame_count: 0,
                        established_ns: now,
                        fec_decoder: SwRlncDecoder::new_boxed(),
                        highest_rx_seq: 0,
                        loss_q8: 0,
                        burst_q8: 0,
                    };
                    if cfg!(debug_assertions) { eprintln!("[M13-NODE-PQC] → Established"); }
                    if tun.is_some() && !routes_installed {
                        setup_tunnel_routes(&hub_ip);
                        routes_installed = true;
                    }
                }
                RxAction::HandshakeFailed => {
                    eprintln!("[M13-NODE-PQC] Handshake failed → Disconnected");
                    state = NodeState::Disconnected;
                }
                RxAction::RekeyNeeded => {
                    state = NodeState::Registering;
                }
                RxAction::Parity { base_seq, k, seed, data_start, data_len } => {
                    if fec_parity_count < MAX_CQE {
                        fec_parity_base_seq[fec_parity_count] = base_seq;
                        fec_parity_k[fec_parity_count] = k;
                        fec_parity_seed[fec_parity_count] = seed;
                        fec_parity_bid[fec_parity_count] = bid;
                        fec_parity_start[fec_parity_count] = data_start as u16;
                        fec_parity_len[fec_parity_count] = data_len as u16;
                        fec_parity_count += 1;
                    }
                }
                RxAction::Drop => {}
            }

            if !bid_deferred {
                reactor.add_buffer_to_pbr(bid);
                reactor.commit_pbr();
            }
        }

        // FEC recovery pass — io_uring worker
        if fec_parity_count > 0 && fec_data_count > 0 {
            if let NodeState::Established { ref mut fec_decoder, .. } = state {
                let ref_base = fec_parity_base_seq[0];
                if fec_decoder.base_seq != ref_base
                    && ref_base.wrapping_sub(fec_decoder.base_seq) as i32 > 0 {
                        fec_decoder.row_present = 0;
                        fec_decoder.deliver_next = 0;
                        fec_decoder.base_seq = ref_base;
                }

                for di in 0..fec_data_count {
                    let seq = fec_data_seq[di];
                    let rel = seq.wrapping_sub(fec_decoder.base_seq) as usize;
                    if rel < MAX_K {
                        let ptr = unsafe {
                            reactor.arena_base_ptr().add(
                                (fec_data_bid[di] as usize) * FRAME_SIZE + fec_data_start[di] as usize
                            )
                        };
                        let l = fec_data_len[di] as usize;
                        let data = unsafe { std::slice::from_raw_parts(ptr, l) };
                        fec_decoder.ingest_systematic(rel, data);
                    }
                }
                let pre_mask = fec_decoder.row_present;

                for pi in 0..fec_parity_count {
                    let ptr = unsafe {
                        reactor.arena_base_ptr().add(
                            (fec_parity_bid[pi] as usize) * FRAME_SIZE + fec_parity_start[pi] as usize
                        )
                    };
                    let l = fec_parity_len[pi] as usize;
                    let data = unsafe { std::slice::from_raw_parts(ptr, l) };
                    fec_decoder.ingest_parity(
                        fec_parity_seed[pi], fec_parity_k[pi] as usize, data
                    );
                }
                
                let recovered_mask = fec_decoder.row_present & !pre_mask;

                // Deliver explicitly recovered packets back to TUN directly into pre-allocated write buffer area
                if tun_fd >= 0 {
                    for rel in 0..MAX_K {
                        if (recovered_mask & (1u8 << rel)) != 0 {
                            let recovered = fec_decoder.get_payload(rel);
                            let ip_ver = recovered[0] >> 4;
                            let ip_len = match ip_ver {
                                4 => u16::from_be_bytes([recovered[2], recovered[3]]) as usize,
                                6 => 40 + u16::from_be_bytes([recovered[4], recovered[5]]) as usize,
                                _ => 0,
                            };
                            if ip_len > 0 && ip_len <= recovered.len() {
                                if let Some(bid) = reactor.get_free_bid() {
                                    let write_ptr = unsafe {
                                        let base = reactor.arena_base_ptr().add((bid as usize) * FRAME_SIZE);
                                        std::ptr::copy_nonoverlapping(recovered.as_ptr(), base, ip_len);
                                        base
                                    };
                                    reactor.stage_tun_write(tun_fd, write_ptr, ip_len as u32, bid);
                                    tun_write_count += 1;
                                }
                            }
                        }
                    }
                    reactor.submit();
                }
            }
        }

        // Re-arm multishot recv if terminated during this batch
        if multishot_needs_rearm {
            reactor.arm_multishot_recv();
        }

        // ── Handshake timeout ──────────────────────────────────
        if let NodeState::Handshaking { ref mut started_ns, ref client_hello_bytes, .. } = state {
            // SURGICAL PATCH: Replace 5-second constant with 250ms Micro-ARQ boundary.
            // Eradicates the 5-second dead-trap and ensures rapid retransmission.
            if now.saturating_sub(*started_ns) > HANDSHAKE_RETX_INTERVAL_NS {
                eprintln!("[M13-NODE-PQC] Handshake timeout (2000ms). Retransmitting...");

                let hs_flags = FLAG_CONTROL | FLAG_HANDSHAKE;
                let mut seq_cap = seq_tx;

                // Closure IoC execution prevents borrow checker collision
                send_fragmented_udp(
                    &src_mac, &hub_mac,
                    client_hello_bytes, hs_flags,
                    &mut seq_cap,
                    |frame| {
                        hexdump.dump_tx(frame, now);
                        let _ = sock.send(frame);
                        tx_count += 1;
                    }
                );

                seq_tx = seq_cap;
                *started_ns = now; // Reset timer without recomputing 10ms of NTT math
            }
        }

        // ── Keepalive (pre-Established only) ──────────────────
        if !matches!(state, NodeState::Established { .. })
            && (now.saturating_sub(last_keepalive_ns) > 100_000_000 || tx_count == 0) {
            last_keepalive_ns = now;
            let ka = build_m13_frame(&src_mac, &hub_mac, seq_tx, FLAG_CONTROL);
            seq_tx += 1;
            if sock.send(&ka).is_ok() { tx_count += 1; }
        }

        // ── Telemetry (1/sec) ─────────────────────────────────
        if now.saturating_sub(last_report_ns) > 1_000_000_000 {
            let state_label = match &state {
                NodeState::Registering => "Reg",
                NodeState::Handshaking { .. } => "HS",
                NodeState::Established { .. } => "Est",
                NodeState::Disconnected => "Disc",
            };
            eprintln!("[M13-N0] RX:{} TX:{} TUN_R:{} TUN_W:{} AEAD_OK:{} FAIL:{} State:{} Up:{}s",
                rx_count, tx_count, tun_read_count, tun_write_count, aead_ok_count, aead_fail_count, state_label,
                match &state { NodeState::Established { established_ns, .. } => (now - established_ns) / 1_000_000_000, _ => (now - start_ns) / 1_000_000_000 });
            last_report_ns = now;
            gc_counter += 1;
            if gc_counter.is_multiple_of(5) { assembler.gc(now); }
        }

        // Submit any pending SQEs
        reactor.submit();
        let _ = reactor.ring.submit_and_wait(0);
    }

    if routes_installed {
        teardown_tunnel_routes(&hub_ip);
    }
    let final_up_s = match &state { NodeState::Established { established_ns, .. } => (rdtsc_ns(&cal) - established_ns) / 1_000_000_000, _ => (rdtsc_ns(&cal) - start_ns) / 1_000_000_000 };
    eprintln!("[M13-N0] Shutdown. RX:{} TX:{} TUN_R:{} TUN_W:{} AEAD_OK:{} FAIL:{} Up:{}s",
        rx_count, tx_count, tun_read_count, tun_write_count, aead_ok_count, aead_fail_count, final_up_s);
}
