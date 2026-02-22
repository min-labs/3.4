// M13 HUB — Orchestrator
use std::mem;
use std::sync::atomic::Ordering;

// ── Library Imports ─────────────────────────────────────────────────────
use m13_hub::engine::protocol::{
    EthernetHeader, M13Header, ETH_P_M13, M13_WIRE_MAGIC, M13_WIRE_VERSION, M13_HDR_SIZE, ETH_HDR_SIZE,
    FLAG_FRAGMENT, FLAG_HANDSHAKE, FLAG_CONTROL,
    PeerTable, PeerLifecycle, MAX_PEERS,
    produce_feedback_frame, RxBitmap, ReceiverState, FEEDBACK_INTERVAL_PKTS, FEEDBACK_RTT_DEFAULT_NS, FEEDBACK_FRAME_LEN,
    Scheduler, TxCounter, TX_RING_SIZE, HW_FILL_MAX,
    JitterBuffer, measure_epsilon_proc, JBUF_CAPACITY,
    FragHeader, FRAG_HDR_SIZE,
    build_fragmented_raw_udp, build_fragmented_l2};
use m13_hub::engine::runtime::{
    HexdumpState, run_monitor, Telemetry,
    TscCal, calibrate_tsc, rdtsc_ns, read_tsc,
    discover_isolated_cores, pin_to_core, verify_affinity, lock_pmu, fence_interrupts,
    fatal, E_NO_ISOLATED_CORES, E_AFFINITY_FAIL, FixedSlab};
use m13_hub::network::xdp::{Engine, ZeroCopyTx, MAX_WORKERS, FRAME_SIZE, UMEM_SIZE};
use m13_hub::network::bpf::BpfSteersman;
use m13_hub::network::datapath::{create_tun, setup_nat, teardown_all_hub,
    detect_mac, resolve_gateway_mac, build_raw_udp_frame, RAW_HDR_LEN,
    get_interface_ip, send_fin_burst_udp, send_fin_burst_l2};
use m13_hub::network::{
    PacketVector, PacketDesc, Disposition, NextNode, VECTOR_SIZE,
    GraphCtx, CycleStats, scatter,
    datapath,
};
// process_client_hello_hub and process_finished_hub are now called by Core 0 PQC worker
// (hub/src/cryptography/async_pqc.rs), not by the datapath.
// ring::aead used via fully qualified paths in drain handler (ring::aead::UnboundKey, etc.)

const SLAB_DEPTH: usize = 8192;
const GRAPH_BATCH: usize = 256;
const DEADLINE_NS: u64 = 50_000;
const PREFETCH_DIST: usize = 4;
const SEQ_WINDOW: usize = 131_072; // 2^17
const _: () = assert!(SEQ_WINDOW & (SEQ_WINDOW - 1) == 0);


extern "C" fn signal_handler(_sig: i32) { m13_hub::engine::runtime::SHUTDOWN.store(true, Ordering::Relaxed); }

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // SAFETY: signal_handler is a valid extern "C" fn with stable address. It only performs
    // a single atomic store (Relaxed), which is async-signal-safe per POSIX.
    unsafe {
        libc::signal(libc::SIGTERM, signal_handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, signal_handler as *const () as libc::sighandler_t);
    }

    // Panic hook: guarantee cleanup even on unwinding crash
    let panic_if_name = args.get(1).cloned().unwrap_or_else(|| "veth0".to_string());
    std::panic::set_hook(Box::new(move |info| {
        eprintln!("[M13-HUB] PANIC: {}", info);
        teardown_all_hub(&panic_if_name);
        std::process::exit(1);
    }));

    if args.iter().any(|a| a == "--monitor") {
        run_monitor(MAX_WORKERS);
        return;
    }
    let mut if_name = "veth0".to_string();
    let mut single_queue: Option<i32> = None;
    let mut hexdump_mode = false;
    let mut tunnel_mode = false;
    let mut listen_port: Option<u16> = Some(443); // Default: UDP/443 (blends with QUIC)
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--monitor" => { run_monitor(MAX_WORKERS); return; }
            "--hexdump" => { hexdump_mode = true; }
            "--tunnel" => { tunnel_mode = true; }
            "--port" | "--listen" => {
                i += 1;
                if i < args.len() {
                    listen_port = Some(match args[i].parse() {
                        Ok(p) => p,
                        Err(_) => fatal(E_AFFINITY_FAIL, "Invalid port number"),
                    });
                }
            }
            "--single-queue" => {
                i += 1;
                if i < args.len() {
                    single_queue = Some(match args[i].parse() {
                        Ok(v) => v,
                        Err(_) => fatal(E_AFFINITY_FAIL, "Invalid queue ID argument"),
                    });
                }
            }
            "-i" | "--iface" => {
                i += 1;
                if i < args.len() { if_name = args[i].clone(); }
            }
            other => {
                if !other.starts_with("--") { if_name = other.to_string(); }
            }
        }
        i += 1;
    }
    if hexdump_mode {
        std::env::set_var("M13_HEXDUMP", "1");
    }
    // Hub always listens. CLI --port takes precedence, then env var, then default 443.
    // If M13_LISTEN_PORT is already set in the environment, don't clobber it with the default.
    match listen_port {
        Some(p) => {
            let cli_port_given = args.iter().any(|a| a == "--port" || a == "--listen");
            if cli_port_given || std::env::var("M13_LISTEN_PORT").is_err() {
                std::env::set_var("M13_LISTEN_PORT", p.to_string());
            }
        }
        None => {
            if std::env::var("M13_LISTEN_PORT").is_err() {
                std::env::set_var("M13_LISTEN_PORT", "443");
            }
        }
    }
    run_executive(&if_name, single_queue, tunnel_mode);
}
// ── THE EXECUTIVE ────────────────────────────────────────────────────────

fn run_executive(if_name: &str, single_queue: Option<i32>, tunnel: bool) {
    // Register signal handlers before spawning workers.
    // signal() is async-signal-safe. Handler sets AtomicBool — one CPU instruction.
    // SAFETY: signal_handler is a valid extern "C" fn with stable address. It only performs
    // a single atomic store (Relaxed), which is async-signal-safe per POSIX.
    unsafe {
        libc::signal(libc::SIGTERM, signal_handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, signal_handler as *const () as libc::sighandler_t);
    }

    // === AUTO-CLEANUP: kill stale hub, detach XDP, allocate hugepages ===
    eprintln!("[M13-EXEC] Pre-flight cleanup...");
    // Kill any previous m13-hub (SIGKILL, exclude ourselves)
    let my_pid = std::process::id();
    if let Ok(output) = std::process::Command::new("pgrep").arg("m13-hub").output() {
        if output.status.success() {
            let pids = String::from_utf8_lossy(&output.stdout);
            for pid_str in pids.lines() {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    if pid != my_pid {
                        // SAFETY: PID is from pgrep output; kill(pid, SIGKILL) is safe for any valid PID.
                        unsafe { libc::kill(pid as i32, 9); }
                    }
                }
            }
        }
    }
    // Detach any stale XDP programs from the interface
    let _ = std::process::Command::new("ip").args(["link", "set", if_name, "xdp", "off"]).output();
    let _ = std::process::Command::new("ip").args(["link", "set", if_name, "xdpgeneric", "off"]).output();

    // CRITICAL: Collapse NIC to single queue so ALL traffic hits queue 0 (where AF_XDP binds).
    // Without this, RSS distributes UDP/443 across multiple queues → AF_XDP never sees packets
    // on queues != 0 → silent RX drop. This is the #1 failure mode for pure AF_XDP.
    let sq_result = std::process::Command::new("ethtool")
        .args(["-L", if_name, "combined", "1"])
        .output();
    match sq_result {
        Ok(ref o) if o.status.success() => {
            eprintln!("[M13-EXEC] NIC {} collapsed to single queue (ethtool -L combined 1).", if_name);
        }
        Ok(ref o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            eprintln!("[M13-EXEC] WARNING: ethtool -L combined 1 failed: {}. UDP/443 may miss AF_XDP queue.", stderr.trim());
        }
        Err(e) => {
            eprintln!("[M13-EXEC] WARNING: ethtool not found: {}. Ensure NIC has 1 queue manually.", e);
        }
    }

    // Allocate hugepages: workers × UMEM_SIZE / 2MB per hugepage + headroom
    let hp_worker_count = match single_queue { Some(_) => 1, None => MAX_WORKERS };
    let hugepages_needed = (hp_worker_count * (UMEM_SIZE + 16 * 1024 * 1024)) / (2 * 1024 * 1024);
    let _ = std::fs::write("/proc/sys/vm/nr_hugepages", format!("{}\n", hugepages_needed));
    if let Ok(hp) = std::fs::read_to_string("/proc/sys/vm/nr_hugepages") {
        eprintln!("[M13-EXEC] Hugepages: {} allocated", hp.trim());
    }
    eprintln!("[M13-EXEC] Pre-flight cleanup complete.");

    // TSC calibration — must happen before workers spawn.
    // Workers receive a copy of the calibration data (immutable, per-worker).
    let tsc_cal = calibrate_tsc();

    lock_pmu();
    fence_interrupts();
    let isolated_cores = discover_isolated_cores();
    if isolated_cores.is_empty() {
        fatal(E_NO_ISOLATED_CORES, "No isolated cores. Boot with isolcpus=... or set M13_MOCK_CMDLINE");
    }
    // MANDATE: M13_SIMULATION and Mock Engines are completely dead. 
    // All Hub workers MUST be backed by physical AF_XDP hardware queues.
    let worker_count = match single_queue { 
        Some(_) => 1, 
        None => isolated_cores.len().min(MAX_WORKERS) 
    };

    eprintln!("[M13-EXEC] Discovered {} isolated core(s): {:?}. Spawning {} XDP worker(s).",
        isolated_cores.len(), &isolated_cores[..worker_count], worker_count);
    // BPF Steersman: Enforcement is binary. Software emulation is prohibited.
    let steersman = BpfSteersman::load_and_attach(if_name);
    let map_fd = steersman.map_fd();
    eprintln!("[M13-EXEC] BPF Steersman attached to {} [{}]. map_fd={}", if_name, steersman.attach_mode, map_fd);
    
    // TUN interface
    let tun_ref = if tunnel {
        let t = create_tun("m13tun0");
        if t.is_some() { setup_nat(); }
        t
    } else { None };

    // R-02: Create SPSC rings for TUN decoupling + spawn housekeeping thread
    use m13_hub::engine::spsc;
    use m13_hub::network::PacketDesc;
    const SPSC_RING_DEPTH: usize = 2048; // power-of-two, upgraded from 256 for proper backpressure

    // 4 rings: tx_tun (dp→tun), rx_tun (tun→dp), free_to_tun (dp→tun slab IDs), free_to_dp (tun→dp slab IDs)
    let (spsc_tx_tun_prod, spsc_tx_tun_cons) = spsc::make_spsc::<PacketDesc>(SPSC_RING_DEPTH);
    let (spsc_rx_tun_prod, spsc_rx_tun_cons) = spsc::make_spsc::<PacketDesc>(SPSC_RING_DEPTH);
    let (spsc_free_to_tun_prod, spsc_free_to_tun_cons) = spsc::make_spsc::<u32>(SPSC_RING_DEPTH);
    let (spsc_free_to_dp_prod, spsc_free_to_dp_cons) = spsc::make_spsc::<u32>(SPSC_RING_DEPTH);

    // R-02: Share UMEM base with TUN HK thread via OnceLock.
    // Worker 0 publishes (umem_base_ptr_as_usize, frame_size) after Engine::new().
    // TUN HK thread blocks on .get() until the value is available.
    let umem_info: std::sync::Arc<std::sync::OnceLock<(usize, u32)>> =
        std::sync::Arc::new(std::sync::OnceLock::new());

    // Only spawn the TUN housekeeping thread if tunnel mode is active
    let tun_thread = if let Some(ref tun) = tun_ref {
        let tun_hk_core = *isolated_cores.last().unwrap();
        let tun_file = tun.try_clone().ok();
        let umem_info_hk = umem_info.clone();
        Some(std::thread::Builder::new()
            .name("m13-tun-hk".into()).stack_size(4 * 1024 * 1024)
            .spawn(move || {
                pin_to_core(tun_hk_core);
                tun_housekeeping_thread(
                    tun_file.expect("TUN file clone failed"),
                    spsc_tx_tun_cons,
                    spsc_rx_tun_prod,
                    spsc_free_to_tun_cons,
                    spsc_free_to_dp_prod,
                    umem_info_hk,
                );
            })
            .unwrap_or_else(|_| fatal(E_AFFINITY_FAIL, "TUN HK thread spawn failed")))
    } else { None };

    eprintln!("[M13-EXEC] R-02 SPSC rings: depth={}, TUN HK thread: {}",
        SPSC_RING_DEPTH,
        if tun_thread.is_some() { format!("Core {}", isolated_cores.last().unwrap()) } else { "inactive".into() });

    // V1/V5: Statically allocate the global atomic pacing array and leak it for DO-178C lifetime
    let target_pacing_ptr: *const [m13_hub::engine::drl::DrlPacingState; 256] = unsafe {
        let layout = std::alloc::Layout::new::<[m13_hub::engine::drl::DrlPacingState; 256]>();
        std::alloc::alloc_zeroed(layout) as *mut _
    };

    let (spsc_drl_state_prod, spsc_drl_state_cons) = m13_hub::engine::spsc::make_spsc::<m13_hub::engine::drl::DrlStateTensor>(8192);

    let ai_pacing_usize = target_pacing_ptr as usize;
    let cal_clone = tsc_cal;
    let drl_thread = Some(std::thread::Builder::new().name("m13-drl-cp".into()).spawn(move || {
        let tp = ai_pacing_usize as *const [m13_hub::engine::drl::DrlPacingState; 256];
        // SAFETY: Pointer is dynamically allocated and purposely leaked to persist beyond thread death.
        unsafe { m13_hub::engine::drl::drl_worker_thread(0, cal_clone, spsc_drl_state_cons, tp); }
    }).expect("FATAL: Failed to spawn Core 0 DRL Worker Plane"));

    let mut opt_drl_state_prod = Some(spsc_drl_state_prod);

    let pacing_usize = target_pacing_ptr as usize;

    let mut handles = Vec::with_capacity(worker_count);
    // Wrap worker-side SPSC handles in Option so worker 0 gets them via .take()
    let mut opt_tx_tun_prod = Some(spsc_tx_tun_prod);
    let mut opt_rx_tun_cons = Some(spsc_rx_tun_cons);
    let mut opt_free_to_tun_prod = Some(spsc_free_to_tun_prod);
    let mut opt_free_to_dp_cons = Some(spsc_free_to_dp_cons);

    #[allow(clippy::needless_range_loop)] // worker_idx indexes both isolated_cores and governs SPSC handle distribution
    for worker_idx in 0..worker_count {
        let core_id = isolated_cores[worker_idx];
        let queue_id = match single_queue { Some(q) => q, None => worker_idx as i32 };
        let iface = if_name.to_string();
        let cal = tsc_cal; // Copy for this worker (TscCal is Copy)
        let tun = tun_ref.as_ref().and_then(|f| f.try_clone().ok());

        // Only worker 0 gets SPSC handles (TUN I/O is single-reader/writer)
        let w_tx_tun = if worker_idx == 0 { opt_tx_tun_prod.take() } else { None };
        let w_rx_tun = if worker_idx == 0 { opt_rx_tun_cons.take() } else { None };
        let w_free_tun = if worker_idx == 0 { opt_free_to_tun_prod.take() } else { None };
        let w_free_dp = if worker_idx == 0 { opt_free_to_dp_cons.take() } else { None };
        let w_drl_tx = if worker_idx == 0 { opt_drl_state_prod.take() } else { None };
        let w_pacing_usize = pacing_usize;
        let umem_info_w = umem_info.clone();

        let handle = std::thread::Builder::new()
            .name(format!("m13-w{}", worker_idx)).stack_size(32 * 1024 * 1024)
            .spawn(move || {
                // SAFETY: Pointer was heap-allocated + leaked with 'static lifetime.
                let tp = w_pacing_usize as *const [m13_hub::engine::drl::DrlPacingState; 256];
                worker_entry(
                    worker_idx, core_id, queue_id, &iface, map_fd, cal, tun,
                    w_tx_tun, w_rx_tun, w_free_tun, w_free_dp,
                    umem_info_w,
                    w_drl_tx, tp,
                );
            })
            .unwrap_or_else(|_| fatal(E_AFFINITY_FAIL, "Thread spawn failed"));
        handles.push(handle);
    }

    eprintln!("[M13-EXEC] Engine operational. Workers running.");

    for h in handles { let _ = h.join(); }
    // Wait for DRL worker thread
    if let Some(th) = drl_thread { let _ = th.join(); }
    // Wait for TUN housekeeping thread
    if let Some(th) = tun_thread { let _ = th.join(); }
    drop(steersman);

    // Post-worker cleanup: teardown everything
    teardown_all_hub(if_name);
    eprintln!("[M13-EXEC] All workers stopped. XDP detached. Clean exit.");
}

// ── Decomposed Worker Stages ────────────────────────────────────────────
// Each stage extracted from worker_entry as #[inline(always)] for readability
// without pipeline bubbles. Parameters are the minimal set each stage needs.

/// Stage 3: Generate feedback frame if receiver state indicates.
#[inline(always)]
#[allow(clippy::too_many_arguments)] // Feedback generation parameters — struct wrapper adds unnecessary indirection
fn stage_feedback_gen(
    umem: *mut u8,
    rx_state: &mut ReceiverState,
    rx_bitmap: &mut RxBitmap,
    slab: &mut FixedSlab,
    scheduler: &mut Scheduler,
    src_mac: &[u8; 6],
    jbuf: &JitterBuffer,
    rx_batch_ns: u64,
) {
    let rtt_est = FEEDBACK_RTT_DEFAULT_NS;
    if rx_state.needs_feedback(rx_batch_ns, rtt_est) {
        if let Some(idx) = slab.alloc() {
            // SAFETY: Pointer arithmetic within UMEM bounds; idx from slab is valid.
            let frame_ptr = unsafe { umem.add((idx as usize) * FRAME_SIZE as usize) };
            let bcast_mac = [0xFF; 6];
            // SAFETY: frame_ptr computed from slab.alloc() within valid UMEM bound.
            unsafe {
                produce_feedback_frame(
                    frame_ptr, &bcast_mac, src_mac,
                    rx_state, rx_bitmap, rx_batch_ns,
                    jbuf.tail - jbuf.head, JBUF_CAPACITY,
                );
            }
            scheduler.enqueue_critical((idx as u64) * FRAME_SIZE as u64, FEEDBACK_FRAME_LEN);
        }
    }
}
// ── VPP Graph Executor (consolidated from executor.rs) ─────────────────
// Pipeline: rx_parse → aead_decrypt → classify → {tun_write, tx_enqueue, handshake}

/// Execute the full VPP graph on a batch of RX descriptors.
fn execute_graph(
    rx_descs: &[(u64, u32)],
    ctx: &mut GraphCtx<'_>,
) -> CycleStats {
    let mut stats = CycleStats::default();
    let n = rx_descs.len();
    if n == 0 { return stats; }

    let mut offset = 0;
    while offset < n {
        let chunk_end = (offset + VECTOR_SIZE).min(n);
        let chunk = &rx_descs[offset..chunk_end];
        let sub_stats = execute_subvector(chunk, ctx);
        stats.parsed += sub_stats.parsed;
        stats.aead_ok += sub_stats.aead_ok;
        stats.aead_fail += sub_stats.aead_fail;
        stats.tun_writes += sub_stats.tun_writes;
        stats.handshakes += sub_stats.handshakes;
        stats.feedback += sub_stats.feedback;
        stats.drops += sub_stats.drops;
        stats.data_fwd += sub_stats.data_fwd;
        stats.parse_tsc += sub_stats.parse_tsc;
        stats.decrypt_tsc += sub_stats.decrypt_tsc;
        stats.classify_tsc += sub_stats.classify_tsc;
        stats.scatter_tsc += sub_stats.scatter_tsc;
        stats.tun_write_tsc += sub_stats.tun_write_tsc;
        stats.handshake_ok += sub_stats.handshake_ok;
        stats.handshake_fail += sub_stats.handshake_fail;
        stats.direction_fail += sub_stats.direction_fail;
        for i in 0..sub_stats.fin_count {
            if stats.fin_count < stats.fin_events.len() {
                stats.fin_events[stats.fin_count] = sub_stats.fin_events[i];
                stats.fin_count += 1;
            }
        }
        offset = chunk_end;
    }
    stats
}

/// Execute the graph on a single sub-vector (≤64 packets).
fn execute_subvector(
    descs: &[(u64, u32)],
    ctx: &mut GraphCtx<'_>,
) -> CycleStats {
    let mut stats = CycleStats::default();

    // NODE 1: RX PARSE — build PacketDesc, peer lookup, split encrypt/clear
    let mut decrypt_vec = PacketVector::new();
    let mut cleartext_vec = PacketVector::new();
    let t_parse = read_tsc();
    datapath::rx_parse_raw(descs, &mut decrypt_vec, &mut cleartext_vec, ctx, &mut stats);
    stats.parse_tsc = read_tsc() - t_parse;
    if cfg!(debug_assertions) { eprintln!("[DBG] rx_parse done: decrypt={} clear={}", decrypt_vec.len, cleartext_vec.len); }

    // NODE 1.5: RECONNECTION DETECTION on cleartext packets
    datapath::handle_reconnection(&cleartext_vec, ctx);
    if cfg!(debug_assertions) { eprintln!("[DBG] handle_reconnection done"); }

    // NODE 2: AEAD DECRYPT — vectorized AES-NI/ARMv8-CE pipeline
    let mut aead_results = Disposition::new();
    if decrypt_vec.len > 0 {
        let t_decrypt = read_tsc();
        datapath::aead_decrypt_vector(&mut decrypt_vec, &mut aead_results, ctx, &mut stats);
        stats.decrypt_tsc = read_tsc() - t_decrypt;
    }

    // NODE 3: CLASSIFY + ROUTE
    let mut all_packets = PacketVector::new();
    for i in 0..decrypt_vec.len {
        if aead_results.next[i] == NextNode::Drop {
            ctx.slab.free((decrypt_vec.descs[i].addr / ctx.frame_size as u64) as u32);
            stats.drops += 1;
        } else {
            all_packets.push(decrypt_vec.descs[i]);
        }
    }
    for i in 0..cleartext_vec.len {
        all_packets.push(cleartext_vec.descs[i]);
    }
    if all_packets.is_empty() { return stats; }

    let mut classify_disp = Disposition::new();
    let t_classify = read_tsc();
    datapath::classify_route(&all_packets, &mut classify_disp, ctx, &mut stats, ctx.closing);
    stats.classify_tsc = read_tsc() - t_classify;
    if cfg!(debug_assertions) { eprintln!("[DBG] classify done, n={}", all_packets.len); }

    // NODE 4: SCATTER — fan-out by disposition
    let mut recycle_decrypt = PacketVector::new();
    let mut recycle_classify = PacketVector::new();
    let mut tun_vec = PacketVector::new();
    let mut recycle_encrypt = PacketVector::new();
    let mut tx_vec = PacketVector::new();
    let mut handshake_vec = PacketVector::new();
    let mut feedback_vec = PacketVector::new();
    let mut drop_vec = PacketVector::new();
    let mut cleartext_echo_vec = PacketVector::new();
    let mut parity_vec = PacketVector::new();
    let t_scatter = read_tsc();
    scatter(
        &all_packets, &classify_disp,
        &mut recycle_decrypt, &mut recycle_classify,
        &mut tun_vec, &mut recycle_encrypt,
        &mut tx_vec, &mut handshake_vec,
        &mut feedback_vec, &mut drop_vec,
        &mut cleartext_echo_vec,
        &mut parity_vec,
    );
    stats.scatter_tsc = read_tsc() - t_scatter;
    if cfg!(debug_assertions) {
        eprintln!("[DBG] scatter done: tun={} tx={} hs={} fb={} drop={}",
            tun_vec.len, tx_vec.len, handshake_vec.len, feedback_vec.len, drop_vec.len);
    }

    // Free feedback, drop, and recycled (already-processed) frames
    for i in 0..feedback_vec.len {
        stats.feedback += 1;
        ctx.slab.free((feedback_vec.descs[i].addr / ctx.frame_size as u64) as u32);
    }
    for i in 0..drop_vec.len {
        stats.drops += 1;
        ctx.slab.free((drop_vec.descs[i].addr / ctx.frame_size as u64) as u32);
    }
    for i in 0..recycle_decrypt.len {
        ctx.slab.free((recycle_decrypt.descs[i].addr / ctx.frame_size as u64) as u32);
    }
    for i in 0..recycle_classify.len {
        ctx.slab.free((recycle_classify.descs[i].addr / ctx.frame_size as u64) as u32);
    }
    for i in 0..recycle_encrypt.len {
        ctx.slab.free((recycle_encrypt.descs[i].addr / ctx.frame_size as u64) as u32);
    }
    for i in 0..all_packets.len {
        if classify_disp.next[i] == NextNode::Consumed {
            ctx.slab.free((all_packets.descs[i].addr / ctx.frame_size as u64) as u32);
        }
    }
    for i in 0..parity_vec.len {
        ctx.slab.free((parity_vec.descs[i].addr / ctx.frame_size as u64) as u32);
    }
    if cfg!(debug_assertions) { eprintln!("[DBG] free done, entering output nodes"); }

    // FEC RECOVERY: process parity + data, inject recovered frames into tun_vec / tx_vec
    if parity_vec.len > 0 && tun_vec.len > 0 {
        fec_decode_vector(&mut tun_vec, &parity_vec, ctx, &mut stats);
    }

    // OUTPUT: TUN WRITE
    // R-02: When SPSC is active, slab ownership transfers to TUN thread via push.
    //       When SPSC is None (fallback), we free slabs here as before.
    if tun_vec.len > 0 {
        let mut tun_disp = Disposition::new();
        let has_spsc = ctx.tx_tun_prod.is_some();
        let t_tun = read_tsc();
        datapath::tun_write_vector(&tun_vec, &mut tun_disp, ctx, &mut stats);
        stats.tun_write_tsc = read_tsc() - t_tun;
        // Only free slabs if VFS fallback was used (no SPSC = direct write, we own the slab)
        if !has_spsc {
            for i in 0..tun_vec.len {
                ctx.slab.free((tun_vec.descs[i].addr / ctx.frame_size as u64) as u32);
            }
        }
    }

    // OUTPUT: TX ENQUEUE (data forwarding)
    if tx_vec.len > 0 {
        let mut tx_disp = Disposition::new();
        datapath::tx_enqueue_vector(&tx_vec, &mut tx_disp, ctx, &mut stats);
    }

    // COLD PATH: HANDSHAKE + FRAGMENT PROCESSING
    for i in 0..handshake_vec.len {
        let desc = &handshake_vec.descs[i];
        if desc.flags & FLAG_FRAGMENT != 0 {
            process_fragment(desc, ctx, &mut stats);
        } else {
            stats.handshakes += 1;
            ctx.slab.free((desc.addr / ctx.frame_size as u64) as u32);
        }
    }



    // V4: Echo/cleartext packets — route to TUN write for local delivery
    for i in 0..cleartext_echo_vec.len {
        let desc = &cleartext_echo_vec.descs[i];
        ctx.slab.free((desc.addr / ctx.frame_size as u64) as u32);
    }
    stats
}

/// Execute FEC encoding across the current Vector Batch.
/// VPP-style Quad-loop unrolled matrix builder ensures zero L1D stalls.
#[inline(always)]
fn fec_encode_vector(
    routed_vec: &PacketVector,
    parity_vec: &mut PacketVector,
    ctx: &mut GraphCtx<'_>,
) {
    let k = routed_vec.len;
    if k == 0 { return; }

    use m13_hub::engine::fec::{AFEC_SUB_HDR_SIZE, USO_MTU, encode_parity_payload};
    use m13_hub::engine::protocol::{M13_HDR_SIZE, ETH_HDR_SIZE, M13_WIRE_MAGIC, M13_WIRE_VERSION, FLAG_FEC, FLAG_TUNNEL, ETH_P_M13};
    use m13_hub::engine::runtime::prefetch_read_l1;
    use m13_hub::network::PacketDesc;
    use m13_hub::network::datapath::{IP_HDR_LEN, UDP_HDR_LEN};

    // VPP Quad-Loop Unrolling for Matrix ingestion + Continuous Window Parity Generation
    // Grouped independently by peer_idx in the same pass.
    let mut wi = 0;
    while wi + 3 < k {
        if wi + 7 < k {
            unsafe {
                prefetch_read_l1(ctx.umem_base.add(routed_vec.descs[wi + 4].addr as usize + routed_vec.descs[wi + 4].m13_offset as usize + M13_HDR_SIZE));
                prefetch_read_l1(ctx.umem_base.add(routed_vec.descs[wi + 5].addr as usize + routed_vec.descs[wi + 5].m13_offset as usize + M13_HDR_SIZE));
                prefetch_read_l1(ctx.umem_base.add(routed_vec.descs[wi + 6].addr as usize + routed_vec.descs[wi + 6].m13_offset as usize + M13_HDR_SIZE));
                prefetch_read_l1(ctx.umem_base.add(routed_vec.descs[wi + 7].addr as usize + routed_vec.descs[wi + 7].m13_offset as usize + M13_HDR_SIZE));
            }
        }
        for j in 0..4 {
            let desc = &routed_vec.descs[wi + j];
            let pidx = desc.peer_idx as usize;
            
            // V1/V5: DO-178C Hardware-Timestamped Watchdog Read (Wait-free Acquire)
            let target_pacing = if pidx < m13_hub::engine::protocol::MAX_PEERS {
                unsafe { (*ctx.target_pacing_ptr)[pidx].load(ctx.now_ns) }
            } else { 4 };

            let payload_ptr = unsafe {
                ctx.umem_base.add(desc.addr as usize + desc.m13_offset as usize + M13_HDR_SIZE)
            };
            let plen = desc.payload_len as usize;
            
            // SAFETY: payload_ptr computed from UMEM descriptor within bounds.
            unsafe { ctx.peers.fec_encoders[pidx].push(payload_ptr, plen.min(USO_MTU)); }

            // V5: Zero-Parity Bypass — Hardware Passthrough
            if target_pacing == 0 {
                // Instantly exit GF(2^8) logic if perfectly clean environment
                ctx.peers.fec_pacing_counters[pidx] = 0;
                continue;
            }

            ctx.peers.fec_pacing_counters[pidx] += 1;
            
            if ctx.peers.fec_pacing_counters[pidx] >= target_pacing {
                ctx.peers.fec_pacing_counters[pidx] = 0;
                
                // V5: Verbose Terminal Tracker
                if std::env::var("M13_DRL_DEBUG").is_ok() {
                    eprintln!("[M13-DRL] Event: Parity Generated | Threshold Pacing: 1 per {} | Peer: {}", target_pacing, pidx);
                }
                
                if let Some(slab_idx) = ctx.slab.alloc() {
                    let addr = (slab_idx as u64) * ctx.frame_size as u64;
                    let frame_ptr = unsafe { ctx.umem_base.add(addr as usize) };
                    let fec_payload_len = USO_MTU.min(
                        ctx.frame_size as usize - ETH_HDR_SIZE - M13_HDR_SIZE - AFEC_SUB_HDR_SIZE
                    );
                    
                    unsafe { std::ptr::write_bytes(frame_ptr, 0, ETH_HDR_SIZE + M13_HDR_SIZE + AFEC_SUB_HDR_SIZE + fec_payload_len); }
                    
                    let seq = ctx.peers.slots[pidx].next_seq();
                    let base_seq = seq.saturating_sub(ctx.peers.fec_encoders[pidx].count as u64) as u32;
                    let seed = 1;

                    unsafe {
                        let f = std::slice::from_raw_parts_mut(frame_ptr, ETH_HDR_SIZE + M13_HDR_SIZE + AFEC_SUB_HDR_SIZE + fec_payload_len);
                        f[0..6].copy_from_slice(&[0xFF; 6]);
                        f[6..12].copy_from_slice(&ctx.src_mac);
                        f[12] = (ETH_P_M13 >> 8) as u8;
                        f[13] = (ETH_P_M13 & 0xFF) as u8;
                        f[14] = M13_WIRE_MAGIC;
                        f[15] = M13_WIRE_VERSION;
                        f[46..54].copy_from_slice(&seq.to_le_bytes());
                        f[54] = FLAG_FEC | FLAG_TUNNEL;
                        
                        let total_payload = (AFEC_SUB_HDR_SIZE + fec_payload_len) as u32;
                        f[55..59].copy_from_slice(&total_payload.to_le_bytes());
                        
                        let sub_hdr = m13_hub::engine::fec::AfecSubHeader {
                            base_seq_low: base_seq,
                            k: ctx.peers.fec_encoders[pidx].count,
                            parity_idx: 0,
                            seed,
                            density: 0xFF,
                        };
                        std::ptr::write_unaligned(
                            frame_ptr.add(ETH_HDR_SIZE + M13_HDR_SIZE) as *mut _,
                            sub_hdr,
                        );
                        
                        let parity_data = std::slice::from_raw_parts_mut(
                            frame_ptr.add(ETH_HDR_SIZE + M13_HDR_SIZE + AFEC_SUB_HDR_SIZE),
                            fec_payload_len
                        );
                        encode_parity_payload(parity_data, &ctx.peers.fec_encoders[pidx], ctx.peers.fec_encoders[pidx].count as usize, seed);
                    }
                    
                    let mut pdesc = PacketDesc::EMPTY;
                    pdesc.addr = addr;
                    pdesc.len = (ETH_HDR_SIZE + IP_HDR_LEN + UDP_HDR_LEN + M13_HDR_SIZE + AFEC_SUB_HDR_SIZE + fec_payload_len) as u32;
                    pdesc.payload_len = (AFEC_SUB_HDR_SIZE + fec_payload_len) as u32;
                    pdesc.peer_idx = pidx as u8;
                    pdesc.seq_id = seq;
                    pdesc.flags = FLAG_FEC | FLAG_TUNNEL;
                    pdesc.m13_offset = ETH_HDR_SIZE as u16;
                    parity_vec.push(pdesc);
                }
            }
        }
        wi += 4;
    }
    while wi < k {
        let desc = &routed_vec.descs[wi];
        let pidx = desc.peer_idx as usize;
        
        // V1/V5: DO-178C Hardware-Timestamped Watchdog Read (Wait-free Acquire)
        let target_pacing = if pidx < m13_hub::engine::protocol::MAX_PEERS {
            unsafe { (*ctx.target_pacing_ptr)[pidx].load(ctx.now_ns) }
        } else { 4 };

        let payload_ptr = unsafe {
            ctx.umem_base.add(desc.addr as usize + desc.m13_offset as usize + M13_HDR_SIZE)
        };
        let plen = desc.payload_len as usize;
        
        // SAFETY: payload_ptr computed from UMEM descriptor within bounds.
        unsafe { ctx.peers.fec_encoders[pidx].push(payload_ptr, plen.min(USO_MTU)); }
        ctx.peers.fec_pacing_counters[pidx] += 1;
        
        if ctx.peers.fec_pacing_counters[pidx] >= target_pacing {
            ctx.peers.fec_pacing_counters[pidx] = 0;
            
            if let Some(slab_idx) = ctx.slab.alloc() {
                let addr = (slab_idx as u64) * ctx.frame_size as u64;
                let frame_ptr = unsafe { ctx.umem_base.add(addr as usize) };
                let fec_payload_len = USO_MTU.min(
                    ctx.frame_size as usize - ETH_HDR_SIZE - M13_HDR_SIZE - AFEC_SUB_HDR_SIZE
                );
                
                unsafe { std::ptr::write_bytes(frame_ptr, 0, ETH_HDR_SIZE + M13_HDR_SIZE + AFEC_SUB_HDR_SIZE + fec_payload_len); }
                
                let seq = ctx.peers.slots[pidx].next_seq();
                let base_seq = seq.saturating_sub(ctx.peers.fec_encoders[pidx].count as u64) as u32;
                let seed = 1;

                unsafe {
                    let f = std::slice::from_raw_parts_mut(frame_ptr, ETH_HDR_SIZE + M13_HDR_SIZE + AFEC_SUB_HDR_SIZE + fec_payload_len);
                    f[0..6].copy_from_slice(&[0xFF; 6]);
                    f[6..12].copy_from_slice(&ctx.src_mac);
                    f[12] = (ETH_P_M13 >> 8) as u8;
                    f[13] = (ETH_P_M13 & 0xFF) as u8;
                    f[14] = M13_WIRE_MAGIC;
                    f[15] = M13_WIRE_VERSION;
                    f[46..54].copy_from_slice(&seq.to_le_bytes());
                    f[54] = FLAG_FEC | FLAG_TUNNEL;
                    
                    let total_payload = (AFEC_SUB_HDR_SIZE + fec_payload_len) as u32;
                    f[55..59].copy_from_slice(&total_payload.to_le_bytes());
                    
                    let sub_hdr = m13_hub::engine::fec::AfecSubHeader {
                        base_seq_low: base_seq,
                        k: ctx.peers.fec_encoders[pidx].count,
                        parity_idx: 0,
                        seed,
                        density: 0xFF,
                    };
                    std::ptr::write_unaligned(
                        frame_ptr.add(ETH_HDR_SIZE + M13_HDR_SIZE) as *mut _,
                        sub_hdr,
                    );
                    
                    let parity_data = std::slice::from_raw_parts_mut(
                        frame_ptr.add(ETH_HDR_SIZE + M13_HDR_SIZE + AFEC_SUB_HDR_SIZE),
                        fec_payload_len
                    );
                    encode_parity_payload(parity_data, &ctx.peers.fec_encoders[pidx], ctx.peers.fec_encoders[pidx].count as usize, seed);
                }
                
                let mut pdesc = PacketDesc::EMPTY;
                pdesc.addr = addr;
                pdesc.len = (ETH_HDR_SIZE + IP_HDR_LEN + UDP_HDR_LEN + M13_HDR_SIZE + AFEC_SUB_HDR_SIZE + fec_payload_len) as u32;
                pdesc.payload_len = (AFEC_SUB_HDR_SIZE + fec_payload_len) as u32;
                pdesc.peer_idx = pidx as u8;
                pdesc.seq_id = seq;
                pdesc.flags = FLAG_FEC | FLAG_TUNNEL;
                pdesc.m13_offset = ETH_HDR_SIZE as u16;
                parity_vec.push(pdesc);
            }
        }
        wi += 1;
    }
}

/// Execute FEC recovery across the current Vector Batch.
/// Operates exclusively within the SPSC cache footprint.
fn fec_decode_vector(
    tun_vec: &mut PacketVector,
    parity_vec: &PacketVector,
    ctx: &mut GraphCtx<'_>,
    _stats: &mut CycleStats,
) {
    if tun_vec.is_empty() && parity_vec.is_empty() { return; }

    use m13_hub::engine::fec::{AfecSubHeader, AFEC_SUB_HDR_SIZE, MAX_K};
    let mut peer_active = [false; MAX_PEERS];
    let mut peer_base = [0u32; MAX_PEERS];
    let mut peer_pre_mask = [0u8; MAX_PEERS];
    let mut peer_k = [0usize; MAX_PEERS];

    // 1. Ingest Parity (provides base_seq_low, establishes block bounds)
    for i in 0..parity_vec.len {
        let desc = &parity_vec.descs[i];
        let pidx = desc.peer_idx as usize;
        let p_ptr = unsafe { ctx.umem_base.add(desc.addr as usize + desc.m13_offset as usize + M13_HDR_SIZE) };
        let sub_hdr: AfecSubHeader = unsafe { std::ptr::read_unaligned(p_ptr as *const _) };
        
        let decoder = &mut ctx.peers.fec_decoders[pidx];
        
        if !peer_active[pidx] {
            peer_active[pidx] = true;
            peer_base[pidx] = sub_hdr.base_seq_low;
            peer_k[pidx] = sub_hdr.k as usize;
            
            if decoder.base_seq != sub_hdr.base_seq_low
                && sub_hdr.base_seq_low.wrapping_sub(decoder.base_seq) as i32 > 0 {
                    decoder.row_present = 0;
                    decoder.deliver_next = 0;
                    decoder.base_seq = sub_hdr.base_seq_low;
            }
            peer_pre_mask[pidx] = decoder.row_present;
        }

        let fec_payload_len = desc.payload_len as usize - AFEC_SUB_HDR_SIZE;
        let data = unsafe { std::slice::from_raw_parts(p_ptr.add(AFEC_SUB_HDR_SIZE), fec_payload_len) };
        decoder.ingest_parity(sub_hdr.seed, sub_hdr.k as usize, data);
    }

    // 2. Ingest Systematic frames (Data)
    use m13_hub::engine::runtime::prefetch_read_l1;
    let k = tun_vec.len;
    let mut i = 0;
    while i + 3 < k {
        if i + 7 < k {
            unsafe {
                prefetch_read_l1(ctx.umem_base.add(tun_vec.descs[i + 4].addr as usize + tun_vec.descs[i + 4].m13_offset as usize + m13_hub::engine::protocol::M13_HDR_SIZE));
                prefetch_read_l1(ctx.umem_base.add(tun_vec.descs[i + 5].addr as usize + tun_vec.descs[i + 5].m13_offset as usize + m13_hub::engine::protocol::M13_HDR_SIZE));
                prefetch_read_l1(ctx.umem_base.add(tun_vec.descs[i + 6].addr as usize + tun_vec.descs[i + 6].m13_offset as usize + m13_hub::engine::protocol::M13_HDR_SIZE));
                prefetch_read_l1(ctx.umem_base.add(tun_vec.descs[i + 7].addr as usize + tun_vec.descs[i + 7].m13_offset as usize + m13_hub::engine::protocol::M13_HDR_SIZE));
            }
        }
        for j in 0..4 {
            let desc = &tun_vec.descs[i + j];
            let pidx = desc.peer_idx as usize;
            let decoder = &mut ctx.peers.fec_decoders[pidx];
            
            if !peer_active[pidx] {
                peer_active[pidx] = true;
                peer_pre_mask[pidx] = decoder.row_present;
                peer_base[pidx] = decoder.base_seq;
                peer_k[pidx] = 0;
            }

            let seq = desc.seq_id as u32; 
            let rel = seq.wrapping_sub(peer_base[pidx]) as usize;
            if rel < MAX_K {
                peer_pre_mask[pidx] |= 1u8 << rel;
                let p_ptr = unsafe { ctx.umem_base.add(desc.addr as usize + desc.m13_offset as usize + m13_hub::engine::protocol::M13_HDR_SIZE) };
                let plen = desc.payload_len as usize;
                let data = unsafe { std::slice::from_raw_parts(p_ptr, plen) };
                decoder.ingest_systematic(rel, data);
            }
        }
        i += 4;
    }
    while i < k {
        let desc = &tun_vec.descs[i];
        let pidx = desc.peer_idx as usize;
        let decoder = &mut ctx.peers.fec_decoders[pidx];
        
        if !peer_active[pidx] {
            peer_active[pidx] = true;
            peer_pre_mask[pidx] = decoder.row_present;
            peer_base[pidx] = decoder.base_seq;
            peer_k[pidx] = 0;
        }

        let seq = desc.seq_id as u32; 
        let rel = seq.wrapping_sub(peer_base[pidx]) as usize;
        if rel < MAX_K {
            peer_pre_mask[pidx] |= 1u8 << rel;
            let p_ptr = unsafe { ctx.umem_base.add(desc.addr as usize + desc.m13_offset as usize + m13_hub::engine::protocol::M13_HDR_SIZE) };
            let plen = desc.payload_len as usize;
            let data = unsafe { std::slice::from_raw_parts(p_ptr, plen) };
            decoder.ingest_systematic(rel, data);
        }
        i += 1;
    }

    // 3. Extract perfectly recovered frames
    for pidx in 0..MAX_PEERS {
        if peer_active[pidx] && peer_k[pidx] > 0 {
            let decoder = &mut ctx.peers.fec_decoders[pidx];
            let post_mask = decoder.row_present;
            let recovered_mask = post_mask & !peer_pre_mask[pidx];

            // DRL ACCUMULATION: hardware POPCNT on algebraic exclusion mask.
            // ARM64: `cnt` instruction. x86: `popcnt`. Both single-cycle.
            let recovered_count = recovered_mask.count_ones();
            if recovered_count > 0 {
                ctx.peers.slots[pidx].drl_recovered_pkts += recovered_count;
            }
            
            for rel in 0..peer_k[pidx] {
                if (recovered_mask & (1u8 << rel)) != 0 {
                    if let Some(slab_idx) = ctx.slab.alloc() {
                        let payload = decoder.get_payload(rel);
                        let ip_ver = payload[0] >> 4;
                        let ip_len = match ip_ver {
                            4 => u16::from_be_bytes([payload[2], payload[3]]) as usize,
                            6 => 40 + u16::from_be_bytes([payload[4], payload[5]]) as usize,
                            _ => {
                                ctx.slab.free(slab_idx);
                                continue;
                            }
                        };
                        if ip_len == 0 || ip_len > 1500 {
                            ctx.slab.free(slab_idx);
                            continue;
                        }

                        let addr = (slab_idx as u64) * ctx.frame_size as u64;
                        // For tun write to work without shifting, we explicitly offset M13_HDR_SIZE
                        let payload_start = addr as usize + M13_HDR_SIZE; 
                        let ptr = unsafe { ctx.umem_base.add(payload_start) };
                        unsafe {
                            std::ptr::copy_nonoverlapping(payload.as_ptr(), ptr, ip_len);
                        }

                        let mut rec_desc = PacketDesc::EMPTY;
                        rec_desc.addr = addr;
                        rec_desc.len = (M13_HDR_SIZE + ip_len) as u32; 
                        rec_desc.payload_len = ip_len as u32;
                        rec_desc.m13_offset = 0; 
                        
                        tun_vec.push(rec_desc);
                    }
                }
            }
        }
    }
}

/// Process a fragmented frame (cold path — handshake fragments).
fn process_fragment(
    desc: &PacketDesc,
    ctx: &mut GraphCtx<'_>,
    stats: &mut CycleStats,
) {
    let m13_off = desc.m13_offset as usize;
    // desc.addr is a UMEM OFFSET, NOT a pointer. Must add umem_base.
    let frame_ptr = unsafe { ctx.umem_base.add(desc.addr as usize) };
    let frame_len = desc.len as usize;
    let pidx = desc.peer_idx as usize;

    if pidx >= MAX_PEERS || frame_len < m13_off + M13_HDR_SIZE + FRAG_HDR_SIZE {
        ctx.slab.free((desc.addr / ctx.frame_size as u64) as u32);
        return;
    }

    let frag_hdr = unsafe { &*(frame_ptr.add(m13_off + M13_HDR_SIZE) as *const FragHeader) };
    let frag_data_start = m13_off + M13_HDR_SIZE + FRAG_HDR_SIZE;
    let frag_msg_id = unsafe { std::ptr::addr_of!(frag_hdr.frag_msg_id).read_unaligned() };
    let frag_index = unsafe { std::ptr::addr_of!(frag_hdr.frag_index).read_unaligned() };
    let frag_total = unsafe { std::ptr::addr_of!(frag_hdr.frag_total).read_unaligned() };
    let frag_offset = unsafe { std::ptr::addr_of!(frag_hdr.frag_offset).read_unaligned() };
    let frag_data_len = unsafe { std::ptr::addr_of!(frag_hdr.frag_len).read_unaligned() } as usize;

    if frag_data_start + frag_data_len <= frame_len {
        let frag_data = unsafe { std::slice::from_raw_parts(frame_ptr.add(frag_data_start), frag_data_len) };
        // DEFECT γ: Borrow-split — copy Assembler (it's Copy, holds raw ptr) to sever
        // the mutable borrow on PeerTable. Closure captures `ctx` exclusively.
        let mut asm = ctx.peers.assemblers[pidx];
        let has_handshake = desc.flags & FLAG_HANDSHAKE != 0;
        asm.feed(
            frag_msg_id, frag_index, frag_total, frag_offset, desc.flags, frag_data, ctx.now_ns,
            |reassembled| {
                if has_handshake && !reassembled.is_empty() {
                    process_handshake_message(reassembled, pidx, ctx, stats);
                }
            },
        );
        ctx.peers.assemblers[pidx] = asm;
    }
    ctx.slab.free((desc.addr / ctx.frame_size as u64) as u32);
}

/// Process a reassembled handshake message (cold path).
/// Both ClientHello and Finished are dispatched to Core 0 via SPSC.
/// Zero inline lattice math on the datapath.
fn process_handshake_message(
    data: &[u8],
    pidx: usize,
    ctx: &mut GraphCtx<'_>,
    stats: &mut CycleStats,
) {
    if data.is_empty() { return; }
    let msg_type = data[0];
    stats.handshakes += 1;
    const HS_CLIENT_HELLO: u8 = 0x01;
    const HS_FINISHED: u8 = 0x03;

    match msg_type {
        HS_CLIENT_HELLO | HS_FINISHED => {
            // ================================================================
            // UNIFIED ASYNC PQC DISPATCH: Zero Datapath Stalls
            // ================================================================
            // Copy reassembled payload to shared arena (indexed by pidx).
            // Core 0 reads from arena — no payload copied through SPSC ring.
            let max_len = m13_hub::cryptography::async_pqc::MAX_HS_PAYLOAD_SIZE;
            let copy_len = data.len().min(max_len);
            unsafe {
                let arena_slot = &mut *ctx.payload_arena.add(pidx);
                arena_slot[..copy_len].copy_from_slice(&data[..copy_len]);
            }

            if msg_type == HS_CLIENT_HELLO {
                ctx.peers.slots[pidx].lifecycle = PeerLifecycle::Handshaking;
            }

            // Push slim PqcReq (32 bytes) to SPSC ring
            let pqc_msg_type: u8 = if msg_type == HS_CLIENT_HELLO { 1 } else { 2 };
            if let Some(ref mut pqc_tx) = ctx.pqc_req_tx {
                let req = m13_hub::cryptography::async_pqc::PqcReq {
                    pidx: pidx as u16,
                    msg_type: pqc_msg_type,
                    _pad: 0,
                    payload_len: copy_len as u32,
                    rx_ns: ctx.now_ns,
                };
                if pqc_tx.push_batch(&[req]) == 0 {
                    eprintln!("[M13-VPP] PQC SPSC full — msg_type=0x{:02X} pidx={} dropped", msg_type, pidx);
                    stats.handshake_fail += 1;
                }
            }
        }
        _ => {}
    }
}

/// TX pipeline: TUN → AEAD Encrypt → UDP Encapsulate → TX Enqueue.
fn execute_tx_graph(
    ctx: &mut GraphCtx<'_>,
) -> (u64, u64) {
    if ctx.tun_fd < 0 || ctx.worker_idx != 0 { return (0, 0); }
    let mut total_tx: u64 = 0;
    let mut total_tun_read: u64 = 0;

    for _ in 0..4 {
        let mut tun_vec = PacketVector::new();
        let read_count = datapath::tun_read_batch(&mut tun_vec, ctx);
        if read_count == 0 { break; }
        total_tun_read += read_count as u64;

        // PEER ROUTING — match dst_ip to peer
        let mut fallback_idx: Option<usize> = None;
        let mut established_count = 0u16;
        for pi in 0..MAX_PEERS {
            if ctx.peers.slots[pi].lifecycle == PeerLifecycle::Established {
                if fallback_idx.is_none() { fallback_idx = Some(pi); }
                established_count += 1;
            }
        }

        let mut routed_vec = PacketVector::new();
        for i in 0..tun_vec.len {
            let desc = &mut tun_vec.descs[i];
            let peer_idx = match ctx.peers.lookup_by_tunnel_ip(desc.src_ip) {
                Some(idx) => idx,
                None => {
                    if established_count == 1 {
                        fallback_idx.unwrap()
                    } else {
                        ctx.slab.free((desc.addr / ctx.frame_size as u64) as u32);
                        continue;
                    }
                }
            };
            if !ctx.peers.slots[peer_idx].has_session() {
                ctx.slab.free((desc.addr / ctx.frame_size as u64) as u32);
                continue;
            }
            desc.peer_idx = peer_idx as u8;
            let seq = ctx.peers.slots[peer_idx].next_seq();
            desc.seq_id = seq;
            unsafe {
                let m13_ptr = ctx.umem_base.add(desc.addr as usize + desc.m13_offset as usize);
                std::ptr::copy_nonoverlapping(seq.to_le_bytes().as_ptr(), m13_ptr.add(32), 8);
            }
            routed_vec.push(*desc);
        }
        if routed_vec.is_empty() { continue; }

        // ── FEC ENCODE: generate parity frames for this batch ───────────
        let mut parity_vec = PacketVector::new();
        fec_encode_vector(&routed_vec, &mut parity_vec, ctx);

        // AEAD ENCRYPT — data frames
        let mut encrypt_disp = Disposition::new();
        datapath::aead_encrypt_vector(&mut routed_vec, &mut encrypt_disp, ctx);

        // AEAD ENCRYPT — parity frames
        let mut parity_encrypt_disp = Disposition::new();
        if parity_vec.len > 0 {
            datapath::aead_encrypt_vector(&mut parity_vec, &mut parity_encrypt_disp, ctx);
        }

        // UDP ENCAPSULATION + TX ENQUEUE
        for i in 0..routed_vec.len {
            if encrypt_disp.next[i] == NextNode::Drop {
                ctx.slab.free((routed_vec.descs[i].addr / ctx.frame_size as u64) as u32);
                continue;
            }
            let desc = &routed_vec.descs[i];
            let pidx = desc.peer_idx as usize;
            let peer_ip = ctx.peers.slots[pidx].addr.ip().unwrap_or([0; 4]);
            let peer_port = ctx.peers.slots[pidx].addr.port().unwrap_or(0);
            let m13_flen = desc.len as usize;
            let total_len = RAW_HDR_LEN + m13_flen;
            if total_len > ctx.frame_size as usize {
                ctx.slab.free((desc.addr / ctx.frame_size as u64) as u32);
                continue;
            }
            let frame_ptr = unsafe { ctx.umem_base.add(desc.addr as usize) };
            unsafe {
                std::ptr::copy(frame_ptr, frame_ptr.add(RAW_HDR_LEN), m13_flen);
                let raw_frame = std::slice::from_raw_parts_mut(frame_ptr, total_len);
                raw_frame[0..6].copy_from_slice(&ctx.gateway_mac);
                raw_frame[6..12].copy_from_slice(&ctx.src_mac);
                raw_frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
                let ip_total = (20 + 8 + m13_flen) as u16;
                let ip = &mut raw_frame[14..34];
                ip[0] = 0x45; ip[1] = 0x00;
                ip[2..4].copy_from_slice(&ip_total.to_be_bytes());
                ip[4..6].copy_from_slice(&ctx.ip_id_counter.to_be_bytes());
                *ctx.ip_id_counter = ctx.ip_id_counter.wrapping_add(1);
                ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
                ip[8] = 64; ip[9] = 17;
                ip[10..12].copy_from_slice(&[0, 0]);
                ip[12..16].copy_from_slice(&ctx.hub_ip);
                ip[16..20].copy_from_slice(&peer_ip);
                let cksum = m13_hub::network::datapath::ip_checksum(ip);
                ip[10..12].copy_from_slice(&cksum.to_be_bytes());
                raw_frame[34..36].copy_from_slice(&ctx.hub_port.to_be_bytes());
                raw_frame[36..38].copy_from_slice(&peer_port.to_be_bytes());
                let udp_total = (8 + m13_flen) as u16;
                raw_frame[38..40].copy_from_slice(&udp_total.to_be_bytes());
                raw_frame[40..42].copy_from_slice(&[0, 0]);
            }
            if ctx.scheduler.enqueue_bulk(desc.addr, total_len as u32) {
                ctx.peers.slots[pidx].frame_count += 1;
                total_tx += 1;
            } else {
                // Scheduler ring full: free slab (prevents UMEM leak) + track drop
                ctx.slab.free((desc.addr / ctx.frame_size as u64) as u32);
                ctx.peers.slots[pidx].drl_tx_drops += 1;
            }
        }

        // UDP ENCAP + TX ENQUEUE — parity frames (same pattern as data)
        for i in 0..parity_vec.len {
            if parity_encrypt_disp.next[i] == NextNode::Drop {
                ctx.slab.free((parity_vec.descs[i].addr / ctx.frame_size as u64) as u32);
                continue;
            }
            let desc = &parity_vec.descs[i];
            let pidx = desc.peer_idx as usize;
            let peer_ip = ctx.peers.slots[pidx].addr.ip().unwrap_or([0; 4]);
            let peer_port = ctx.peers.slots[pidx].addr.port().unwrap_or(0);
            let m13_flen = desc.len as usize;
            let total_len = RAW_HDR_LEN + m13_flen;
            if total_len > ctx.frame_size as usize {
                ctx.slab.free((desc.addr / ctx.frame_size as u64) as u32);
                continue;
            }
            let frame_ptr = unsafe { ctx.umem_base.add(desc.addr as usize) };
            unsafe {
                std::ptr::copy(frame_ptr, frame_ptr.add(RAW_HDR_LEN), m13_flen);
                let raw_frame = std::slice::from_raw_parts_mut(frame_ptr, total_len);
                raw_frame[0..6].copy_from_slice(&ctx.gateway_mac);
                raw_frame[6..12].copy_from_slice(&ctx.src_mac);
                raw_frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
                let ip_total = (20 + 8 + m13_flen) as u16;
                let ip = &mut raw_frame[14..34];
                ip[0] = 0x45; ip[1] = 0x00;
                ip[2..4].copy_from_slice(&ip_total.to_be_bytes());
                ip[4..6].copy_from_slice(&ctx.ip_id_counter.to_be_bytes());
                *ctx.ip_id_counter = ctx.ip_id_counter.wrapping_add(1);
                ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
                ip[8] = 64; ip[9] = 17;
                ip[10..12].copy_from_slice(&[0, 0]);
                ip[12..16].copy_from_slice(&ctx.hub_ip);
                ip[16..20].copy_from_slice(&peer_ip);
                let cksum = m13_hub::network::datapath::ip_checksum(ip);
                ip[10..12].copy_from_slice(&cksum.to_be_bytes());
                raw_frame[34..36].copy_from_slice(&ctx.hub_port.to_be_bytes());
                raw_frame[36..38].copy_from_slice(&peer_port.to_be_bytes());
                let udp_total = (8 + m13_flen) as u16;
                raw_frame[38..40].copy_from_slice(&udp_total.to_be_bytes());
                raw_frame[40..42].copy_from_slice(&[0, 0]);
            }
            if ctx.scheduler.enqueue_bulk(desc.addr, total_len as u32) {
                total_tx += 1;
            } else {
                // Scheduler ring full: free slab (prevents UMEM leak) + track drop
                ctx.slab.free((desc.addr / ctx.frame_size as u64) as u32);
                ctx.peers.slots[pidx].drl_tx_drops += 1;
            }
        }

        if read_count < VECTOR_SIZE { break; }
    }
    (total_tun_read, total_tx)
}

// ── TUN Housekeeping Thread (R-02A: DPDK Lifecycle Enforcement) ─────────
// Runs on an isolated core. Performs ALL VFS syscalls (read/write) on the TUN fd.
// Communicates with the datapath thread via 4 SPSC lock-free rings.
//
// DPDK-Style Local Cache: [u32; 4096] pending_return buffer.
// Mathematical Bound: TUN HK consumes from tx_tun_cons (2048) + free_to_tun_cons (2048).
// Maximum theoretical in-flight slabs = 4096. Buffer can NEVER overflow.
// This eliminates ALL conditional drops — zero slab leakage under any backpressure scenario.
fn tun_housekeeping_thread(
    tun_file: std::fs::File,
    mut rx_from_dp: m13_hub::engine::spsc::Consumer<m13_hub::network::PacketDesc>,
    mut tx_to_dp: m13_hub::engine::spsc::Producer<m13_hub::network::PacketDesc>,
    mut free_slab_rx: m13_hub::engine::spsc::Consumer<u32>,
    mut free_slab_tx: m13_hub::engine::spsc::Producer<u32>,
    umem_info: std::sync::Arc<std::sync::OnceLock<(usize, u32)>>,
) {
    use std::os::unix::io::AsRawFd;
    use m13_hub::engine::protocol::{M13_HDR_SIZE, ETH_HDR_SIZE, M13_WIRE_MAGIC, M13_WIRE_VERSION, FLAG_TUNNEL, ETH_P_M13};
    use libc::{poll, pollfd, POLLIN};
    let tun_fd = tun_file.as_raw_fd();

    // Block until worker 0 publishes UMEM base after Engine::new()
    eprintln!("[M13-TUN-HK] Waiting for UMEM base from worker 0...");
    let (umem_base_usize, frame_size) = loop {
        if let Some(info) = umem_info.get() {
            break *info;
        }
        if m13_hub::engine::runtime::SHUTDOWN.load(std::sync::atomic::Ordering::Relaxed) {
            eprintln!("[M13-TUN-HK] Shutdown before UMEM available.");
            return;
        }
        std::thread::yield_now();
    };
    let umem_base = umem_base_usize as *mut u8;
    eprintln!("[M13-TUN-HK] UMEM base={:#x}, frame_size={}, TUN fd={}", umem_base_usize, frame_size, tun_fd);

    // DPDK-Style Local Cache: Absorbs backpressure on free_to_dp ring.
    // Absolute Mathematical Maximum: tx_tun_cons (2048) + free_to_tun_cons (2048) = 4096.
    // 4096 * 4 bytes = 16 KB stack array. Impossible to overflow.
    let mut pending_return = [0u32; 4096];
    let mut pending_count: usize = 0;

    let mut pfd = pollfd { fd: tun_fd, events: POLLIN, revents: 0 };
    let mut write_buf = [m13_hub::network::PacketDesc::EMPTY; 64];
    let mut alloc_buf = [0u32; 64];
    let mut total_writes: u64 = 0;
    let mut total_reads: u64 = 0;

    eprintln!("[M13-TUN-HK] VFS Housekeeping Thread active. DPDK cache=4096 slots.");

    loop {
        if m13_hub::engine::runtime::SHUTDOWN.load(std::sync::atomic::Ordering::Relaxed) { break; }

        // ==========================================================
        // PHASE 0: DRAIN PENDING RETURNS (Backpressure Resolution)
        // Must run FIRST to free ring space before generating new returns.
        // ==========================================================
        if pending_count > 0 {
            let pushed = free_slab_tx.push_batch(&pending_return[..pending_count]);
            if pushed > 0 {
                // Fast block-memory shift to preserve cache locality
                pending_return.copy_within(pushed..pending_count, 0);
                pending_count -= pushed;
            }
        }

        // ==========================================================
        // PHASE 1: TX PATH (Datapath → TUN VFS → Return Slabs)
        // ==========================================================
        let write_count = rx_from_dp.pop_batch(&mut write_buf);
        if write_count > 0 {
            let mut local_free = [0u32; 64];
            for i in 0..write_count {
                let desc = &write_buf[i];
                let m13_off = desc.m13_offset as usize;
                let payload_start = m13_off + M13_HDR_SIZE;

                let plen = unsafe {
                    let m13_ptr = umem_base.add(desc.addr as usize + m13_off);
                    u32::from_le_bytes(
                        std::slice::from_raw_parts(m13_ptr.add(41), 4)
                            .try_into().unwrap_or([0;4])
                    )
                } as usize;

                if plen > 0 && payload_start + plen <= desc.len as usize {
                    let payload_ptr = unsafe { umem_base.add(desc.addr as usize + payload_start) };
                    unsafe {
                        libc::write(tun_fd, payload_ptr as *const libc::c_void, plen);
                    }
                    total_writes += 1;
                }
                local_free[i] = (desc.addr / frame_size as u64) as u32;
            }

            // Attempt immediate return; overflow into DPDK cache (guaranteed to fit)
            let pushed = free_slab_tx.push_batch(&local_free[..write_count]);
            for &idx in local_free.iter().take(write_count).skip(pushed) {
                pending_return[pending_count] = idx;
                pending_count += 1;
            }
        }

        // ==========================================================
        // PHASE 2: RX PATH (TUN VFS → Datapath)
        // Uses poll() with 1ms timeout to avoid busy-spinning.
        // ==========================================================
        let p_res = unsafe { poll(&mut pfd, 1, 1) }; // 1ms timeout
        if p_res > 0 && (pfd.revents & POLLIN) != 0 {
            let alloc_count = free_slab_rx.pop_batch(&mut alloc_buf);


            for i in 0..alloc_count {
                let idx = alloc_buf[i];
                let addr = (idx as u64) * (frame_size as u64);
                let frame_ptr = unsafe { umem_base.add(addr as usize) };
                let payload_ptr = unsafe { frame_ptr.add(ETH_HDR_SIZE + M13_HDR_SIZE) };
                let max_payload = frame_size as usize - ETH_HDR_SIZE - M13_HDR_SIZE;

                let n = unsafe {
                    libc::read(tun_fd, payload_ptr as *mut libc::c_void, max_payload)
                };

                if n <= 0 {
                    // EAGAIN or failure: Return this slab AND all remaining unused slabs
                    // to the DPDK cache. Mathematically guaranteed to fit (max 4096).
                    pending_return[pending_count] = idx;
                    pending_count += 1;
                    for &idx in alloc_buf.iter().take(alloc_count).skip(i + 1) {
                        pending_return[pending_count] = idx;
                        pending_count += 1;
                    }
                    break;
                }

                let payload_len = n as usize;
                let frame_len = ETH_HDR_SIZE + M13_HDR_SIZE + payload_len;

                // Build Ethernet + M13 header in-place
                let frame = unsafe { std::slice::from_raw_parts_mut(frame_ptr, frame_len) };
                frame[0..6].copy_from_slice(&[0xFF; 6]);
                frame[6..12].copy_from_slice(&[0; 6]); // src_mac filled by datapath
                frame[12] = (ETH_P_M13 >> 8) as u8;
                frame[13] = (ETH_P_M13 & 0xFF) as u8;
                frame[14] = M13_WIRE_MAGIC;
                frame[15] = M13_WIRE_VERSION;
                frame[54] = FLAG_TUNNEL;
                frame[55..59].copy_from_slice(&(payload_len as u32).to_le_bytes());

                let mut desc = m13_hub::network::PacketDesc::EMPTY;
                desc.addr = addr;
                desc.len = frame_len as u32;
                desc.m13_offset = ETH_HDR_SIZE as u16;
                desc.flags = FLAG_TUNNEL;
                desc.payload_len = payload_len as u32;

                if payload_len >= 20 {
                    let ip_hdr = unsafe { std::slice::from_raw_parts(payload_ptr as *const u8, 20) };
                    desc.src_ip.copy_from_slice(&ip_hdr[16..20]);
                }

                if tx_to_dp.push_batch(&[desc]) == 0 {
                    // rx_tun ring full: cache the slab for return (guaranteed to fit)
                    pending_return[pending_count] = idx;
                    pending_count += 1;
                }
                total_reads += 1;
            }
        } else if write_count == 0 {
            // No TX work and no RX data — yield to avoid busy-spinning
            std::thread::yield_now();
        }
    }

    // Drain remaining pending returns at shutdown
    if pending_count > 0 {
        let pushed = free_slab_tx.push_batch(&pending_return[..pending_count]);
        if pushed < pending_count {
            eprintln!("[M13-TUN-HK] Shutdown: {} slabs unrecoverable (ring full at exit)", pending_count - pushed);
        }
    }

    eprintln!("[M13-TUN-HK] Shutdown. Total writes: {}, reads: {}, pending_at_exit: {}", total_writes, total_reads, pending_count);
}

// ── Worker Entry ────────────────────────────────────────────────────────
#[allow(clippy::too_many_arguments)]
fn worker_entry(
    worker_idx: usize, core_id: usize, queue_id: i32, if_name: &str,
    bpf_map_fd: i32, cal: TscCal, tun: Option<std::fs::File>,
    mut spsc_tx_tun_prod: Option<m13_hub::engine::spsc::Producer<m13_hub::network::PacketDesc>>,
    mut spsc_rx_tun_cons: Option<m13_hub::engine::spsc::Consumer<m13_hub::network::PacketDesc>>,
    mut spsc_free_to_tun_prod: Option<m13_hub::engine::spsc::Producer<u32>>,
    mut spsc_free_to_dp_cons: Option<m13_hub::engine::spsc::Consumer<u32>>,
    umem_info: std::sync::Arc<std::sync::OnceLock<(usize, u32)>>,
    mut spsc_drl_state_prod: Option<m13_hub::engine::spsc::Producer<m13_hub::engine::drl::DrlStateTensor>>,
    target_pacing_ptr: *const [m13_hub::engine::drl::DrlPacingState; 256],
) {
    pin_to_core(core_id);
    verify_affinity(core_id);
    let stats = Telemetry::map_worker(worker_idx, true);
    // SAFETY: SYS_gettid always returns a valid TID on Linux.
    stats.pid.value.store(unsafe { libc::syscall(libc::SYS_gettid) } as u32, Ordering::Relaxed);
    let mut engine = Engine::<ZeroCopyTx>::new_zerocopy(if_name, queue_id, bpf_map_fd);
    eprintln!("[M13-W{}] Datapath: {}", worker_idx, engine.xdp_mode);

    // R-02: Worker 0 publishes UMEM base to unblock TUN HK thread.
    if worker_idx == 0 {
        let _ = umem_info.set((engine.umem_base() as usize, FRAME_SIZE));
        eprintln!("[M13-W0] Published UMEM base={:#x} frame_size={} to TUN HK",
            engine.umem_base() as usize, FRAME_SIZE);
    }
    let mut slab = FixedSlab::new(SLAB_DEPTH);
    let mut scheduler = Scheduler::new();
    let mut rx_state = ReceiverState::new();
    let mut rx_bitmap = RxBitmap::new();
    let hexdump_enabled = std::env::var("M13_HEXDUMP").is_ok();
    let mut hexdump = HexdumpState::new(hexdump_enabled);
    let mut gc_counter: u64 = 0;
    let iface_mac = detect_mac(if_name);
    let src_mac = iface_mac;

    // Multi-tenant peer table
    let mut peers = PeerTable::new(rdtsc_ns(&cal));
    eprintln!("[M13-W{}] PeerTable: {} slots, tunnel subnet 10.13.0.0/24", worker_idx, MAX_PEERS);

    // === PURE AF_XDP: No kernel socket. Raw UDP TX via AF_XDP ring. ===
    let hub_port: u16 = std::env::var("M13_LISTEN_PORT").ok()
        .and_then(|p| p.parse::<u16>().ok()).unwrap_or(443);
    let mut hub_ip: [u8; 4] = get_interface_ip(if_name).unwrap_or_else(|| {
        eprintln!("[M13-W{}] Hub IP not on interface — will learn from first inbound packet.", worker_idx);
        [0, 0, 0, 0]
    });
    let (mut gateway_mac, _gw_ip) = resolve_gateway_mac(if_name).unwrap_or_else(|| {
        eprintln!("[M13-W{}] Gateway MAC not in ARP — will learn from first inbound packet.", worker_idx);
        ([0xFF; 6], [0, 0, 0, 0])
    });
    let mut ip_id_counter: u16 = (worker_idx as u16).wrapping_mul(10000);
    eprintln!("[M13-W{}] AF_XDP Pure Mode: hub={}:{} gw_mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        worker_idx,
        hub_ip[0], hub_ip[1],
        gateway_mac[0], gateway_mac[1], gateway_mac[2],
        gateway_mac[3], gateway_mac[4], gateway_mac[5]);

    let mut udp_rx_count: u64 = 0;
    let mut udp_tx_count: u64 = 0;
    let mut tun_write_count: u64 = 0;
    let mut tun_read_count: u64 = 0;
    let mut aead_ok_count: u64 = 0;
    let mut aead_fail_count: u64 = 0;
    let mut last_hub_report_ns: u64 = 0;
    let worker_start_ns: u64 = rdtsc_ns(&cal);
    for i in 0..SLAB_DEPTH {
        let fp = engine.get_frame_ptr(i as u32);
        // SAFETY: Pointer arithmetic within UMEM bounds; offset validated by kernel ring descriptor.
        unsafe {
            let eth = &mut *(fp as *mut EthernetHeader);
            let m13 = &mut *(fp.add(ETH_HDR_SIZE) as *mut M13Header);
            eth.dst = [0xFF; 6]; // broadcast — real dst set per-frame
            eth.src = src_mac;
            eth.ethertype = ETH_P_M13.to_be();
            m13.signature = [0; 32];
            m13.signature[0] = M13_WIRE_MAGIC;
            m13.signature[1] = M13_WIRE_VERSION;
            m13.seq_id = 0; m13.flags = 0;
            m13.payload_len = 0; m13.padding = [0; 3];
        }
    }
    engine.refill_rx_full(&mut slab);
    let umem = engine.umem_base();

    // Measure ε_proc (processing jitter floor) and create jitter buffer
    let epsilon_ns = measure_epsilon_proc(&cal);
    let mut jbuf = JitterBuffer::new();
    eprintln!("[M13-W{}] ACTIVE. Pipeline: Graph({}) Deadline: {}us Prefetch: {} HW_Fill: {}/{} \
              SeqWin: {} Feedback: every {} pkts \
              JBuf: {}entries D_buf={}us ε={}us",
        worker_idx, GRAPH_BATCH, DEADLINE_NS / 1000, PREFETCH_DIST, HW_FILL_MAX, TX_RING_SIZE,
        SEQ_WINDOW, FEEDBACK_INTERVAL_PKTS,
        JBUF_CAPACITY, jbuf.depth_ns / 1000, epsilon_ns / 1000);

    // SAFETY: Type is repr(C) and all-zeroes is a valid bit pattern.
    let mut rx_batch: [libbpf_sys::xdp_desc; GRAPH_BATCH] = unsafe { mem::zeroed() };

    // Graceful close state
    let mut closing = false;
    let mut fin_deadline_ns: u64 = 0;

    // ========================================================================
    // WORLD-CLASS FIX: ASYNC PQC CONTROL PLANE (Zero Datapath Stalls)
    // ========================================================================
    // Both ClientHello (10ms) and Finished (5ms) offloaded to Core 0.
    // OSI layer decoupling: Core 0 handles crypto only (Layer 7).
    // Datapath handles L2/L3 framing with locally-learned hub_ip/gateway_mac.
    let (spsc_pqc_req_prod, spsc_pqc_req_cons, spsc_pqc_resp_prod, spsc_pqc_resp_cons) =
        m13_hub::cryptography::async_pqc::make_pqc_spsc();

    // Allocate shared payload arena (datapath writes, Core 0 reads)
    let payload_arena_box = Box::new(
        [[0u8; m13_hub::cryptography::async_pqc::MAX_HS_PAYLOAD_SIZE]; MAX_PEERS]
    );
    let payload_arena_ptr: *mut [u8; m13_hub::cryptography::async_pqc::MAX_HS_PAYLOAD_SIZE] =
        Box::into_raw(payload_arena_box) as *mut _;

    // Allocate Core 0-local hs_state arena (Core 0 writes and reads)
    let hs_state_arena_box = Box::new(
        [m13_hub::cryptography::async_pqc::FlatHubHandshakeState::EMPTY; MAX_PEERS]
    );
    let hs_state_arena_ptr: *mut m13_hub::cryptography::async_pqc::FlatHubHandshakeState =
        Box::into_raw(hs_state_arena_box) as *mut _;

    // Spawn PQC Control Plane on Core 0 — receives arena pointers as usize (Send-safe).
    // usize is unconditionally Send. Reconstruct pointers inside the thread.
    let pqc_payload_usize = payload_arena_ptr as usize;
    let pqc_hs_usize = hs_state_arena_ptr as usize;
    std::thread::Builder::new().name("m13-pqc-cp".into()).spawn(move || {
        let pa = pqc_payload_usize as *const [u8; m13_hub::cryptography::async_pqc::MAX_HS_PAYLOAD_SIZE];
        let ha = pqc_hs_usize as *mut m13_hub::cryptography::async_pqc::FlatHubHandshakeState;
        // SAFETY: pa and ha are reconstructed from leaked heap allocations with 'static lifetime.
        // pa is read-only by PQC worker (written by datapath before SPSC push).
        // ha is exclusively owned by PQC worker after thread spawn.
        unsafe {
            m13_hub::cryptography::async_pqc::pqc_worker_thread(
                0, // core_id: Linux Housekeeping Core 0
                spsc_pqc_req_cons,
                spsc_pqc_resp_prod,
                pa,
                ha,
                MAX_PEERS,
            );
        }
    }).expect("FATAL: Failed to spawn Core 0 PQC Control Plane");

    // Datapath retains producer (req) and consumer (resp) ends
    let mut spsc_pqc_req_prod: Option<m13_hub::engine::spsc::Producer<m13_hub::cryptography::async_pqc::PqcReq>> = Some(spsc_pqc_req_prod);
    let mut spsc_pqc_resp_cons: Option<m13_hub::engine::spsc::Consumer<m13_hub::cryptography::async_pqc::PqcResp>> = Some(spsc_pqc_resp_cons);

    // V4: EDT pacer — zero-spin, 10 Gbps default Starlink/Local link rate (Peak Speed)
    let mut edt_pacer = Some(m13_hub::network::uso_pacer::EdtPacer::new(&cal, 10_000_000_000));

    // Hub header template for TUN→AF_XDP path
    // Pre-stamp static M13 header bytes once. Copy per-packet via single memcpy
    // instead of 8 individual writes + fill(0). bytes 16..62 already 0.

    loop {
        // Graceful close protocol.
        // On m13_hub::engine::runtime::SHUTDOWN: send 3x FIN, then keep looping (RX only) until FIN-ACK or deadline.
        if m13_hub::engine::runtime::SHUTDOWN.load(Ordering::Relaxed) && !closing {
            closing = true;
            let rtprop: u64 = 10_000_000;
            fin_deadline_ns = rdtsc_ns(&cal) + rtprop.saturating_mul(5).clamp(10_000_000, 100_000_000);
            // Send FIN to all established peers via raw UDP
            let mut fin_total = 0usize;
            for pi in 0..MAX_PEERS {
                if peers.slots[pi].lifecycle == PeerLifecycle::Established {
                    let sent = if peers.slots[pi].addr.is_udp() {
                        send_fin_burst_udp(
                            &mut slab, &engine, &mut scheduler,
                            &src_mac, &gateway_mac,
                            hub_ip, peers.slots[pi].addr.ip().unwrap(),
                            hub_port, peers.slots[pi].addr.port().unwrap(),
                            &mut ip_id_counter,
                            peers.slots[pi].seq_tx, false, 3,
                        )
                    } else {
                        send_fin_burst_l2(
                            &mut slab, &engine, &mut scheduler,
                            &src_mac, &peers.slots[pi].mac,
                            peers.slots[pi].seq_tx, false, 3,
                        )
                    };
                    fin_total += sent;
                }
            }
            eprintln!("[M13-W{}] FIN sent to {} peers ({}x total). Deadline={}ms.",
                worker_idx, peers.count, fin_total,
                (fin_deadline_ns.saturating_sub(rdtsc_ns(&cal))) / 1_000_000);
        }
        if closing && rdtsc_ns(&cal) >= fin_deadline_ns {
            eprintln!("[M13-W{}] FIN deadline expired. Force-closing.", worker_idx);
            break;
        }
        let now = rdtsc_ns(&cal);
        stats.cycles.value.fetch_add(1, Ordering::Relaxed);
        engine.recycle_tx(&mut slab);
        engine.refill_rx(&mut slab);

        // TUN TX — VPP pipeline: tun_read_batch → aead_encrypt_vector → UDP encap → TX enqueue
        // Only worker 0 reads TUN to avoid contention/reordering.
        // Vectorized AEAD encrypt saturates AES-NI/ARMv8-CE pipeline (4-at-a-time prefetch).
        if worker_idx == 0 {
            let mut tx_gctx = m13_hub::network::GraphCtx {
                peers: &mut peers,
                slab: &mut slab,
                scheduler: &mut scheduler,
                rx_state: &mut rx_state,
                rx_bitmap: &mut rx_bitmap,
                tun_fd: tun.as_ref().map(|f| {
                    use std::os::unix::io::AsRawFd;
                    f.as_raw_fd()
                }).unwrap_or(-1),
                src_mac,
                gateway_mac,
                hub_ip,
                hub_port,
                ip_id_counter: &mut ip_id_counter,
                worker_idx,
                closing,
                now_ns: now,
                umem_base: engine.umem_base(),
                frame_size: FRAME_SIZE,
                // R-02: SPSC handles (None = VFS fallback)
                tx_tun_prod: spsc_tx_tun_prod.as_mut(),
                rx_tun_cons: spsc_rx_tun_cons.as_mut(),
                free_to_tun_prod: spsc_free_to_tun_prod.as_mut(),
                free_to_dp_cons: spsc_free_to_dp_cons.as_mut(),
                // DEFECT ε FIXED: Observability exports
                hexdump: &mut hexdump,
                cal,
                // V4: PQC offload + EDT pacer
                pqc_req_tx: spsc_pqc_req_prod.as_mut(),
                pqc_resp_rx: spsc_pqc_resp_cons.as_mut(),
                payload_arena: payload_arena_ptr,
                pacer: edt_pacer.as_mut(),
                drl_state_tx: spsc_drl_state_prod.as_mut(),
                target_pacing_ptr,
            };
            let (tun_read, tx_count) = execute_tx_graph(&mut tx_gctx);
            udp_tx_count += tx_count;
            tun_read_count += tun_read;
        }
        // === HUB WORKER TELEMETRY (1/sec) ===
        if now.saturating_sub(last_hub_report_ns) > 1_000_000_000 {
            last_hub_report_ns = now;
            let mut established = 0u16;
            for pi in 0..MAX_PEERS {
                if peers.slots[pi].lifecycle == PeerLifecycle::Established { established += 1; }
            }
            let hs_ok = stats.handshake_ok.value.load(Ordering::Relaxed);
            let hs_fail = stats.handshake_fail.value.load(Ordering::Relaxed);
            eprintln!("[M13-W{}] RX:{} TX:{} TUN_R:{} TUN_W:{} AEAD:{}/{} HS:{}/{} Slab:{}/{} Peers:{}/{} Up:{}s",
                worker_idx, udp_rx_count, udp_tx_count,
                tun_read_count, tun_write_count,
                aead_ok_count, aead_fail_count,
                hs_ok, hs_fail,
                slab.available(), SLAB_DEPTH,
                established, peers.count,
                (now - worker_start_ns) / 1_000_000_000);
        }

        // === STAGE 0: ADAPTIVE BATCH DRAIN ===
        let mut rx_count = engine.poll_rx_batch(&mut rx_batch, &stats);
        if rx_count > 0 && rx_count < GRAPH_BATCH {
            loop {
                engine.recycle_tx(&mut slab); engine.refill_rx(&mut slab);
                let n = engine.poll_rx_batch(&mut rx_batch[rx_count..], &stats);
                rx_count += n;
                if rx_count >= GRAPH_BATCH || rdtsc_ns(&cal) - now >= DEADLINE_NS { break; }
            }
        }

        // === STAGE 0.5: JITTER BUFFER DRAIN ===
        // Release TC_CRITICAL frames whose release time has arrived.
        // Must happen BEFORE classification so buffered frames from previous
        // cycles get scheduled THIS cycle.
        {
            let (rel, _) = jbuf.drain(now, &mut scheduler);
            if rel > 0 {
                // Bridge jitter buffer telemetry (4 Relaxed stores)
                stats.jbuf_depth_us.value.store(jbuf.depth_ns / 1000, Ordering::Relaxed);
                stats.jbuf_jitter_us.value.store(jbuf.estimator.get() / 1000, Ordering::Relaxed);
                stats.jbuf_releases.value.store(jbuf.total_releases, Ordering::Relaxed);
                stats.jbuf_drops.value.store(jbuf.total_drops, Ordering::Relaxed);
            }
        }

        // === VPP GRAPH EXECUTOR ===
        // Parse → AEAD → Classify → Route → TUN write → Fragment → Handshake
        // Replaces the monolithic per-packet classify loop with vectorized processing.
        let rx_batch_ns = if rx_count > 0 { now } else { 0 };

        if rx_count > 0 {
            // Convert AF_XDP descriptors to (addr, len) pairs
            let mut rx_descs: [(u64, u32); GRAPH_BATCH] = [(0, 0); GRAPH_BATCH];
            for i in 0..rx_count {
                rx_descs[i] = (rx_batch[i].addr, rx_batch[i].len);
            }

            // Extract TUN fd for the executor (raw fd, -1 if no TUN)
            let tun_fd = tun.as_ref().map(|f| {
                use std::os::unix::io::AsRawFd;
                f.as_raw_fd()
            }).unwrap_or(-1);

            {
                let mut gctx = m13_hub::network::GraphCtx {
                    peers: &mut peers,
                    slab: &mut slab,
                    scheduler: &mut scheduler,
                    rx_state: &mut rx_state,
                    rx_bitmap: &mut rx_bitmap,
                    tun_fd,
                    src_mac,
                    gateway_mac,
                    hub_ip,
                    hub_port,
                    ip_id_counter: &mut ip_id_counter,
                    worker_idx,
                    closing,
                    now_ns: now,
                    umem_base: umem,
                    frame_size: FRAME_SIZE,
                    // R-02: SPSC handles (None = VFS fallback)
                    tx_tun_prod: spsc_tx_tun_prod.as_mut(),
                    rx_tun_cons: spsc_rx_tun_cons.as_mut(),
                    free_to_tun_prod: spsc_free_to_tun_prod.as_mut(),
                    free_to_dp_cons: spsc_free_to_dp_cons.as_mut(),
                    // DEFECT ε FIXED: Observability exports
                    hexdump: &mut hexdump,
                    cal,
                    // V4: PQC offload + EDT pacer
                    pqc_req_tx: spsc_pqc_req_prod.as_mut(),
                    pqc_resp_rx: spsc_pqc_resp_cons.as_mut(),
                    payload_arena: payload_arena_ptr,
                    pacer: edt_pacer.as_mut(),
                    drl_state_tx: spsc_drl_state_prod.as_mut(),
                    target_pacing_ptr,
                };

                let cycle = execute_graph(
                    &rx_descs[..rx_count], &mut gctx,
                );

                // Propagate learned network addresses back from GraphCtx.
                // hub_ip and gateway_mac are VALUE copies in GraphCtx; rx_parse_raw
                // learns them from the first inbound packet but writes to the copy.
                // Without this, all TX frames use src_ip=0.0.0.0 → unroutable.
                hub_ip = gctx.hub_ip;
                gateway_mac = gctx.gateway_mac;

                // Bridge telemetry — counters
                udp_rx_count += cycle.parsed as u64;
                aead_ok_count += cycle.aead_ok as u64;
                aead_fail_count += cycle.aead_fail as u64;
                tun_write_count += cycle.tun_writes as u64;

                // Bridge telemetry — security counters to SHM
                stats.decrypt_ok.value.fetch_add(cycle.aead_ok, Ordering::Relaxed);
                stats.auth_fail.value.fetch_add(cycle.aead_fail, Ordering::Relaxed);
                stats.drops.value.fetch_add(cycle.drops, Ordering::Relaxed);
                stats.rx_count.value.fetch_add(cycle.parsed, Ordering::Relaxed);

                // Bridge telemetry — per-stage TSC timing to SHM
                stats.parse_tsc_total.value.fetch_add(cycle.parse_tsc, Ordering::Relaxed);
                stats.decrypt_tsc_total.value.fetch_add(cycle.decrypt_tsc, Ordering::Relaxed);
                stats.classify_tsc_total.value.fetch_add(cycle.classify_tsc, Ordering::Relaxed);
                stats.scatter_tsc_total.value.fetch_add(cycle.scatter_tsc, Ordering::Relaxed);
                stats.tun_write_tsc_total.value.fetch_add(cycle.tun_write_tsc, Ordering::Relaxed);
                stats.handshake_ok.value.fetch_add(cycle.handshake_ok, Ordering::Relaxed);
                stats.handshake_fail.value.fetch_add(cycle.handshake_fail, Ordering::Relaxed);
                stats.direction_fail.value.fetch_add(cycle.direction_fail, Ordering::Relaxed);

                // Process deferred FIN events (executor can't send FIN-ACK — needs Engine)
                for fi in 0..cycle.fin_count {
                    let (peer_idx, was_closing) = cycle.fin_events[fi];
                    let pidx = peer_idx as usize;
                    if pidx >= MAX_PEERS { continue; }

                    if was_closing {
                        eprintln!("[M13-W{}] FIN-ACK received. Graceful close complete.", worker_idx);
                        fin_deadline_ns = 0;
                    } else {
                        eprintln!("[M13-W{}] FIN received from peer {:?}. Sending FIN-ACK.",
                            worker_idx, peers.slots[pidx].addr);
                        if peers.slots[pidx].addr.is_udp() {
                            send_fin_burst_udp(
                                &mut slab, &engine, &mut scheduler,
                                &src_mac, &gateway_mac,
                                hub_ip, peers.slots[pidx].addr.ip().unwrap(),
                                hub_port, peers.slots[pidx].addr.port().unwrap(),
                                &mut ip_id_counter,
                                peers.slots[pidx].seq_tx, true, 3,
                            );
                        } else {
                            send_fin_burst_l2(
                                &mut slab, &engine, &mut scheduler,
                                &src_mac, &peers.slots[pidx].mac,
                                peers.slots[pidx].seq_tx, true, 3,
                            );
                        }
                        peers.evict(pidx);
                    }
                }

                // Process registration echoes — send FLAG_CONTROL echo to peers
                // without sessions so Node transitions Registering → Handshaking.
                // Done OUTSIDE pipeline (like FIN-ACK) to avoid UMEM slab corruption.
                //
                // DEFECT α FIX: 100ms throttle prevents slab exhaustion from
                // uncontrolled echo storms. slab.free(idx) on enqueue failure
                // prevents catastrophic slab leak.
                for pidx in 0..MAX_PEERS {
                    if peers.slots[pidx].is_empty() { continue; }
                    if peers.slots[pidx].has_session() { continue; }

                    // 100ms echo throttle — prevents UMEM slab exhaustion
                    if now.saturating_sub(peers.slots[pidx].last_echo_ns) < 100_000_000 {
                        continue;
                    }
                    peers.slots[pidx].last_echo_ns = now;

                    // Build a minimal valid M13 frame
                    let mut echo_m13 = [0u8; 62]; // ETH(14) + M13(48)
                    echo_m13[14] = M13_WIRE_MAGIC;
                    echo_m13[15] = M13_WIRE_VERSION;
                    echo_m13[54] = FLAG_CONTROL;

                    if peers.slots[pidx].addr.is_udp() {
                        let peer_ip = match peers.slots[pidx].addr.ip() {
                            Some(ip) => ip,
                            None => continue,
                        };
                        let peer_port = match peers.slots[pidx].addr.port() {
                            Some(p) => p,
                            None => continue,
                        };
                        echo_m13[0..6].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
                        echo_m13[6..12].copy_from_slice(&src_mac);
                        echo_m13[12] = (ETH_P_M13 >> 8) as u8;
                        echo_m13[13] = (ETH_P_M13 & 0xFF) as u8;

                        if let Some(idx) = slab.alloc() {
                            let frame_ptr = unsafe { umem.add((idx as usize) * FRAME_SIZE as usize) };
                            let total_len;
                            unsafe {
                                let buf = std::slice::from_raw_parts_mut(frame_ptr, FRAME_SIZE as usize);
                                total_len = build_raw_udp_frame(
                                    buf, &src_mac, &gateway_mac,
                                    hub_ip, peer_ip, hub_port, peer_port,
                                    ip_id_counter, &echo_m13,
                                );
                                ip_id_counter = ip_id_counter.wrapping_add(1);
                            }
                            if !scheduler.enqueue_critical(
                                (idx as u64) * FRAME_SIZE as u64,
                                total_len as u32,
                            ) {
                                slab.free(idx); // CRITICAL: Prevent slab leak
                            }
                        }
                    } else {
                        // L2 peer — send raw ETH+M13 echo
                        echo_m13[0..6].copy_from_slice(&peers.slots[pidx].mac);
                        echo_m13[6..12].copy_from_slice(&src_mac);
                        echo_m13[12] = (ETH_P_M13 >> 8) as u8;
                        echo_m13[13] = (ETH_P_M13 & 0xFF) as u8;

                        if let Some(idx) = slab.alloc() {
                            let frame_ptr = unsafe { umem.add((idx as usize) * FRAME_SIZE as usize) };
                            unsafe {
                                let buf = std::slice::from_raw_parts_mut(frame_ptr, FRAME_SIZE as usize);
                                buf[..62].copy_from_slice(&echo_m13);
                            }
                            if !scheduler.enqueue_critical(
                                (idx as u64) * FRAME_SIZE as u64,
                                62,
                            ) {
                                slab.free(idx); // CRITICAL: Prevent slab leak
                            }
                        }
                    }
                }
            }
        }

        // === STAGE 3: FEEDBACK GENERATION ===
        stage_feedback_gen(umem, &mut rx_state, &mut rx_bitmap, &mut slab, &mut scheduler, &src_mac, &jbuf, rx_batch_ns);

        // === V4: PQC RESPONSE DRAIN ===
        // Drain completed PQC responses from the SPSC ring.
        // Core 0 returns raw crypto payload. Datapath frames with learned addresses.
        if let Some(ref mut pqc_rx) = spsc_pqc_resp_cons {
            let mut resp_batch = [m13_hub::cryptography::async_pqc::PqcResp::EMPTY; 8];
            let count = pqc_rx.pop_batch(&mut resp_batch);
            for resp in resp_batch.iter().take(count) {
                let pidx = resp.pidx as usize;
                if pidx >= MAX_PEERS { continue; }

                if resp.success == 0 {
                    // Handshake failed
                    peers.hs_sidecar[pidx] = None;
                    stats.handshake_fail.value.fetch_add(1, Ordering::Relaxed);
                    eprintln!("[M13-PQC-DRAIN] Handshake FAILED pidx={}", pidx);
                    continue;
                }

                match resp.msg_type {
                    0x02 => {
                        // ServerHello: Core 0 completed ClientHello processing.
                        // Frame raw payload with datapath-local hub_ip/gateway_mac.
                        let payload = &resp.response_payload[..resp.response_len as usize];
                        let hs_flags = FLAG_CONTROL | FLAG_HANDSHAKE;
                        let mut hs_seq_tx = peers.slots[pidx].seq_tx;

                        if peers.slots[pidx].addr.is_udp() {
                            let peer_ip = peers.slots[pidx].addr.ip().unwrap_or([0; 4]);
                            let peer_port = peers.slots[pidx].addr.port().unwrap_or(0);
                            build_fragmented_raw_udp(
                                &src_mac, &gateway_mac, hub_ip, peer_ip,
                                hub_port, peer_port, payload, hs_flags,
                                &mut hs_seq_tx, &mut ip_id_counter,
                                |frame_data, flen| {
                                    let frame_now = rdtsc_ns(&cal);
                                    // SAFETY: frame_data.as_ptr() is valid — derived from &[u8] slice.
                                    unsafe { hexdump.dump_tx(frame_data.as_ptr(), flen as usize, frame_now); }
                                    if let Some(slab_idx) = slab.alloc() {
                                        let dst = unsafe { umem.add(slab_idx as usize * FRAME_SIZE as usize) };
                                        let copy_len = (flen as usize).min(FRAME_SIZE as usize);
                                        unsafe { std::ptr::copy_nonoverlapping(frame_data.as_ptr(), dst, copy_len); }
                                        scheduler.enqueue_critical(
                                            (slab_idx as u64) * FRAME_SIZE as u64, flen,
                                        );
                                    }
                                },
                            );
                        } else {
                            let peer_mac = peers.slots[pidx].mac;
                            build_fragmented_l2(
                                &src_mac, &peer_mac,
                                payload, hs_flags,
                                &mut hs_seq_tx,
                                |frame_data, flen| {
                                    let frame_now = rdtsc_ns(&cal);
                                    // SAFETY: frame_data.as_ptr() is valid — derived from &[u8] slice.
                                    unsafe { hexdump.dump_tx(frame_data.as_ptr(), flen as usize, frame_now); }
                                    if let Some(slab_idx) = slab.alloc() {
                                        let dst = unsafe { umem.add(slab_idx as usize * FRAME_SIZE as usize) };
                                        let copy_len = (flen as usize).min(FRAME_SIZE as usize);
                                        unsafe { std::ptr::copy_nonoverlapping(frame_data.as_ptr(), dst, copy_len); }
                                        scheduler.enqueue_critical(
                                            (slab_idx as u64) * FRAME_SIZE as u64, flen,
                                        );
                                    }
                                },
                            );
                        }

                        peers.slots[pidx].seq_tx = hs_seq_tx;
                        stats.handshake_ok.value.fetch_add(1, Ordering::Relaxed);
                        eprintln!("[M13-PQC-DRAIN] ServerHello framed for peer {:?}",
                            peers.slots[pidx].addr);
                    }
                    0x03 => {
                        // SessionEstablished: Core 0 completed Finished verification.
                        // Install AEAD cipher.
                        let key = resp.session_key;
                        peers.slots[pidx].session_key = key;
                        let ukey = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &key).unwrap();
                        peers.ciphers[pidx] = Some(ring::aead::LessSafeKey::new(ukey));
                        peers.slots[pidx].frame_count = 0;
                        let rel_s = ((now.saturating_sub(peers.epoch_ns)) / 1_000_000_000) as u32;
                        peers.slots[pidx].established_rel_s = rel_s;
                        peers.slots[pidx].lifecycle = PeerLifecycle::Established;
                        peers.hs_sidecar[pidx] = None;
                        stats.handshake_ok.value.fetch_add(1, Ordering::Relaxed);
                        eprintln!("[M13-PQC-DRAIN] SessionEstablished for peer {:?} (AEAD active)",
                            peers.slots[pidx].addr);
                    }
                    _ => {}
                }
            }
        }

        // === STAGE 6: SCHEDULE TX ===
        {
            let tx_counter = TxCounter::new();
            scheduler.schedule(&mut engine.tx_path, &tx_counter, usize::MAX, now);
            stats.tx_count.value.fetch_add(tx_counter.value.load(Ordering::Relaxed), Ordering::Relaxed);
        }
        // Periodic peer table GC + assembler GC
        gc_counter += 1;
        if gc_counter.is_multiple_of(10000) {
            peers.gc(now);
            for asm in peers.assemblers.iter_mut() { asm.gc(now); }
        }
    }

    // === GRACEFUL m13_hub::engine::runtime::SHUTDOWN CLEANUP ===
    while jbuf.head < jbuf.tail {
        let slot = jbuf.head & (JBUF_CAPACITY - 1);
        slab.free((jbuf.entries[slot].addr / FRAME_SIZE as u64) as u32);
        jbuf.head += 1;
    }
    eprintln!("[M13-W{}] Shutdown complete. Slab: {}/{} free. UDP TX:{} RX:{} TUN_R:{} TUN_W:{} AEAD_OK:{} FAIL:{} Peers:{} Up:{}s",
        worker_idx, slab.available(), SLAB_DEPTH, udp_tx_count, udp_rx_count,
        tun_read_count, tun_write_count, aead_ok_count, aead_fail_count, peers.count,
        (rdtsc_ns(&cal) - worker_start_ns) / 1_000_000_000);
}
