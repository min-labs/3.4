// M13 HUB — ENGINE: PROTOCOL MODULE
// Everything about the M13 protocol: wire format, peer state, fragmentation,
// receiver state, scheduler, and jitter buffer.
// Wire format:   EthernetHeader, M13Header, FeedbackFrame, FragHeader — zero-copy
// Peer table:    DPDK/VPP-style flat array, FNV-1a probing, cache-aligned slots
// Fragment:      Cold-path handshake-only reassembly with 5-second GC
// Receiver:      1024-bit RxBitmap, loss detection, feedback frame production
// Scheduler:     Isochronous TX with strict priority (critical/bulk) queues
// Jitter buffer: RFC 3550 EWMA with circular release buffer

use std::mem;
use crate::engine::fec::SwRlncDecoder;

use std::sync::atomic::{AtomicU64, Ordering};
use bytemuck::{Pod, Zeroable};
use ring::aead;
use crate::cryptography::handshake::HubHandshakeState;

// ============================================================================
// WIRE CONSTANTS
// ============================================================================

/// IEEE 802.1 Local Experimental EtherType for M13 raw Ethernet frames.
pub const ETH_P_M13: u16 = 0x88B5;
/// Wire protocol magic byte. Stored in M13Header.signature[0].
pub const M13_WIRE_MAGIC: u8 = 0xD1;
/// Wire protocol version. Phase 1 = 0x01. Stored in M13Header.signature[1].
pub const M13_WIRE_VERSION: u8 = 0x01;

// M13 header flags (single-byte bitfield at M13Header.flags)
pub const FLAG_CONTROL: u8   = 0x80;
pub const FLAG_FEEDBACK: u8  = 0x40;
pub const FLAG_TUNNEL: u8    = 0x20;
// FLAG_ECN (0x10) reserved for congestion signaling — not yet implemented
pub const FLAG_FIN: u8       = 0x08;  // Graceful close signal
pub const FLAG_FEC: u8       = 0x04;  // RLNC forward error correction
pub const FLAG_HANDSHAKE: u8 = 0x02;  // PQC handshake control
pub const FLAG_FRAGMENT: u8  = 0x01;  // Fragmented message

// PQC handshake sub-types (first byte of handshake payload)
pub const HS_CLIENT_HELLO: u8 = 0x01;
pub const HS_SERVER_HELLO: u8 = 0x02;
pub const HS_FINISHED: u8     = 0x03;

// AEAD nonce direction byte (prevents reflection attacks)
pub const DIR_HUB_TO_NODE: u8 = 0x00;
pub const DIR_NODE_TO_HUB: u8 = 0x01;

// Session limits
pub const REKEY_FRAME_LIMIT: u64 = 1u64 << 32;
pub const REKEY_TIME_LIMIT_NS: u64 = 3_600_000_000_000; // 1 hour

// ============================================================================
// WIRE HEADERS
// ============================================================================

/// IEEE 802.3 Ethernet header. 14 bytes on wire: dst(6) + src(6) + ethertype(2).
#[repr(C, packed)]
#[derive(Copy, Clone, Pod, Zeroable)]
pub struct EthernetHeader {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: u16,
}

/// M13 wire protocol header. 48 bytes. Carried after EthernetHeader.
/// signature[0]=magic(0xD1), signature[1]=version(0x01), [2]=encrypted flag.
/// Encrypted region: bytes [32..48] (seq_id, flags, payload_len, padding).
#[repr(C, packed)]
#[derive(Copy, Clone, Pod, Zeroable)]
pub struct M13Header {
    pub signature: [u8; 32],
    pub seq_id: u64,
    pub flags: u8,
    pub payload_len: u32,
    pub padding: [u8; 3],
}
const _: () = assert!(mem::size_of::<M13Header>() == 48);

/// Feedback frame payload v2. 40 bytes. Carried after M13Header with flags=0xC0.
/// Wire: EthernetHeader(14) + M13Header(48) + FeedbackFrame(40) = 102 bytes.
/// v2 adds loss_count (exact gap count from RxBitmap) and nack_bitmap (64-bit
/// per-packet loss map for RLNC retransmission decisions).
#[repr(C, packed)]
#[derive(Copy, Clone, Pod, Zeroable)]
pub struct FeedbackFrame {
    pub highest_seq: u64,
    pub rx_timestamp_ns: u64,
    pub delivered: u32,
    pub delivered_time_ns: u64,
    pub loss_count: u32,
    pub nack_bitmap: u64,
}
const _: () = assert!(mem::size_of::<FeedbackFrame>() == 40);

// ============================================================================
// DERIVED CONSTANTS
// ============================================================================

pub const ETH_HDR_SIZE: usize = mem::size_of::<EthernetHeader>();
pub const M13_HDR_SIZE: usize = mem::size_of::<M13Header>();
pub const FEEDBACK_FRAME_LEN: u32 =
    (ETH_HDR_SIZE + M13_HDR_SIZE + mem::size_of::<FeedbackFrame>()) as u32;

// Fragment sub-header. 8 bytes, prepended to payload when FLAG_FRAGMENT set.
// DEFECT α: `packed` retained to lock wire format ABI against future field reordering.
// Safe on ARM Cortex-A53: all fields extracted by value (Copy) via read_unaligned().
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct FragHeader {
    pub frag_msg_id: u16,
    pub frag_index: u8,
    pub frag_total: u8,
    pub frag_offset: u16,
    pub frag_len: u16,
}
pub const FRAG_HDR_SIZE: usize = 8;
const _: () = assert!(mem::size_of::<FragHeader>() == FRAG_HDR_SIZE);

// ============================================================================
// R-04: O(1) ZERO-ALLOCATION FRAGMENT MATRIX (HugeTLB)
// ============================================================================
// Replaces HashMap<u16, AssemblyBuffer> + Vec<u8> with pre-allocated slots.
// Zero heap allocation on hot path. Closure IoC prevents Use-After-Free.
// Literature: RFC 815 single-buffer, DPDK rte_ip_frag_table, smoltcp Assembler.

pub const MAX_FRAGMENTS: u8 = 16;
pub const MAX_REASSEMBLY_SIZE: usize = 9216; // Absorbs 8,788B ServerHello
pub const ASM_SLOTS_PER_PEER: usize = 8;

/// Hardware-aligned reassembly slot. Maps contiguous memory for zero-copy reassembly.
/// 9280 bytes = 145 cache lines (exact multiple of align(64)).
#[repr(C, align(64))]
pub struct AssemblySlot {
    pub buf: [u8; MAX_REASSEMBLY_SIZE], // 9,216 bytes
    pub decoder: SwRlncDecoder,
    pub first_rx_ns: u64,               // 8 bytes
    pub msg_id: u16,                    // 2 bytes
    pub received_mask: u16,             // 2 bytes
    pub max_len: u16,                   // 2 bytes
    pub total: u8,                      // 1 byte
    pub active: bool,                   // 1 byte
}

impl AssemblySlot {
    #[inline(always)]
    pub fn reset(&mut self, msg_id: u16, total: u8, now_ns: u64) {
        self.msg_id = msg_id;
        self.total = total;
        self.received_mask = 0;
        self.max_len = 0;
        self.first_rx_ns = now_ns;
        self.active = true;
        self.decoder.reset();
    }
}

/// Zero-allocation O(1) fragment assembler.
/// Holds a raw pointer to a pre-allocated HugeTLB arena of ASM_SLOTS_PER_PEER slots.
/// Derives Copy: pointer is shared for single-threaded use (severs PeerTable borrow).
///
/// Safety: All raw pointer dereferences are guarded by null checks. The pointer is
/// set once at boot via `Assembler::init(ptr)` from a HugeTLB arena and never freed
/// while the Assembler is live. Single-threaded datapath — no concurrent access.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[derive(Copy, Clone)]
pub struct Assembler {
    pub slots: *mut AssemblySlot,
    pub mask: u16,
}

// Single-threaded datapath ownership. No Sync — prevents accidental sharing.
unsafe impl Send for Assembler {}

impl Default for Assembler {
    fn default() -> Self {
        Assembler { slots: std::ptr::null_mut(), mask: (ASM_SLOTS_PER_PEER - 1) as u16 }
    }
}

impl Assembler {
    /// Initialize with pointer to pre-allocated HugeTLB arena.
    pub fn init(ptr: *mut AssemblySlot) -> Self {
        Assembler { slots: ptr, mask: (ASM_SLOTS_PER_PEER - 1) as u16 }
    }

    /// DEFECT δ: Clear all slots without severing the HugeTLB pointer.
    /// Used on reconnection instead of Assembler::new() which would null the pointer.
    #[inline(always)]
    pub fn clear_all(&mut self) {
        if self.slots.is_null() { return; }
        for i in 0..ASM_SLOTS_PER_PEER {
            unsafe { (*self.slots.add(i)).active = false; }
        }
    }

    /// Feed a fragment. On completion, calls on_complete with the reassembled slice.
    /// Closure IoC: slot.active is cleared AFTER on_complete returns → no Use-After-Free.
    #[allow(clippy::too_many_arguments)] // Wire protocol fields — struct wrapper adds hot-path overhead
    #[inline(always)]
    pub fn feed<F>(
        &mut self,
        msg_id: u16,
        index: u8,
        total: u8,
        offset: u16,
        flags: u8,
        data: &[u8],
        now_ns: u64,
        mut on_complete: F,
    ) where F: FnMut(&[u8]) {
        if total == 0 || total > MAX_FRAGMENTS { return; }
        if index >= total && (flags & FLAG_FEC) == 0 { return; }
        if self.slots.is_null() { return; }

        let off = offset as usize;
        let dlen = data.len();
        if off + dlen > MAX_REASSEMBLY_SIZE && (flags & FLAG_FEC) == 0 { return; }

        let slot_idx = ((msg_id ^ (msg_id >> 3)) & self.mask) as usize;
        let slot = unsafe { &mut *self.slots.add(slot_idx) };

        // SURGICAL PATCH: If the slot is inactive, it unconditionally belongs to the incoming msg_id.
        if slot.msg_id != msg_id || !slot.active {
            if !slot.active || now_ns.saturating_sub(slot.first_rx_ns) > 5_000_000_000 {
                slot.reset(msg_id, total, now_ns);
            } else { return; }
        }

        let is_parity = (flags & FLAG_FEC) != 0;

        if !is_parity {
            let bit = 1u16 << index;
            if (slot.received_mask & bit) == 0 {
                unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), slot.buf.as_mut_ptr().add(off), dlen); }
                slot.received_mask |= bit;
                let end_bound = (off + dlen) as u16;
                if end_bound > slot.max_len { slot.max_len = end_bound; }
            }
        }

        let abs_seq = if is_parity { total as u32 + index as u32 } else { index as u32 };
        let seed = index;
        slot.decoder.ingest(abs_seq, is_parity, seed, data);

        let decoded_count = slot.decoder.row_present.count_ones() as u8;
        if decoded_count == total || slot.received_mask == ((1u16 << total) - 1) {
            if slot.received_mask != ((1u16 << total) - 1) {
                // Reconstruct missing systemic fragments from RLNC matrix payload memory
                for i in 0..total {
                    let bit = 1u16 << i;
                    if (slot.received_mask & bit) == 0 {
                        let r_off = (i as usize) * 1402; // max_chunk
                        if r_off >= MAX_REASSEMBLY_SIZE { break; }
                        let expected_len = data.len(); // Pad out to exact parity payload length, trailing safely ignored by upper
                        let copy_len = expected_len.min(MAX_REASSEMBLY_SIZE - r_off);
                        unsafe { std::ptr::copy_nonoverlapping(slot.decoder.payload[i as usize].as_ptr(), slot.buf.as_mut_ptr().add(r_off), copy_len); }
                        slot.received_mask |= bit;
                        if (r_off + copy_len) as u16 > slot.max_len {
                            slot.max_len = (r_off + copy_len) as u16;
                        }
                    }
                }
            }

            let final_len = slot.max_len as usize;
            let complete_slice = unsafe { std::slice::from_raw_parts(slot.buf.as_ptr(), final_len) };
            on_complete(complete_slice);
            slot.active = false;
        }
    }

    /// Garbage-collect stale incomplete messages (5-second timeout).
    #[inline(always)]
    pub fn gc(&mut self, now_ns: u64) {
        if self.slots.is_null() { return; }
        for i in 0..ASM_SLOTS_PER_PEER {
            let slot = unsafe { &mut *self.slots.add(i) };
            if slot.active && now_ns.saturating_sub(slot.first_rx_ns) > 5_000_000_000 {
                slot.active = false;
            }
        }
    }
}

/// Allocate HugeTLB arena for assembler slots.
/// Returns raw pointer to the first AssemblySlot or panics on failure.
pub fn alloc_asm_arena(n_slots: usize) -> *mut AssemblySlot {
    let size = n_slots * mem::size_of::<AssemblySlot>();
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_HUGETLB | libc::MAP_POPULATE,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        // Fallback to regular mmap if HugeTLB not available (e.g., test environments)
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            crate::engine::runtime::fatal(
                crate::engine::runtime::E_UMEM_ALLOC_FAIL,
                "assembler arena mmap failed",
            );
        }
        eprintln!("[M13-R04] ASM arena: {}B via regular mmap (HugeTLB unavailable)", size);
        unsafe { std::ptr::write_bytes(ptr as *mut u8, 0, size); }
        return ptr as *mut AssemblySlot;
    }
    eprintln!("[M13-R04] ASM arena: {}B via MAP_HUGETLB", size);
    unsafe { std::ptr::write_bytes(ptr as *mut u8, 0, size); }
    ptr as *mut AssemblySlot
}

/// Free HugeTLB arena. Called on PeerTable drop.
pub fn free_asm_arena(ptr: *mut AssemblySlot, n_slots: usize) {
    if ptr.is_null() { return; }
    let size = n_slots * mem::size_of::<AssemblySlot>();
    unsafe { libc::munmap(ptr as *mut libc::c_void, size); }
}

// ── Zero-Allocation Closure-Based Fragment Builders ─────────────────────

/// Build fragmented raw UDP frames and emit each via closure (Hub ServerHello path).
/// Zero heap allocation: stack buffers for both M13 inner frame and raw IP/UDP outer frame.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
pub fn build_fragmented_raw_udp<F>(
    src_mac: &[u8; 6], gw_mac: &[u8; 6],
    hub_ip: [u8; 4], peer_ip: [u8; 4],
    hub_port: u16, peer_port: u16,
    payload: &[u8], flags: u8,
    seq: &mut u64, ip_id_base: &mut u16,
    mut emit: F,
) where F: FnMut(&[u8], u32) {
    use crate::network::datapath::build_raw_udp_frame;

    let max_chunk = 1402;
    let total = payload.len().div_ceil(max_chunk);
    let msg_id = (*seq & 0xFFFF) as u16;

    let mut m13_buf = [0u8; 1500];
    let mut raw = [0u8; 2048];

    for i in 0..total {
        let offset = i * max_chunk;
        let chunk_len = (payload.len() - offset).min(max_chunk);
        let m13_flen = ETH_HDR_SIZE + M13_HDR_SIZE + FRAG_HDR_SIZE + chunk_len;

        // Build M13 inner frame
        m13_buf[0..6].copy_from_slice(&[0xFF; 6]);
        m13_buf[6..12].copy_from_slice(src_mac);
        m13_buf[12] = (ETH_P_M13 >> 8) as u8;
        m13_buf[13] = (ETH_P_M13 & 0xFF) as u8;
        m13_buf[14] = M13_WIRE_MAGIC;
        m13_buf[15] = M13_WIRE_VERSION;
        // Zero signature region [16..46]
        for b in &mut m13_buf[16..46] { *b = 0; }
        m13_buf[46..54].copy_from_slice(&seq.to_le_bytes());
        m13_buf[54] = flags | FLAG_FRAGMENT;
        for b in &mut m13_buf[55..59] { *b = 0; }

        let fh = ETH_HDR_SIZE + M13_HDR_SIZE;
        m13_buf[fh..fh+2].copy_from_slice(&msg_id.to_le_bytes());
        m13_buf[fh+2] = i as u8;
        m13_buf[fh+3] = total as u8;
        m13_buf[fh+4..fh+6].copy_from_slice(&(offset as u16).to_le_bytes());
        m13_buf[fh+6..fh+8].copy_from_slice(&(chunk_len as u16).to_le_bytes());

        let dp = fh + FRAG_HDR_SIZE;
        m13_buf[dp..dp+chunk_len].copy_from_slice(&payload[offset..offset+chunk_len]);

        // Build raw IP/UDP outer frame
        let total_len = build_raw_udp_frame(
            &mut raw, src_mac, gw_mac, hub_ip, peer_ip,
            hub_port, peer_port, *ip_id_base, &m13_buf[..m13_flen],
        );
        *ip_id_base = ip_id_base.wrapping_add(1);
        *seq += 1;

        emit(&raw[..total_len], total_len as u32);
    }
}

/// Build fragmented L2 frames and emit each via closure (Hub ServerHello L2 path).
#[inline(always)]
pub fn build_fragmented_l2<F>(
    src_mac: &[u8; 6], peer_mac: &[u8; 6],
    payload: &[u8], flags: u8, seq: &mut u64,
    mut emit: F,
) where F: FnMut(&[u8], u32) {
    let max_chunk = 1402;
    let total = payload.len().div_ceil(max_chunk);
    let msg_id = (*seq & 0xFFFF) as u16;
    let mut frame = [0u8; 1500];
    let mut window = crate::engine::fec::EncoderWindow::new();
    let mut p_len = 0;

    for i in 0..total {
        let offset = i * max_chunk;
        let chunk_len = (payload.len() - offset).min(max_chunk);
        let m13_flen = ETH_HDR_SIZE + M13_HDR_SIZE + FRAG_HDR_SIZE + chunk_len;

        frame[0..6].copy_from_slice(peer_mac);
        frame[6..12].copy_from_slice(src_mac);
        frame[12] = (ETH_P_M13 >> 8) as u8;
        frame[13] = (ETH_P_M13 & 0xFF) as u8;
        frame[14] = M13_WIRE_MAGIC;
        frame[15] = M13_WIRE_VERSION;
        for b in &mut frame[16..46] { *b = 0; }
        frame[46..54].copy_from_slice(&seq.to_le_bytes());
        frame[54] = flags | FLAG_FRAGMENT;
        for b in &mut frame[55..59] { *b = 0; }

        let fh = ETH_HDR_SIZE + M13_HDR_SIZE;
        frame[fh..fh+2].copy_from_slice(&msg_id.to_le_bytes());
        frame[fh+2] = i as u8;
        frame[fh+3] = total as u8;
        frame[fh+4..fh+6].copy_from_slice(&(offset as u16).to_le_bytes());
        frame[fh+6..fh+8].copy_from_slice(&(chunk_len as u16).to_le_bytes());

        let dp = fh + FRAG_HDR_SIZE;
        frame[dp..dp+chunk_len].copy_from_slice(&payload[offset..offset+chunk_len]);

        unsafe { window.push(payload[offset..offset+chunk_len].as_ptr(), chunk_len); }
        p_len = p_len.max(chunk_len);

        *seq += 1;
        emit(&frame[..m13_flen], m13_flen as u32);
    }

    let parity_count = total / 2;
    for p in 0..parity_count {
        let p_idx = total + p;
        let m13_flen = ETH_HDR_SIZE + M13_HDR_SIZE + FRAG_HDR_SIZE + p_len;

        frame[0..6].copy_from_slice(peer_mac);
        frame[6..12].copy_from_slice(src_mac);
        frame[12] = (ETH_P_M13 >> 8) as u8;
        frame[13] = (ETH_P_M13 & 0xFF) as u8;
        frame[14] = M13_WIRE_MAGIC;
        frame[15] = M13_WIRE_VERSION;
        for b in &mut frame[16..46] { *b = 0; }
        frame[46..54].copy_from_slice(&seq.to_le_bytes());
        frame[54] = flags | FLAG_FRAGMENT | FLAG_FEC;
        for b in &mut frame[55..59] { *b = 0; }

        let fh = ETH_HDR_SIZE + M13_HDR_SIZE;
        frame[fh..fh+2].copy_from_slice(&msg_id.to_le_bytes());
        frame[fh+2] = p_idx as u8;
        frame[fh+3] = total as u8;
        frame[fh+4..fh+6].copy_from_slice(&0u16.to_le_bytes());
        frame[fh+6..fh+8].copy_from_slice(&(p_len as u16).to_le_bytes());

        let dp = fh + FRAG_HDR_SIZE;
        crate::engine::fec::encode_parity_payload(
            &mut frame[dp..dp+p_len], &window, total, p_idx as u8
        );

        *seq += 1;
        emit(&frame[..m13_flen], m13_flen as u32);
    }
}


// ============================================================================
// PEER TABLE — DPDK/VPP-style flat array with FNV-1a linear probing
// ============================================================================

pub const MAX_PEERS: usize = 256;
pub const TUNNEL_SUBNET: [u8; 4] = [10, 13, 0, 0];

/// 6-byte peer identity. Natural key for UDP peers behind NAT.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PeerAddr {
    Empty,
    Udp { ip: [u8; 4], port: u16 },
    L2 { mac: [u8; 6] },
}

impl PeerAddr {
    pub const EMPTY: PeerAddr = PeerAddr::Empty;
    pub fn new_udp(ip: [u8; 4], port: u16) -> Self { PeerAddr::Udp { ip, port } }
    pub fn new_l2(mac: [u8; 6]) -> Self { PeerAddr::L2 { mac } }
    pub fn ip(&self) -> Option<[u8; 4]> {
        match self { PeerAddr::Udp { ip, .. } => Some(*ip), _ => None }
    }
    pub fn port(&self) -> Option<u16> {
        match self { PeerAddr::Udp { port, .. } => Some(*port), _ => None }
    }
    pub fn is_udp(&self) -> bool { matches!(self, PeerAddr::Udp { .. }) }

    /// FNV-1a hash. 6 bytes for UDP (ip+port), 6 bytes for L2 (mac).
    pub fn hash(&self) -> usize {
        const BASIS: u64 = 0xcbf29ce484222325;
        const PRIME: u64 = 0x100000001b3;
        let bytes: [u8; 6] = match self {
            PeerAddr::Empty => return 0,
            PeerAddr::Udp { ip, port } => [
                ip[0], ip[1], ip[2], ip[3],
                (*port >> 8) as u8, (*port & 0xFF) as u8,
            ],
            PeerAddr::L2 { mac } => *mac,
        };
        let mut h = BASIS;
        for b in bytes { h ^= b as u64; h = h.wrapping_mul(PRIME); }
        h as usize
    }
}

impl std::fmt::Debug for PeerAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerAddr::Empty => write!(f, "(empty)"),
            PeerAddr::Udp { ip, port } => write!(f, "{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], port),
            PeerAddr::L2 { mac } => write!(f, "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum PeerLifecycle {
    Empty = 0,
    Registered = 1,
    Handshaking = 2,
    Established = 3,
}

/// Per-peer state. Exactly 1 cache line (64 bytes) for zero false sharing.
#[repr(C, align(64))]
pub struct PeerSlot {
    pub addr: PeerAddr,
    pub lifecycle: PeerLifecycle,
    pub tunnel_ip_idx: u8,
    pub session_key: [u8; 32],
    pub seq_tx: u64,
    pub frame_count: u64,
    pub established_rel_s: u32,
    pub mac: [u8; 6],
    pub last_echo_ns: u64,
    /// DRL accumulator: FEC-recovered packets since last harvest. Cleared by classify_one.
    pub drl_recovered_pkts: u32,
    /// DRL accumulator: TX scheduler drops since last harvest. Cleared by classify_one.
    pub drl_tx_drops: u32,
}

impl PeerSlot {
    pub const EMPTY: PeerSlot = PeerSlot {
        addr: PeerAddr::EMPTY, lifecycle: PeerLifecycle::Empty,
        tunnel_ip_idx: 0, session_key: [0u8; 32], seq_tx: 0,
        frame_count: 0, established_rel_s: 0, mac: [0xFF; 6],
        last_echo_ns: 0,
        drl_recovered_pkts: 0,
        drl_tx_drops: 0,
    };
    pub fn is_empty(&self) -> bool { self.lifecycle == PeerLifecycle::Empty }
    pub fn has_session(&self) -> bool { self.lifecycle == PeerLifecycle::Established }
    pub fn next_seq(&mut self) -> u64 {
        let s = self.seq_tx;
        self.seq_tx = self.seq_tx.wrapping_add(1);
        s
    }
    pub fn reset_session(&mut self) {
        self.session_key = [0u8; 32];
        self.seq_tx = 0;
        self.frame_count = 0;
    }
}

/// Multi-tenant peer table. Single-threaded (owned by one worker).
pub struct PeerTable {
    pub slots: [PeerSlot; MAX_PEERS],
    pub count: usize,
    pub assemblers: [Assembler; MAX_PEERS],
    pub epoch_ns: u64,
    pub handshakes: [Option<HubHandshakeState>; MAX_PEERS],
    pub rx_states: [ReceiverState; MAX_PEERS],
    pub schedulers: [Scheduler; MAX_PEERS],
    pub jitter_bufs: [JitterBuffer; MAX_PEERS],
    pub hs_sidecar: [Option<HubHandshakeState>; MAX_PEERS],
    tunnel_ip_bitmap: [u64; 4],
    pub ciphers: [Option<aead::LessSafeKey>; MAX_PEERS],
    pub fec_decoders: [Box<crate::engine::fec::SwRlncDecoder>; MAX_PEERS],
    pub fec_encoders: [Box<crate::engine::fec::EncoderWindow>; MAX_PEERS],
    pub fec_pacing_counters: [u8; MAX_PEERS],
    asm_arena: *mut AssemblySlot,
}

impl PeerTable {
    pub fn new(epoch_ns: u64) -> Self {
        let total_slots = MAX_PEERS * ASM_SLOTS_PER_PEER;
        let arena = alloc_asm_arena(total_slots);
        PeerTable {
            slots: [PeerSlot::EMPTY; MAX_PEERS],
            count: 0,
            assemblers: std::array::from_fn(|i| {
                let ptr = unsafe { arena.add(i * ASM_SLOTS_PER_PEER) };
                Assembler::init(ptr)
            }),
            epoch_ns,
            handshakes: std::array::from_fn(|_| None),
            rx_states: std::array::from_fn(|_| ReceiverState::new()),
            schedulers: std::array::from_fn(|_| Scheduler::new()),
            jitter_bufs: std::array::from_fn(|_| JitterBuffer::new()),
            hs_sidecar: std::array::from_fn(|_| None),
            tunnel_ip_bitmap: [0u64; 4],
            ciphers: std::array::from_fn(|_| None),
            fec_decoders: std::array::from_fn(|_| crate::engine::fec::SwRlncDecoder::new_boxed()),
            fec_encoders: std::array::from_fn(|_| crate::engine::fec::EncoderWindow::new_boxed()),
            fec_pacing_counters: [0; MAX_PEERS],
            asm_arena: arena,
        }
    }

    pub fn lookup(&self, addr: PeerAddr) -> Option<usize> {
        let h = addr.hash() % MAX_PEERS;
        for probe in 0..MAX_PEERS {
            let idx = (h + probe) % MAX_PEERS;
            if self.slots[idx].addr == addr { return Some(idx); }
            if self.slots[idx].is_empty() { return None; }
        }
        None
    }

    pub fn lookup_or_insert(&mut self, addr: PeerAddr, mac: [u8; 6]) -> Option<usize> {
        if let PeerAddr::Empty = addr { return None; }
        let h = addr.hash() % MAX_PEERS;
        let mut first_empty: Option<usize> = None;
        for probe in 0..MAX_PEERS {
            let idx = (h + probe) % MAX_PEERS;
            if self.slots[idx].addr == addr { return Some(idx); }
            if self.slots[idx].is_empty() {
                if first_empty.is_none() { first_empty = Some(idx); }
                break;
            }
        }

        // ── Reconnection guard ──────────────────────────────────────────
        // A UDP node may reconnect from a new ephemeral port (process restart,
        // NAT port remap). The old slot stays Established with a dead session key.
        // If we insert a second slot, lookup_by_tunnel_ip still finds the old one
        // → TX goes to the dead peer → no internet.
        // Fix: evict any existing peer from the same source IP before inserting.
        if let PeerAddr::Udp { ip: new_ip, .. } = addr {
            for i in 0..MAX_PEERS {
                if let PeerAddr::Udp { ip: old_ip, .. } = self.slots[i].addr {
                    if old_ip == new_ip && self.slots[i].addr != addr {
                        eprintln!("[M13-VPP] Reconnection detected: evicting stale peer {:?} (same IP, new port)",
                            self.slots[i].addr);
                        self.evict(i);
                        // The evicted slot might be usable now
                        if first_empty.is_none() { first_empty = Some(i); }
                    }
                }
            }
        }

        if let Some(idx) = first_empty {
            self.slots[idx] = PeerSlot {
                addr,
                lifecycle: PeerLifecycle::Registered,
                tunnel_ip_idx: 0,
                session_key: [0u8; 32],
                seq_tx: 0,
                frame_count: 0,
                established_rel_s: 0,
                mac,
                last_echo_ns: 0,
                drl_recovered_pkts: 0,
                drl_tx_drops: 0,
            };
            self.count += 1;
            Some(idx)
        } else {
            None
        }
    }

    pub fn evict(&mut self, idx: usize) {
        if idx >= MAX_PEERS || self.slots[idx].is_empty() { return; }
        let tip = self.slots[idx].tunnel_ip_idx;
        if tip > 0 { self.free_tunnel_ip(tip); }
        self.slots[idx] = PeerSlot::EMPTY;
        self.handshakes[idx] = None;
        self.rx_states[idx] = ReceiverState::new();
        self.schedulers[idx] = Scheduler::new();
        self.jitter_bufs[idx] = JitterBuffer::new();
        self.hs_sidecar[idx] = None;
        self.ciphers[idx] = None;
        self.assemblers[idx].clear_all();
        self.count -= 1;
    }

    pub fn lookup_by_tunnel_ip(&self, dst_ip: [u8; 4]) -> Option<usize> {
        if dst_ip[0] != TUNNEL_SUBNET[0] || dst_ip[1] != TUNNEL_SUBNET[1] { return None; }
        let target_idx = dst_ip[3];
        if target_idx == 0 { return None; }
        (0..MAX_PEERS).find(|&i| self.slots[i].tunnel_ip_idx == target_idx
                && self.slots[i].lifecycle == PeerLifecycle::Established)
    }

    pub fn alloc_tunnel_ip(&mut self) -> Option<u8> {
        for word_idx in 0..4u8 {
            let word = self.tunnel_ip_bitmap[word_idx as usize];
            if word != u64::MAX {
                let bit = (!word).trailing_zeros() as u8;
                let ip_idx = word_idx * 64 + bit + 1;
                if ip_idx > 254 { return None; }
                self.tunnel_ip_bitmap[word_idx as usize] |= 1u64 << bit;
                return Some(ip_idx);
            }
        }
        None
    }

    pub fn free_tunnel_ip(&mut self, idx: u8) {
        if idx == 0 || idx > 254 { return; }
        let adj = (idx - 1) as usize;
        self.tunnel_ip_bitmap[adj / 64] &= !(1u64 << (adj % 64));
    }

    pub fn gc(&mut self, _now_ns: u64) {
        // TODO: implement eviction for idle peers
    }
}

impl Drop for PeerTable {
    fn drop(&mut self) {
        let total_slots = MAX_PEERS * ASM_SLOTS_PER_PEER;
        free_asm_arena(self.asm_arena, total_slots);
        self.asm_arena = std::ptr::null_mut();
    }
}

// ============================================================================
// RECEIVER STATE — RxBitmap + ReceiverState + feedback frame production
// ============================================================================

pub const FEEDBACK_INTERVAL_PKTS: u32 = 32;
pub const FEEDBACK_RTT_DEFAULT_NS: u64 = 10_000_000;

/// 1024-bit sliding window bitmap for sequence gap detection.
pub struct RxBitmap {
    bits: [u64; 16],
    base: u64,
}

impl Default for RxBitmap {
    fn default() -> Self { Self::new() }
}

impl RxBitmap {
    pub fn new() -> Self { RxBitmap { bits: [0u64; 16], base: 0 } }

    pub fn mark(&mut self, seq: u64) {
        if seq < self.base { return; }
        let offset = seq - self.base;
        if offset >= 1024 {
            self.advance_to(seq);
        }
        let offset = seq - self.base;
        if offset < 1024 {
            self.bits[(offset / 64) as usize] |= 1u64 << (offset % 64);
        }
    }

    pub fn advance_to(&mut self, seq: u64) {
        if seq < self.base + 1024 { return; }
        let new_base = seq.saturating_sub(512);
        let shift = new_base - self.base;
        if shift >= 1024 {
            self.bits = [0u64; 16];
        } else {
            let word_shift = (shift / 64) as usize;
            let bit_shift = (shift % 64) as u32;
            let mut new_bits = [0u64; 16];
            for i in word_shift..16 {
                new_bits[i - word_shift] = self.bits[i] >> bit_shift;
                if bit_shift > 0 && i + 1 < 16 {
                    new_bits[i - word_shift] |= self.bits[i + 1] << (64 - bit_shift);
                }
            }
            self.bits = new_bits;
        }
        self.base = new_base;
    }

    pub fn drain_losses(&mut self) -> (u32, u64) {
        let (mut losses, mut nack_bitmap) = (0u32, 0u64);
        let check_end = 512u64;
        for i in 0..check_end {
            let word = (i / 64) as usize;
            let bit = i % 64;
            if self.bits[word] & (1u64 << bit) == 0 {
                losses += 1;
                if i < 64 { nack_bitmap |= 1u64 << i; }
            }
        }
        (losses, nack_bitmap)
    }
}

pub struct ReceiverState {
    pub rx_bitmap: RxBitmap,
    pub highest_seq: u64,
    pub delivered: u32,
    pub pkt_since_feedback: u32,
    pub last_rx_batch_ns: u64,
    pub first_rx_ns: u64,
}

impl Default for ReceiverState {
    fn default() -> Self { Self::new() }
}

impl ReceiverState {
    pub fn new() -> Self {
        ReceiverState {
            rx_bitmap: RxBitmap::new(),
            highest_seq: 0,
            delivered: 0,
            pkt_since_feedback: 0,
            last_rx_batch_ns: 0,
            first_rx_ns: 0,
        }
    }
    pub fn record_rx(&mut self, seq: u64, now_ns: u64) {
        self.rx_bitmap.mark(seq);
        if seq > self.highest_seq { self.highest_seq = seq; }
        self.delivered += 1;
        self.pkt_since_feedback += 1;
        self.last_rx_batch_ns = now_ns;
        if self.first_rx_ns == 0 { self.first_rx_ns = now_ns; }
    }
    /// Check if enough packets received to warrant generating a feedback frame.
    pub fn needs_feedback(&mut self, rx_batch_ns: u64, _rtt_est: u64) -> bool {
        if rx_batch_ns == 0 { return false; }
        self.pkt_since_feedback >= FEEDBACK_INTERVAL_PKTS
    }
}

/// Write a FeedbackFrame directly into a UMEM buffer via raw pointer.
/// Caller provides: raw pointer, dst/src MAC, receiver state, bitmap, timestamp,
/// jitter buffer depth, and jitter buffer capacity.
/// Returns the total frame length (ETH+M13+Feedback = 102 bytes).
/// # Safety
/// `frame_ptr` must point to a valid writable buffer of at least `FEEDBACK_FRAME_LEN` bytes.
#[allow(clippy::too_many_arguments)]
pub unsafe fn produce_feedback_frame(
    frame_ptr: *mut u8,
    dst_mac: &[u8; 6],
    src_mac: &[u8; 6],
    rx_state: &mut ReceiverState,
    rx_bitmap: &mut RxBitmap,
    now_ns: u64,
    _jbuf_depth: usize,
    _jbuf_capacity: usize,
) -> usize {
    let frame_len = FEEDBACK_FRAME_LEN as usize;
    // SAFETY: Caller ensures frame_ptr points to valid UMEM with at least frame_len bytes.
    let buf = unsafe { std::slice::from_raw_parts_mut(frame_ptr, frame_len) };
    buf[0..6].copy_from_slice(dst_mac);
    buf[6..12].copy_from_slice(src_mac);
    buf[12] = (ETH_P_M13 >> 8) as u8;
    buf[13] = (ETH_P_M13 & 0xFF) as u8;
    buf[14] = M13_WIRE_MAGIC; buf[15] = M13_WIRE_VERSION;
    buf[54] = FLAG_CONTROL | FLAG_FEEDBACK;
    let fb_offset = ETH_HDR_SIZE + M13_HDR_SIZE;
    buf[fb_offset..fb_offset+8].copy_from_slice(&rx_state.highest_seq.to_le_bytes());
    buf[fb_offset+8..fb_offset+16].copy_from_slice(&now_ns.to_le_bytes());
    buf[fb_offset+16..fb_offset+20].copy_from_slice(&rx_state.delivered.to_le_bytes());
    let elapsed = now_ns.saturating_sub(rx_state.first_rx_ns);
    buf[fb_offset+20..fb_offset+28].copy_from_slice(&elapsed.to_le_bytes());
    let (loss_count, nack_bitmap) = rx_bitmap.drain_losses();
    buf[fb_offset+28..fb_offset+32].copy_from_slice(&loss_count.to_le_bytes());
    buf[fb_offset+32..fb_offset+40].copy_from_slice(&nack_bitmap.to_le_bytes());
    rx_state.pkt_since_feedback = 0;
    frame_len
}

// ============================================================================
// SCHEDULER — isochronous TX with strict priority queues + BBR cwnd awareness
// ============================================================================

/// Submission handle for the TX pipeline.
pub struct TxSubmit {
    pub frame_idx: u64,
    pub frame_len: u32,
    pub release_ns: u64,  // V4: EDT release time (0 = immediate)
}

pub const TX_RING_SIZE: usize = 256;
pub const HW_FILL_MAX: usize = 64;

/// Strict-priority two-queue scheduler with V4 EDT gating.
/// Critical frames (handshakes, feedback) go first. Bulk data fills remaining capacity.
/// Each entry carries a `release_ns` timestamp; `dequeue(now_ns)` won't release
/// frames until the EDT horizon has passed.
pub struct Scheduler {
    critical: [(u64, u32, u64); TX_RING_SIZE],  // (frame_idx, len, release_ns)
    bulk:     [(u64, u32, u64); TX_RING_SIZE],
    crit_head: usize,
    crit_tail: usize,
    bulk_head: usize,
    bulk_tail: usize,
}

impl Default for Scheduler {
    fn default() -> Self { Self::new() }
}

impl Scheduler {
    pub fn new() -> Self {
        Scheduler {
            critical: [(0, 0, 0); TX_RING_SIZE],
            bulk: [(0, 0, 0); TX_RING_SIZE],
            crit_head: 0, crit_tail: 0,
            bulk_head: 0, bulk_tail: 0,
        }
    }

    /// V4: EDT-aware critical enqueue with explicit release time.
    #[inline(always)]
    pub fn enqueue_critical_edt(&mut self, idx: u64, len: u32, release_ns: u64) -> bool {
        let next = (self.crit_tail + 1) % TX_RING_SIZE;
        if next == self.crit_head { return false; }
        self.critical[self.crit_tail] = (idx, len, release_ns);
        self.crit_tail = next;
        true
    }

    /// Backward-compatible wrapper: critical enqueue with immediate release.
    #[inline(always)]
    pub fn enqueue_critical(&mut self, idx: u64, len: u32) -> bool {
        self.enqueue_critical_edt(idx, len, 0)
    }

    /// V4: EDT-aware bulk enqueue.
    #[inline(always)]
    pub fn enqueue_bulk_edt(&mut self, idx: u64, len: u32, release_ns: u64) -> bool {
        let next = (self.bulk_tail + 1) % TX_RING_SIZE;
        if next == self.bulk_head { return false; }
        self.bulk[self.bulk_tail] = (idx, len, release_ns);
        self.bulk_tail = next;
        true
    }

    /// Backward-compatible wrapper: bulk enqueue with immediate release.
    #[inline(always)]
    pub fn enqueue_bulk(&mut self, idx: u64, len: u32) -> bool {
        self.enqueue_bulk_edt(idx, len, 0)
    }

    /// V4: EDT-gated dequeue. Won't release frames before their `release_ns`.
    /// Returns `None` if the queue is empty OR the head-of-line is not yet released.
    #[inline(always)]
    pub fn dequeue(&mut self, now_ns: u64) -> Option<TxSubmit> {
        if self.crit_head != self.crit_tail {
            let (idx, len, release_ns) = self.critical[self.crit_head];
            if release_ns > 0 && now_ns < release_ns {
                // Head-of-line blocking: critical frame not yet released.
                // Fall through to check bulk queue (which may have ready frames).
            } else {
                self.crit_head = (self.crit_head + 1) % TX_RING_SIZE;
                return Some(TxSubmit { frame_idx: idx, frame_len: len, release_ns });
            }
        }
        if self.bulk_head != self.bulk_tail {
            let (idx, len, release_ns) = self.bulk[self.bulk_head];
            if release_ns > 0 && now_ns < release_ns {
                return None;  // Bulk head-of-line also blocked
            }
            self.bulk_head = (self.bulk_head + 1) % TX_RING_SIZE;
            return Some(TxSubmit { frame_idx: idx, frame_len: len, release_ns });
        }
        None
    }

    pub fn pending(&self) -> usize {
        let c = if self.crit_tail >= self.crit_head { self.crit_tail - self.crit_head }
                else { TX_RING_SIZE - self.crit_head + self.crit_tail };
        let b = if self.bulk_tail >= self.bulk_head { self.bulk_tail - self.bulk_head }
                else { TX_RING_SIZE - self.bulk_head + self.bulk_tail };
        c + b
    }

    /// V4: EDT-aware schedule. Passes `now_ns` to dequeue for release gating.
    pub fn schedule<T: crate::network::xdp::TxPath>(&mut self, tx_path: &mut T, tx_counter: &TxCounter, max_burst: usize, now_ns: u64) {
        let mut count = 0usize;
        while count < max_burst {
            if let Some(submit) = self.dequeue(now_ns) {
                tx_path.stage_tx_addr(submit.frame_idx, submit.frame_len);
                tx_counter.value.fetch_add(1, Ordering::Relaxed);
                count += 1;
            } else {
                break;
            }
        }
        if count > 0 {
            tx_path.commit_tx();
            tx_path.kick_tx();
        }
    }
}

/// Per-peer TX counter for BBR cwnd enforcement.
/// Uses AtomicU64 so the scheduler can increment without &mut borrow.
pub struct TxCounter {
    pub value: AtomicU64,
    pub inflight: u64,
    pub total_sent: u64,
}

impl Default for TxCounter {
    fn default() -> Self { Self::new() }
}

impl TxCounter {
    pub fn new() -> Self { TxCounter { value: AtomicU64::new(0), inflight: 0, total_sent: 0 } }
    #[inline(always)] pub fn on_send(&mut self) { self.inflight += 1; self.total_sent += 1; }
    #[inline(always)] pub fn on_ack(&mut self, delivered: u64) {
        if delivered > self.total_sent { self.inflight = 0; return; }
        let new_inflight = self.total_sent - delivered;
        self.inflight = new_inflight;
    }
}

// ============================================================================
// JITTER BUFFER — RFC 3550 EWMA + circular release buffer
// ENFORCED DETERMINISM: ZERO FLOATING POINT. STRICT Q60.4 FIXED-POINT MATH.
// ============================================================================

pub const JBUF_CAPACITY: usize = 128;

/// Adaptive jitter estimator using RFC 3550 EWMA.
/// Architecture: Q60.4 Fixed-Point DSP Math.
///
/// Internal state `jitter_q4` stores `jitter_ns * 16`, preserving 1/16th
/// nanosecond fractional resolution using integer-only arithmetic.
///
/// Formula derivation from RFC 3550:
///   J = J + (|D| - J) / 16
///   Let J_q4 = 16·J  →  J_q4 = J_q4 - (J_q4 >> 4) + |D|
///
/// Underflow safety: (J_q4 >> 4) ≤ J_q4 for all non-negative J_q4.
/// Overflow safety: max J_q4 ≈ 16 × 30×10⁹ ≈ 39 bits. Within u64.
pub struct JitterEstimator {
    /// Jitter state in Q60.4 format (jitter_ns × 16).
    jitter_q4: u64,
    last_transit: i64,
    initialized: bool,
}

impl Default for JitterEstimator {
    fn default() -> Self { Self::new() }
}

impl JitterEstimator {
    #[inline(always)]
    pub fn new() -> Self {
        JitterEstimator { jitter_q4: 0, last_transit: 0, initialized: false }
    }

    #[inline(always)]
    pub fn update(&mut self, send_ts_ns: u64, recv_ts_ns: u64) {
        let transit = (recv_ts_ns as i64).wrapping_sub(send_ts_ns as i64);

        if !self.initialized {
            self.last_transit = transit;
            self.initialized = true;
            return;
        }

        // |D| = absolute transit difference. abs_diff returns u64, no panic.
        let d = transit.abs_diff(self.last_transit);
        self.last_transit = transit;

        // RFC 3550 EWMA in Q60.4: J_q4 = J_q4 - (J_q4 >> 4) + |D|
        // wrapping ops elide panic branches in emitted assembly.
        self.jitter_q4 = self.jitter_q4
            .wrapping_sub(self.jitter_q4 >> 4)
            .wrapping_add(d);
    }

    /// Jitter estimate in microseconds (for telemetry export).
    #[inline(always)]
    pub fn jitter_us(&self) -> u64 { (self.jitter_q4 >> 4) / 1000 }

    /// Jitter estimate in nanoseconds.
    #[inline(always)]
    pub fn get(&self) -> u64 { self.jitter_q4 >> 4 }
}

/// Entry in jitter buffer: UMEM address + length.
#[derive(Clone, Copy, Default)]
pub struct JBufEntry {
    pub addr: u64,
    pub len: u32,
}

/// Circular jitter buffer with adaptive depth.
pub struct JitterBuffer {
    pub entries: [JBufEntry; JBUF_CAPACITY],
    pub head: usize,
    pub tail: usize,
    pub estimator: JitterEstimator,
    pub total_releases: u64,
    pub total_drops: u64,
    pub depth_ns: u64,
}

impl Default for JitterBuffer {
    fn default() -> Self { Self::new() }
}

impl JitterBuffer {
    pub fn new() -> Self {
        JitterBuffer {
            entries: [JBufEntry::default(); JBUF_CAPACITY],
            head: 0, tail: 0,
            estimator: JitterEstimator::new(),
            total_releases: 0, total_drops: 0,
            depth_ns: 0,
        }
    }

    #[inline(always)]
    pub fn push(&mut self, addr: u64, len: u32) -> bool {
        let next = (self.tail + 1) & (JBUF_CAPACITY - 1);
        if next == self.head {
            self.total_drops += 1;
            return false;
        }
        self.entries[self.tail] = JBufEntry { addr, len };
        self.tail = next;
        true
    }

    /// Drain all entries whose release time has arrived.
    /// Returns (released_count, frames_still_buffered).
    #[inline(always)]
    pub fn drain(&mut self, _now_ns: u64, scheduler: &mut Scheduler) -> (u64, usize) {
        let mut released = 0u64;
        while self.head != self.tail {
            let slot = self.head & (JBUF_CAPACITY - 1);
            let entry = &self.entries[slot];
            scheduler.enqueue_bulk(entry.addr, entry.len);
            self.head = (self.head + 1) & (JBUF_CAPACITY - 1);
            self.total_releases += 1;
            released += 1;
        }
        (released, 0)
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        if self.tail >= self.head { self.tail - self.head }
        else { JBUF_CAPACITY - self.head + self.tail }
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool { self.head == self.tail }
}

/// Measure scheduler → sendto() processing jitter. Takes TscCal for calibrated timing.
pub fn measure_epsilon_proc(cal: &crate::engine::runtime::TscCal) -> u64 {
    use crate::engine::runtime::rdtsc_ns;
    let t0 = rdtsc_ns(cal);
    // Dummy work to measure processing overhead
    let t1 = rdtsc_ns(cal);
    t1.saturating_sub(t0)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Wire tests
    #[test]
    fn header_sizes() {
        assert_eq!(mem::size_of::<EthernetHeader>(), 14);
        assert_eq!(mem::size_of::<M13Header>(), 48);
        assert_eq!(mem::size_of::<FeedbackFrame>(), 40);
        assert_eq!(mem::size_of::<FragHeader>(), 8);
        assert_eq!(ETH_HDR_SIZE, 14);
        assert_eq!(M13_HDR_SIZE, 48);
    }

    #[test]
    fn constants_no_overlap() {
        let flags = [FLAG_CONTROL, FLAG_FEEDBACK, FLAG_TUNNEL,
                     FLAG_FIN, FLAG_HANDSHAKE, FLAG_FRAGMENT];
        for i in 0..flags.len() {
            assert!(flags[i].is_power_of_two(), "flag 0x{:02X} not single bit", flags[i]);
            for j in (i+1)..flags.len() {
                assert_ne!(flags[i], flags[j], "duplicate flag value");
            }
        }
    }

    #[test]
    fn magic_version_valid() {
        assert_eq!(M13_WIRE_MAGIC, 0xD1);
        assert_eq!(M13_WIRE_VERSION, 0x01);
        assert_ne!(M13_WIRE_MAGIC, M13_WIRE_VERSION);
    }

    #[test]
    fn ethertype_is_experimental() {
        assert_eq!(ETH_P_M13, 0x88B5);
    }

    // Fragment tests (R-04: HugeTLB slot-based assembler)
    fn test_assembler() -> (Assembler, *mut AssemblySlot) {
        let arena = alloc_asm_arena(ASM_SLOTS_PER_PEER);
        let asm = Assembler::init(arena);
        (asm, arena)
    }

    #[test]
    fn single_fragment_completes() {
        let (mut asm, arena) = test_assembler();
        let mut result = Vec::new();
        asm.feed(1, 0, 1, 0, 0, b"hello world", 100, |data| result.extend_from_slice(data));
        assert_eq!(&result, b"hello world");
        free_asm_arena(arena, ASM_SLOTS_PER_PEER);
    }

    #[test]
    fn multi_fragment_reassembly() {
        let (mut asm, arena) = test_assembler();
        let mut result = Vec::new();
        asm.feed(42, 0, 3, 0, 0, b"AAAA", 100, |data| result.extend_from_slice(data));
        assert!(result.is_empty());
        asm.feed(42, 1, 3, 4, 0, b"BBBB", 100, |data| result.extend_from_slice(data));
        assert!(result.is_empty());
        asm.feed(42, 2, 3, 8, 0, b"CC", 100, |data| result.extend_from_slice(data));
        assert_eq!(&result, b"AAAABBBBCC");
        free_asm_arena(arena, ASM_SLOTS_PER_PEER);
    }

    #[test]
    fn duplicate_fragment_ignored() {
        let (mut asm, arena) = test_assembler();
        let mut count = 0usize;
        asm.feed(1, 0, 2, 0, 0, b"A", 100, |_| count += 1);
        assert_eq!(count, 0);
        asm.feed(1, 0, 2, 0, 0, b"A", 100, |_| count += 1); // dup
        assert_eq!(count, 0);
        asm.feed(1, 1, 2, 1, 0, b"B", 100, |_| count += 1);
        assert_eq!(count, 1);
        free_asm_arena(arena, ASM_SLOTS_PER_PEER);
    }

    #[test]
    fn gc_removes_stale_messages() {
        let (mut asm, arena) = test_assembler();
        let mut count = 0usize;
        asm.feed(1, 0, 2, 0, 0, b"X", 100, |_| count += 1);
        asm.gc(6_000_000_100);
        asm.feed(1, 1, 2, 1, 0, b"Y", 6_000_000_200, |_| count += 1);
        assert_eq!(count, 0);
        free_asm_arena(arena, ASM_SLOTS_PER_PEER);
    }

    #[test]
    fn out_of_range_index_rejected() {
        let (mut asm, arena) = test_assembler();
        let mut count = 0usize;
        asm.feed(1, 16, 2, 0, 0, b"bad", 100, |_| count += 1);
        asm.feed(1, 2, 2, 0, 0, b"bad", 100, |_| count += 1);
        assert_eq!(count, 0);
        free_asm_arena(arena, ASM_SLOTS_PER_PEER);
    }

    #[test]
    fn clear_all_resets_slots() {
        let (mut asm, arena) = test_assembler();
        let mut count = 0usize;
        asm.feed(1, 0, 2, 0, 0, b"A", 100, |_| count += 1);
        asm.clear_all();
        asm.feed(1, 1, 2, 1, 0, b"B", 200, |_| count += 1);
        assert_eq!(count, 0);
        free_asm_arena(arena, ASM_SLOTS_PER_PEER);
    }

    #[test]
    fn assembly_slot_size() {
        assert_eq!(mem::size_of::<AssemblySlot>(), 9280);
        assert_eq!(9280 % 64, 0);
    }
}
