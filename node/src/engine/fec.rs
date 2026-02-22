#![allow(dead_code)] // Decoder + utility methods wired incrementally; full API for spec parity with hub\n//! M13 VPP-Native FEC: Forward Error Correction via Batch RLNC
//!
//! Math-only module. Zero RL, zero adaptive logic.
//! The VPP batch (PacketVector, up to 64 frames) IS the coding unit.
//!
//! Ported from hub/src/engine/afec.rs — stripped of QLearningAgent, XorShift32.
//! Adapted: MAX_K=64 (was 8), row_present u64 (was u8).
//!
//! BUG FIX vs original afec.rs: Forward elimination now iterates over ALL
//! columns (0..k, j != i) instead of only (i+1)..k. This is required for
//! correctness with R→L (Caterpillar) pivot selection, where parity-derived
//! pivots have non-zero entries at columns BELOW their pivot position.
//!
//! Exports: Gf256, SimdGfMultiplier, TinyMt32,
//!          EncoderWindow, SwRlncDecoder, encode_parity_payload

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

use core::cmp;

// ============================================================================
// CONSTANTS
// ============================================================================

/// Maximum systematic frames per FEC block (Sliding Window size).
/// Decoupled from VPP VECTOR_SIZE to prevent O(k^2) latency spikes.
pub const MAX_K: usize = 8;

/// USO MTU — maximum payload per systematic frame.
pub const USO_MTU: usize = 1380;

// ============================================================================
// 1. GF(2^8) ARITHMETIC — RFC 8681 §3.7 field (x^8 + x^4 + x^3 + x^2 + 1)
// ============================================================================

pub struct Gf256;

impl Gf256 {
    const POLY: u8 = 0x1D;

    /// 256-byte static L1d-pinned inversion table for GF(2^8) with poly 0x1D.
    /// Generated via Fermat's Little Theorem: a^(-1) = a^254.
    /// Verified: a * inv(a) = 1 for all nonzero a.
    const INV_TABLE: [u8; 256] = [
        0x00, 0x01, 0x8E, 0xF4, 0x47, 0xA7, 0x7A, 0xBA, 0xAD, 0x9D, 0xDD, 0x98, 0x3D, 0xAA, 0x5D, 0x96,
        0xD8, 0x72, 0xC0, 0x58, 0xE0, 0x3E, 0x4C, 0x66, 0x90, 0xDE, 0x55, 0x80, 0xA0, 0x83, 0x4B, 0x2A,
        0x6C, 0xED, 0x39, 0x51, 0x60, 0x56, 0x2C, 0x8A, 0x70, 0xD0, 0x1F, 0x4A, 0x26, 0x8B, 0x33, 0x6E,
        0x48, 0x89, 0x6F, 0x2E, 0xA4, 0xC3, 0x40, 0x5E, 0x50, 0x22, 0xCF, 0xA9, 0xAB, 0x0C, 0x15, 0xE1,
        0x36, 0x5F, 0xF8, 0xD5, 0x92, 0x4E, 0xA6, 0x04, 0x30, 0x88, 0x2B, 0x1E, 0x16, 0x67, 0x45, 0x93,
        0x38, 0x23, 0x68, 0x8C, 0x81, 0x1A, 0x25, 0x61, 0x13, 0xC1, 0xCB, 0x63, 0x97, 0x0E, 0x37, 0x41,
        0x24, 0x57, 0xCA, 0x5B, 0xB9, 0xC4, 0x17, 0x4D, 0x52, 0x8D, 0xEF, 0xB3, 0x20, 0xEC, 0x2F, 0x32,
        0x28, 0xD1, 0x11, 0xD9, 0xE9, 0xFB, 0xDA, 0x79, 0xDB, 0x77, 0x06, 0xBB, 0x84, 0xCD, 0xFE, 0xFC,
        0x1B, 0x54, 0xA1, 0x1D, 0x7C, 0xCC, 0xE4, 0xB0, 0x49, 0x31, 0x27, 0x2D, 0x53, 0x69, 0x02, 0xF5,
        0x18, 0xDF, 0x44, 0x4F, 0x9B, 0xBC, 0x0F, 0x5C, 0x0B, 0xDC, 0xBD, 0x94, 0xAC, 0x09, 0xC7, 0xA2,
        0x1C, 0x82, 0x9F, 0xC6, 0x34, 0xC2, 0x46, 0x05, 0xCE, 0x3B, 0x0D, 0x3C, 0x9C, 0x08, 0xBE, 0xB7,
        0x87, 0xE5, 0xEE, 0x6B, 0xEB, 0xF2, 0xBF, 0xAF, 0xC5, 0x64, 0x07, 0x7B, 0x95, 0x9A, 0xAE, 0xB6,
        0x12, 0x59, 0xA5, 0x35, 0x65, 0xB8, 0xA3, 0x9E, 0xD2, 0xF7, 0x62, 0x5A, 0x85, 0x7D, 0xA8, 0x3A,
        0x29, 0x71, 0xC8, 0xF6, 0xF9, 0x43, 0xD7, 0xD6, 0x10, 0x73, 0x76, 0x78, 0x99, 0x0A, 0x19, 0x91,
        0x14, 0x3F, 0xE6, 0xF0, 0x86, 0xB1, 0xE2, 0xF1, 0xFA, 0x74, 0xF3, 0xB4, 0x6D, 0x21, 0xB2, 0x6A,
        0xE3, 0xE7, 0xB5, 0xEA, 0x03, 0x8F, 0xD3, 0xC9, 0x42, 0xD4, 0xE8, 0x75, 0x7F, 0xFF, 0x7E, 0xFD,
    ];

    #[inline(always)]
    pub fn invert(a: u8) -> u8 { unsafe { *Self::INV_TABLE.get_unchecked(a as usize) } }

    #[inline(always)]
    pub const fn mul_scalar(mut a: u8, mut b: u8) -> u8 {
        let mut p = 0;
        let mut i = 0;
        while i < 8 {
            let mask = (b & 1).wrapping_neg();
            p ^= a & mask;
            let hi = a & 0x80;
            a <<= 1;
            let r_mask = (hi.wrapping_shr(7)).wrapping_neg();
            a ^= Self::POLY & r_mask;
            b >>= 1;
            i += 1;
        }
        p
    }
}

/// Precomputes NEON multiplier tables ONCE per coefficient.
/// Hoisted out of the payload iteration loop.
pub struct SimdGfMultiplier {
    #[cfg(target_arch = "aarch64")] t_lo: uint8x16_t,
    #[cfg(target_arch = "aarch64")] t_hi: uint8x16_t,
    #[cfg(target_arch = "x86_64")] t_lo: std::arch::x86_64::__m512i,
    #[cfg(target_arch = "x86_64")] t_hi: std::arch::x86_64::__m512i,
    scalar: u8,
}

impl SimdGfMultiplier {
    #[inline(always)]
    pub fn new(coef: u8) -> Self {
        #[cfg(target_arch = "aarch64")]
        unsafe {
            let mut t_lo_arr = [0u8; 16];
            let mut t_hi_arr = [0u8; 16];
            for i in 0..16 {
                t_lo_arr[i] = Gf256::mul_scalar(coef, i as u8);
                t_hi_arr[i] = Gf256::mul_scalar(coef, (i as u8) << 4);
            }
            Self { t_lo: vld1q_u8(t_lo_arr.as_ptr()), t_hi: vld1q_u8(t_hi_arr.as_ptr()), scalar: coef }
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            use std::arch::x86_64::_mm512_loadu_si512;
            let mut t_lo_arr = [0u8; 64];
            let mut t_hi_arr = [0u8; 64];
            for i in 0..16 {
                let lo = Gf256::mul_scalar(coef, i as u8);
                let hi = Gf256::mul_scalar(coef, (i as u8) << 4);
                // AVX-512 vpshufb requires duplicating the 128-bit table across all four lanes
                t_lo_arr[i] = lo; t_lo_arr[i + 16] = lo; t_lo_arr[i + 32] = lo; t_lo_arr[i + 48] = lo;
                t_hi_arr[i] = hi; t_hi_arr[i + 16] = hi; t_hi_arr[i + 32] = hi; t_hi_arr[i + 48] = hi;
            }
            Self {
                t_lo: _mm512_loadu_si512(t_lo_arr.as_ptr() as *const _),
                t_hi: _mm512_loadu_si512(t_hi_arr.as_ptr() as *const _),
                scalar: coef
            }
        }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        Self { scalar: coef }
    }

    /// Multiply-accumulate: dst[i] ^= coef * src[i]  for all i in 0..len
    #[cfg_attr(target_arch = "x86_64", target_feature(enable = "avx512f", enable = "avx512bw"))]
    #[cfg_attr(not(target_arch = "x86_64"), inline(always))]
    pub unsafe fn mac_region(&self, dst: *mut u8, src: *const u8, len: usize) {
        if self.scalar == 0 { return; }

        #[cfg(target_arch = "aarch64")]
        {
            let mask = vdupq_n_u8(0x0F);
            let mut offset = 0;
            while offset + 16 <= len {
                let p_src = vld1q_u8(src.add(offset));
                let p_dst = vld1q_u8(dst.add(offset));
                let lo = vandq_u8(p_src, mask);
                let hi = vshrq_n_u8(p_src, 4);
                let res_lo = vqtbl1q_u8(self.t_lo, lo);
                let res_hi = vqtbl1q_u8(self.t_hi, hi);
                let prod = veorq_u8(res_lo, res_hi);
                vst1q_u8(dst.add(offset), veorq_u8(p_dst, prod));
                offset += 16;
            }
            while offset < len {
                *dst.add(offset) ^= Gf256::mul_scalar(*src.add(offset), self.scalar);
                offset += 1;
            }
        }
        #[cfg(target_arch = "x86_64")]
        {
            use std::arch::x86_64::*;
            let mask = _mm512_set1_epi8(0x0F);
            
            let mut offset = 0;
            while offset + 64 <= len {
                let p_src = _mm512_loadu_si512(src.add(offset) as *const _);
                let p_dst = _mm512_loadu_si512(dst.add(offset) as *const _);
                
                let lo = _mm512_and_si512(p_src, mask);
                
                // AVX-512 lacks byte-level shift, so we multiply by 0x10 and shift right by 8 to shift bytes right by 4
                // Avoids epi16 shifts crossing byte boundaries. Or use srli_epi16 and mask it:
                let shifted = _mm512_srli_epi16(p_src, 4);
                let hi = _mm512_and_si512(shifted, mask);
                
                let res_lo = _mm512_shuffle_epi8(self.t_lo, lo);
                let res_hi = _mm512_shuffle_epi8(self.t_hi, hi);
                
                let prod = _mm512_xor_si512(res_lo, res_hi);
                _mm512_storeu_si512(dst.add(offset) as *mut _, _mm512_xor_si512(p_dst, prod));
                offset += 64;
            }
            while offset < len {
                *dst.add(offset) ^= Gf256::mul_scalar(*src.add(offset), self.scalar);
                offset += 1;
            }
        }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            let mut offset = 0;
            while offset < len {
                *dst.add(offset) ^= Gf256::mul_scalar(*src.add(offset), self.scalar);
                offset += 1;
            }
        }
    }
}

// ============================================================================
// 2. PRNG — RFC 8682 TinyMT32 (coefficient generation)
// ============================================================================

/// RFC 8682 TinyMT32 PRNG — mandatory for RFC 8681 FEC coefficient generation.
/// Inline `no_std` implementation with RFC-mandated params.
/// 127-bit internal state (status[4]), deterministic across all platforms.
pub struct TinyMt32 {
    status: [u32; 4],
}

impl TinyMt32 {
    const MAT1: u32 = 0x8f7011ee;
    const MAT2: u32 = 0xfc78ff1f;
    const TMAT: u32 = 0x3793fdff;
    const SH0: u32 = 1;
    const SH1: u32 = 10;
    const SH8: u32 = 8;
    const MASK: u32 = 0x7fffffff;

    /// Initialize with a 32-bit seed per RFC 8682 §2.2.
    pub fn new(seed: u32) -> Self {
        let mut s = [seed, Self::MAT1, Self::MAT2, Self::TMAT];
        for i in 1..8u32 {
            s[(i & 3) as usize] ^= i.wrapping_add(
                1812433253u32.wrapping_mul(s[((i - 1) & 3) as usize] ^ (s[((i - 1) & 3) as usize] >> 30))
            );
        }
        let mut t = TinyMt32 { status: s };
        for _ in 0..8 { t.next_state(); }
        t
    }

    #[inline(always)]
    fn next_state(&mut self) {
        let mut y = self.status[3];
        let mut x = (self.status[0] & Self::MASK) ^ self.status[1] ^ self.status[2];
        x ^= x << Self::SH0;
        y ^= (y >> Self::SH0) ^ x;
        self.status[0] = self.status[1];
        self.status[1] = self.status[2];
        self.status[2] = x ^ (y << Self::SH1);
        self.status[3] = y;
        if y & 1 != 0 {
            self.status[1] ^= Self::MAT1;
            self.status[2] ^= Self::MAT2;
        }
    }

    #[inline(always)]
    fn temper(&self) -> u32 {
        let t0 = self.status[3];
        let t1 = self.status[0].wrapping_add(self.status[2] >> Self::SH8);
        let mut r = t0 ^ t1;
        if t1 & 1 != 0 { r ^= Self::TMAT; }
        r
    }

    /// Generate a 32-bit pseudorandom unsigned integer per RFC 8682 §2.2.
    #[inline(always)]
    pub fn next_u32(&mut self) -> u32 {
        self.next_state();
        self.temper()
    }

    /// Convenience: generate random byte for FEC coefficient.
    #[inline(always)]
    pub fn next_u8(&mut self) -> u8 {
        self.next_u32() as u8
    }
}

// ============================================================================
// 3. ENCODER — Batch-mode parity generation (VPP vector = coding unit)
// ============================================================================

/// Encoder window: stores UMEM pointers to systematic payloads within one VPP batch.
/// Valid only during the synchronous TX path (frames haven't been freed yet).
/// At MAX_K=64: 64 × (8+8) = 1KB on stack — fits comfortably.
pub struct EncoderWindow {
    /// Payloads of systematic frames in the sliding window.
    pub payloads: [[u8; USO_MTU]; MAX_K],
    /// Length of each payload.
    pub lens: [usize; MAX_K],
    /// Number of valid entries.
    pub count: u8,
    /// Head index (oldest element).
    pub head: u8,
}

// SAFETY: EncoderWindow holds raw pointers that are only valid during the synchronous
// TX graph execution. The pointers point into UMEM which is pinned (no moves).
unsafe impl Send for EncoderWindow {}

impl EncoderWindow {
    pub const fn new() -> Self {
        Self {
            payloads: [[0; USO_MTU]; MAX_K],
            lens: [0; MAX_K],
            count: 0,
            head: 0,
        }
    }

    /// Store a systematic frame's payload pointer in the window.
    /// If the window is full, slides the window left (evicting the oldest) 
    /// to maintain a continuous Rateless Sliding Window.
    /// # Safety
    /// `ptr` must point to a valid readable buffer of at least `len` bytes.
    #[inline(always)]
    pub unsafe fn push(&mut self, ptr: *const u8, len: usize) {
        let copy_len = cmp::min(len, USO_MTU);
        let idx = ((self.head + self.count) as usize) % MAX_K;
        unsafe { std::ptr::copy_nonoverlapping(ptr, self.payloads[idx].as_mut_ptr(), copy_len); }
        self.lens[idx] = copy_len;
        
        if (self.count as usize) < MAX_K {
            self.count += 1;
        } else {
            self.head = (self.head + 1) % (MAX_K as u8);
        }
    }

    /// Reset the window for the next coding block.
    #[inline(always)]
    pub fn reset(&mut self) {
        self.count = 0;
        self.head = 0;
    }
}

/// Generate one parity frame payload into `dst` via dense RLNC.
///
/// Uses `seed` to deterministically regenerate GF(2^8) coefficients.
/// The decoder can reconstruct the same coefficient vector from the seed.
///
/// Dense coding (RFC 8681 §8.2): all k source symbols participate.
/// At k=64 with GF(256), decoding failure probability < 0.4% per parity frame.
#[inline(always)]
pub fn encode_parity_payload(
    dst: &mut [u8],
    window: &EncoderWindow,
    k: usize,
    seed: u8,
) {
    let len = cmp::min(dst.len(), USO_MTU);
    // Zero the destination — parity starts as additive identity
    dst[..len].fill(0);

    let mut prng = TinyMt32::new(seed as u32);
    let effective_k = cmp::min(k, window.count as usize);
    if effective_k == 0 { return; }

    // Dense coding: all source symbols participate
    for i in 0..effective_k {
        let coef = prng.next_u8().max(1); // Non-zero coefficient
        let s_idx = ((window.head as usize) + i) % MAX_K;
        let slen = cmp::min(window.lens[s_idx], len);
        if slen > 0 {
            let ptr = window.payloads[s_idx].as_ptr();
            let mul = SimdGfMultiplier::new(coef);
            unsafe { mul.mac_region(dst.as_mut_ptr(), ptr, slen); }
        }
    }
}

// ============================================================================
// 4. DECODER — Caterpillar RLNC (band-form GE, R→L pivot, shifted RREF)
//    Ref: CRLNC-FB (ASU/IEEE) — right-to-left pivot selection ensures at most
//    1 row removed on window advance. Back-substitution maintains shifted RREF.
//
//    At MAX_K=64: matrix = 64×64 = 4KB, payload = 64×1380 = 86KB.
//    Heap-allocated via Box::new() — too large for stack.
//
//    BUG FIX: Forward elimination now uses full-row scan (0..k, j != i)
//    instead of the original (i+1)..k, which was incorrect for R→L pivot.
// ============================================================================

/// Sliding-window Caterpillar RLNC decoder matrix.
/// One per peer. Band-form GE with R→L pivot + back-substitution (shifted RREF).
#[repr(C, align(64))]
pub struct SwRlncDecoder {
    /// Coefficient matrix (shifted RREF). Row i = coefficients for symbol i.
    pub matrix: [[u8; MAX_K]; MAX_K],
    /// Decoded payload data. Row i = payload of decoded symbol i.
    pub payload: [[u8; USO_MTU]; MAX_K],
    /// Bitmask of rows that have been successfully pivoted.
    pub row_present: u8,
    /// Next slot to deliver in-order (RFC 8681 §6.2 delivery).
    pub deliver_next: u8,
    /// Absolute seq_id of the window's left edge.
    pub base_seq: u32,
}

impl std::fmt::Debug for SwRlncDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SwRlncDecoder {{ base_seq: {}, row_present: {:02X}, deliver_next: {} }}", self.base_seq, self.row_present, self.deliver_next)
    }
}

impl SwRlncDecoder {
    pub fn new() -> Self {
        // SAFETY: zero-initialized decoder is in a valid empty state.
        unsafe { core::mem::zeroed() }
    }

    /// Fast path reset: zero-initializes the entire state in <1us for recycling without heap reallocation.
    #[inline(always)]
    pub fn reset(&mut self) {
        unsafe { core::ptr::write_bytes(self as *mut Self, 0, 1); }
    }

    /// Heap-allocate a decoder (86KB+ — too large for stack at k=64).
    pub fn new_boxed() -> Box<Self> {
        // Use zeroed allocation to avoid stack overflow from large struct
        unsafe {
            let layout = std::alloc::Layout::new::<Self>();
            let ptr = std::alloc::alloc_zeroed(layout) as *mut Self;
            if ptr.is_null() { std::alloc::handle_alloc_error(layout); }
            Box::from_raw(ptr)
        }
    }

    /// Feed a frame to the decoder. Returns true if a new pivot was gained.
    ///
    /// - `abs_seq`: absolute sequence ID of this frame
    /// - `is_parity`: true for parity frames, false for systematic
    /// - `seed`: PRNG seed for coefficient regeneration (parity only)
    /// - `data`: payload bytes
    #[inline(always)]
    pub fn ingest(&mut self, abs_seq: u32, is_parity: bool, seed: u8, data: &[u8]) -> bool {
        // Out of window — too old
        if abs_seq < self.base_seq { return false; }

        let relative_idx = (abs_seq - self.base_seq) as usize;

        // Sliding window advancement — frame beyond current window
        if relative_idx >= MAX_K {
            let shift = relative_idx - MAX_K + 1;
            self.advance_window(shift);
            return false;
        }

        // Build the equation row for this frame
        let k = MAX_K;
        let mut row_eq = [0u8; MAX_K];

        if !is_parity {
            // Systematic: identity vector at column relative_idx
            row_eq[relative_idx] = 1;
        } else {
            // Parity: reconstruct dense coefficient vector from PRNG seed
            let mut prng = TinyMt32::new(seed as u32);
            for coef in row_eq.iter_mut().take(k) {
                *coef = prng.next_u8().max(1);
            }
        }

        // Copy payload data
        let len = cmp::min(data.len(), USO_MTU);
        let mut pivot_data = [0u8; USO_MTU];
        pivot_data[..len].copy_from_slice(&data[..len]);

        self.reduce_row(row_eq, pivot_data, len)
    }

    /// Feed a systematic frame directly to a known slot index.
    /// Bypasses sliding window logic for exact VPP-native block bounds.
    pub fn ingest_systematic(&mut self, slot_idx: usize, data: &[u8]) -> bool {
        if slot_idx >= MAX_K { return false; }
        
        let mut row_eq = [0u8; MAX_K];
        row_eq[slot_idx] = 1;

        let len = cmp::min(data.len(), USO_MTU);
        let mut pivot_data = [0u8; USO_MTU];
        pivot_data[..len].copy_from_slice(&data[..len]);

        self.reduce_row(row_eq, pivot_data, len)
    }

    #[inline(always)]
    fn reduce_row(&mut self, mut row_eq: [u8; MAX_K], mut pivot_data: [u8; USO_MTU], len: usize) -> bool {
        // Forward elimination — reduce against existing rows
        for i in 0..MAX_K {
            if (self.row_present & (1u8 << i)) != 0 {
                let factor = row_eq[i];
                if factor != 0 {
                    // SIMD Row XOR
                    let mul = SimdGfMultiplier::new(factor);
                    unsafe {
                        mul.mac_region(row_eq.as_mut_ptr(), self.matrix[i].as_ptr(), MAX_K);
                        mul.mac_region(pivot_data.as_mut_ptr(), self.payload[i].as_ptr(), len);
                    }
                    row_eq[i] = 0; // Restore elimination invariant
                }
            }
        }

        // R→L PIVOT — Caterpillar: find LAST (rightmost) non-zero coefficient.
        if let Some(p) = row_eq.iter().rposition(|&x| x != 0) {
            let inv = Gf256::invert(row_eq[p]);
            if inv != 1 {
                let mul = SimdGfMultiplier::new(inv);
                unsafe {
                    // Scalar multiply eq row
                    for item in row_eq.iter_mut() { *item = Gf256::mul_scalar(*item, inv); }
                    
                    let mut temp = [0u8; USO_MTU];
                    temp[..len].copy_from_slice(&pivot_data[..len]);
                    pivot_data[..len].fill(0);
                    mul.mac_region(pivot_data.as_mut_ptr(), temp.as_ptr(), len);
                }
            }

            self.matrix[p] = row_eq;
            self.payload[p] = pivot_data;
            self.row_present |= 1u8 << p;

            // BACK-SUBSTITUTION — maintain shifted RREF.
            for i in 0..MAX_K {
                if i != p && (self.row_present & (1u8 << i)) != 0 {
                    let factor = self.matrix[i][p];
                    if factor != 0 {
                        let mul = SimdGfMultiplier::new(factor);
                        unsafe {
                            mul.mac_region(self.matrix[i].as_mut_ptr(), self.matrix[p].as_ptr(), MAX_K);
                            mul.mac_region(
                                self.payload[i].as_mut_ptr(),
                                self.payload[p].as_ptr(), len
                            );
                        }
                        self.matrix[i][p] = 0; // Restore invariant
                    }
                }
            }
            return true;
        }

        false // Linearly dependent — no new information
    }

    /// Feed a parity frame to the decoder without a window position.
    /// For VPP-native block FEC where k=MAX_K, parity frames don't have
    /// a meaningful abs_seq within the window. Instead, we feed the parity
    /// equation directly: dense coefficients over columns [0..k), GE + pivot.
    ///
    /// - `seed`: TinyMT32 seed for coefficient regeneration
    /// - `k`: number of systematic sources in this FEC block
    /// - `data`: parity payload bytes
    pub fn ingest_parity(&mut self, seed: u8, k: usize, data: &[u8]) -> bool {
        let effective_k = cmp::min(k, MAX_K);
        if effective_k == 0 { return false; }

        // Build parity equation: dense coefficients over [0..k)
        let mut row_eq = [0u8; MAX_K];
        let mut prng = TinyMt32::new(seed as u32);
        for coef in row_eq.iter_mut().take(effective_k) {
            *coef = prng.next_u8().max(1);
        }

        // Copy payload data
        let len = cmp::min(data.len(), USO_MTU);
        let mut pivot_data = [0u8; USO_MTU];
        pivot_data[..len].copy_from_slice(&data[..len]);

        self.reduce_row(row_eq, pivot_data, len)
    }

    /// Current rank (number of decoded symbols).
    #[inline(always)]
    pub fn rank(&self) -> u32 {
        self.row_present.count_ones()
    }

    /// Check if a specific position has been decoded.
    #[inline(always)]
    pub fn is_decoded(&self, idx: usize) -> bool {
        idx < MAX_K && (self.row_present & (1u8 << idx)) != 0
    }

    /// Get the decoded payload for a specific position.
    #[inline(always)]
    pub fn get_payload(&self, idx: usize) -> &[u8; USO_MTU] {
        &self.payload[idx]
    }

    /// Drain contiguous decoded payloads starting from deliver_next.
    /// RFC 8681 §6.2: "ADU is finally passed to the corresponding upper application."
    pub fn deliver<F: FnMut(&[u8; USO_MTU])>(&mut self, mut emit: F) -> u32 {
        let mut count = 0u32;
        while (self.deliver_next as usize) < MAX_K {
            let idx = self.deliver_next as usize;
            if (self.row_present & (1u8 << idx)) != 0 {
                emit(&self.payload[idx]);
                self.deliver_next += 1;
                count += 1;
            } else { break; } // Gap — stop in-order delivery
        }
        count
    }

    /// Advance the sliding window by `shift` positions.
    fn advance_window(&mut self, shift: usize) {
        if shift >= MAX_K {
            self.row_present = 0;
            self.deliver_next = 0;
            self.base_seq = self.base_seq.wrapping_add(shift as u32);
            return;
        }
        for i in 0..MAX_K {
            if i + shift < MAX_K {
                self.matrix[i] = self.matrix[i + shift];
                self.payload[i] = self.payload[i + shift];
                // FIX-9: Shift BOTH rows AND columns of coefficient matrix.
                // Without column shift, coefficient vectors reference stale column
                // positions after the window slides, corrupting Gaussian elimination.
                let mut new_row = [0u8; MAX_K];
                for (j, slot) in new_row.iter_mut().enumerate() {
                    if j + shift < MAX_K {
                        *slot = self.matrix[i + shift][j + shift];
                    }
                }
                self.matrix[i] = new_row;
            } else {
                self.matrix[i] = [0u8; MAX_K];
                self.payload[i] = [0u8; USO_MTU];
            }
        }
        self.row_present >>= shift as u8;
        self.deliver_next = self.deliver_next.saturating_sub(shift as u8);
        self.base_seq = self.base_seq.wrapping_add(shift as u32);
    }
}

// ============================================================================
// 5. AFEC SUB-HEADER — placed after M13 header on parity frames
// ============================================================================

/// FEC sub-header (8 bytes), placed immediately after M13 header on parity frames.
/// Lets the decoder reconstruct the coefficient vector deterministically.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct AfecSubHeader {
    /// Base sequence ID (low 32 bits). Identifies the start of the mathematical FEC block.
    pub base_seq_low: u32,
    /// Number of systematic frames in this block (k).
    pub k: u8,
    /// Index of this parity frame within the block (0..m-1).
    pub parity_idx: u8,
    /// Seed for TinyMT32 coefficient generation.
    pub seed: u8,
    /// Reserved bits (0xFF = dense coding).
    pub density: u8,
}

pub const AFEC_SUB_HDR_SIZE: usize = core::mem::size_of::<AfecSubHeader>();

// ============================================================================
// 6. TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf256_identity() {
        for a in 0..=255u8 {
            assert_eq!(Gf256::mul_scalar(a, 1), a);
        }
    }

    #[test]
    fn gf256_inverse() {
        for a in 1..=255u8 {
            let inv = Gf256::invert(a);
            assert_eq!(Gf256::mul_scalar(a, inv), 1, "Failed for a={}", a);
        }
    }

    #[test]
    fn gf256_zero_absorbs() {
        for a in 0..=255u8 {
            assert_eq!(Gf256::mul_scalar(a, 0), 0);
            assert_eq!(Gf256::mul_scalar(0, a), 0);
        }
    }

    #[test]
    fn encoder_window_push_reset() {
        let mut w = EncoderWindow::new();
        assert_eq!(w.count, 0);
        let data = [42u8; 100];
        unsafe { w.push(data.as_ptr(), 100); }
        assert_eq!(w.count, 1);
        w.reset();
        assert_eq!(w.count, 0);
    }

    #[test]
    fn encode_decode_systematic_only() {
        let mut decoder = SwRlncDecoder::new_boxed();
        let payloads: Vec<[u8; USO_MTU]> = (0..4).map(|i| {
            let mut p = [0u8; USO_MTU];
            p[0] = i as u8;
            p[1] = 0xFF;
            p
        }).collect();

        for (i, payload) in payloads.iter().enumerate().take(4) {
            let gained = decoder.ingest(i as u32, false, 0, payload);
            assert!(gained, "Systematic {} should gain rank", i);
        }
        assert_eq!(decoder.rank(), 4);
        assert_eq!(decoder.get_payload(0)[0], 0);
        assert_eq!(decoder.get_payload(1)[0], 1);
    }

    #[test]
    fn encode_decode_with_parity_recovery() {
        let seed = 42u8;

        let payloads: Vec<[u8; USO_MTU]> = (0..4).map(|i| {
            let mut p = [0u8; USO_MTU];
            for (j, item) in p.iter_mut().enumerate().take(USO_MTU) { *item = ((i * 37 + j) & 0xFF) as u8; }
            p
        }).collect();

        let mut window = EncoderWindow::new();
        for payload in payloads.iter().take(4) {
            unsafe { window.push(payload.as_ptr(), USO_MTU); }
        }
        let mut parity = [0u8; USO_MTU];
        encode_parity_payload(&mut parity, &window, 4, seed);

        let mut decoder = SwRlncDecoder::new_boxed();
        assert!(decoder.ingest(0, false, 0, &payloads[0]));
        // Skip frame 1 — simulating packet loss
        assert!(decoder.ingest(2, false, 0, &payloads[2]));
        assert!(decoder.ingest(3, false, 0, &payloads[3]));
        assert_eq!(decoder.rank(), 3);

        let recovered = decoder.ingest(4, true, seed, &parity);
        assert!(recovered, "Parity should help recover lost frame");
        assert!(decoder.rank() >= 4, "Should have full rank. Got: {}", decoder.rank());
    }

    #[test]
    fn tinymt32_rfc8682_validation() {
        let expected: [u32; 50] = [
            2545341989, 981918433, 3715302833, 2387538352, 3591001365,
            3820442102, 2114400566, 2196103051, 2783359912, 764534509,
            643179475, 1822416315, 881558334, 4207026366, 3690273640,
            3240535687, 2921447122, 3984931427, 4092394160, 44209675,
            2188315343, 2908663843, 1834519336, 3774670961, 3019990707,
            4065554902, 1239765502, 4035716197, 3412127188, 552822483,
            161364450, 353727785, 140085994, 149132008, 2547770827,
            4064042525, 4078297538, 2057335507, 622384752, 2041665899,
            2193913817, 1080849512, 33160901, 662956935, 642999063,
            3384709977, 1723175122, 3866752252, 521822317, 2292524454,
        ];
        let mut rng = TinyMt32::new(1);
        for (i, &exp) in expected.iter().enumerate() {
            let got = rng.next_u32();
            assert_eq!(got, exp, "TinyMT32 mismatch at index {}: got {}, expected {}", i, got, exp);
        }
    }

    #[test]
    fn gf256_0x1d_inversion_roundtrip() {
        for a in 1u16..=255 {
            let inv = Gf256::invert(a as u8);
            let product = Gf256::mul_scalar(a as u8, inv);
            assert_eq!(product, 1, "GF(2^8) inversion failed: {} * inv({})={} != 1", a, a, inv);
        }
    }

}
