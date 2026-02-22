// M13 HUB — ENGINE: DRL ACTION-SPACE CONTROL SUBSYSTEM
// Pure Rust, Zero-Allocation, FPU-Eradicated Q16.16 NEON PPO matrix math.
// Wait-free SPSC IPC bridging Data Plane Telemetry to the AI Control Plane.

use std::sync::atomic::{AtomicU64, Ordering};
use crate::engine::spsc::Consumer;

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

const Q_SHIFT: i32 = 16;
const Q_ONE: i32 = 1 << Q_SHIFT;

/// DRL State Tensor Telemetry (64-byte aligned to prevent AXI false sharing)
#[repr(C, align(64))]
#[derive(Copy, Clone)]
pub struct DrlStateTensor {
    pub peer_idx: u16,
    pub tx_queue_pressure: u16,
    pub rx_loss_q8: u8,
    pub burst_q8: u8,
    pub _pad0: u16,
    pub rx_jitter_us: u32,
    pub tx_drops: u32,
    pub recovered_pkts: u32,
    pub _pad1: [u8; 44],
}

impl Default for DrlStateTensor {
    fn default() -> Self {
        // SAFETY: All-zeroes is a valid bit pattern for this repr(C) struct of integer types.
        unsafe { std::mem::zeroed() }
    }
}
const _: () = assert!(std::mem::size_of::<DrlStateTensor>() == 64);

/// DO-178C Hardware-Timestamped Watchdog Pacing State
/// 64-byte aligned to perfectly isolate cache lines across 256 peers.
#[repr(C, align(64))]
pub struct DrlPacingState {
    pub state: AtomicU64,
}

impl DrlPacingState {
    #[inline(always)]
    pub fn store(&self, pacing: u8, now_ns: u64) {
        let val = ((pacing as u64) << 56) | (now_ns & 0x00FF_FFFF_FFFF_FFFF);
        self.state.store(val, Ordering::Release);
    }

    #[inline(always)]
    pub fn load(&self, now_ns: u64) -> u8 {
        let val = self.state.load(Ordering::Acquire);
        if val == 0 { return 1; } // M13 Baseline: 100% Maximum Redundancy

        let pacing = (val >> 56) as u8;
        let ts = val & 0x00FF_FFFF_FFFF_FFFF;
        
        // DO-178C Watchdog Failback: 50ms absolute timeout
        if now_ns.saturating_sub(ts) > 50_000_000 {
            1 // Safety First: Maximum 100% FEC pacing if AI worker stalls
        } else {
            pacing
        }
    }
}

const STATE_DIM: usize = 4;
const HIDDEN_DIM: usize = 16;
const ACTION_DIM: usize = 1;

/// Q16.16 Fixed-Point Actor Neural Network
#[repr(C, align(64))]
pub struct PpoPolicy {
    pub w1: [i32; STATE_DIM * HIDDEN_DIM], // 64
    pub b1: [i32; HIDDEN_DIM],             // 16
    pub w2: [i32; HIDDEN_DIM * ACTION_DIM], // 16
    pub b2: [i32; ACTION_DIM],             // 1
    pub _pad: [u8; 12],
}

impl Default for PpoPolicy {
    fn default() -> Self { Self::new() }
}

impl PpoPolicy {
    pub fn new() -> Self {
        let mut policy = PpoPolicy {
            w1: [0; 64], b1: [0; 16], w2: [0; 16], b2: [0; 1], _pad: [0; 12],
        };
        // Deterministic bootstrap for isolated zero-FPU execution
        for i in 0..64 { policy.w1[i] = ((i as i32 % 100) - 50) * 1000; }
        for i in 0..16 { policy.b1[i] = 100; }
        for i in 0..16 { policy.w2[i] = ((i as i32 % 50) - 25) * 500; }
        policy.b2[0] = Q_ONE * 4; // Base pacing factor
        policy
    }

    /// Fast forward pass leveraging ARM64 NEON intrinsics directly in L1 cache.
    #[inline(always)]
    pub fn forward_pass_neon(&self, state: &[i32; 4]) -> i32 {
        #[cfg(target_arch = "aarch64")]
        unsafe {
            // SAFETY: Array lengths and alignments statically guaranteed by struct definition.
            let s_neon = vld1q_s32(state.as_ptr());
            let mut hidden = [0i32; 16];

            for h in 0..16 {
                let w_ptr = self.w1.as_ptr().add(h * 4);
                let w_vec = vld1q_s32(w_ptr);
                
                let mul_res = vmulq_s32(w_vec, s_neon);
                let dot_sum = vaddvq_s32(mul_res);
                
                let sum = self.b1[h].saturating_add(dot_sum >> Q_SHIFT);
                hidden[h] = sum.max(0); // Branchless ReLU
            }

            let mut action = self.b2[0];
            for b in 0..4 {
                let w_ptr = self.w2.as_ptr().add(b * 4);
                let h_ptr = hidden.as_ptr().add(b * 4);
                
                let w_vec = vld1q_s32(w_ptr);
                let h_neon = vld1q_s32(h_ptr);
                
                let mul_res = vmulq_s32(w_vec, h_neon);
                action = action.saturating_add(vaddvq_s32(mul_res) >> Q_SHIFT); 
            }
            
            action.clamp(-5000, 5000)
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            let mut action = self.b2[0];
            for h in 0..HIDDEN_DIM {
                let mut sum = self.b1[h];
                for (i, s_val) in state.iter().enumerate() {
                    sum = sum.saturating_add(((self.w1[h * 4 + i] as i64 * *s_val as i64) >> Q_SHIFT) as i32);
                }
                action = action.saturating_add(((self.w2[h] as i64 * sum.max(0) as i64) >> Q_SHIFT) as i32);
            }
            action.clamp(-5000, 5000)
        }
    }

    #[inline(always)]
    pub fn update(&mut self, state: &[i32; 4], reward: i32) {
        let lr = 65; // ~0.001 in Q16
        let grad = if reward > 0 { lr } else { -lr };

        for i in 0..HIDDEN_DIM {
            self.w2[i] = self.w2[i].saturating_add(((grad as i64 * Q_ONE as i64) >> Q_SHIFT) as i32);
            for (j, s_val) in state.iter().enumerate() {
                let delta = ((grad as i64 * *s_val as i64) >> Q_SHIFT) as i32;
                self.w1[i * 4 + j] = self.w1[i * 4 + j].saturating_add(delta);
            }
        }
    }
}

// ============================================================================
// DRL ASYNC WORKER THREAD (CORE 0)
// ============================================================================

/// # Safety
/// Caller must ensure `target_pacing_arr` points to a statically-allocated, 
/// aligned `[DrlPacingState; 256]` that outlives this thread.
pub unsafe fn drl_worker_thread(
    core_id: usize,
    cal: crate::engine::runtime::TscCal,
    mut state_rx: Consumer<DrlStateTensor>,
    target_pacing_arr: *const [DrlPacingState; 256],
) {
    crate::engine::runtime::pin_to_core(core_id);
    crate::engine::runtime::verify_affinity(core_id);

    let mut model = PpoPolicy::new();
    let mut batch = [DrlStateTensor::default(); 128];
    let mut current_pacing_map = [4i32; 256]; 

    // V5: Offline Adaptive Telemetry Logger (Non-blocking append)
    let debug_mode = std::env::var("M13_DRL_DEBUG").is_ok();
    let mut log_file = if debug_mode {
        if let Ok(file) = std::fs::OpenOptions::new().create(true).append(true).open("/home/m13/Desktop/m13/m13_drl_telemetry.csv") {
            use std::io::Write;
            let mut f = file;
            let _ = writeln!(f, "timestamp_ns,peer_idx,tx_queue_pressure,rx_loss_q8,burst_q8,rx_jitter_us,tx_drops,recovered_pkts,target_pacing");
            Some(f)
        } else {
            None
        }
    } else {
        None
    };
    let mut last_log_ns = 0;

    loop {
        if crate::engine::runtime::SHUTDOWN.load(std::sync::atomic::Ordering::Relaxed) { break; }

        let count = state_rx.pop_batch(&mut batch);
        if count == 0 {
            std::thread::yield_now();
            continue;
        }

        let now_ns = crate::engine::runtime::rdtsc_ns(&cal);
        let should_log = debug_mode && (now_ns - last_log_ns > 1_000_000_000);
        if should_log { last_log_ns = now_ns; }

        for t in batch.iter().take(count) {
            let pidx = t.peer_idx as usize;
            if pidx >= 256 { continue; }

            // Encode Telemetry into Q16.16 format
            let s = [
                (t.rx_loss_q8 as i32) << 8, 
                (t.burst_q8 as i32) << 8,
                ((t.tx_queue_pressure as i32) << Q_SHIFT) / 2048,
                ((t.rx_jitter_us as i32) << Q_SHIFT) / 65535,
            ];

            // V6: DYNAMIC REDUNDANCY BOUNDS
            // Goal: Send as much Parity (target -> 1) as mathematically possible.
            // ONLY stop sending parity if we detect local bufferbloat/saturation.
            let reward = -(((t.tx_queue_pressure as i32) * 200) << (Q_SHIFT - 8));
            
            model.update(&s, reward);

            let action_delta = model.forward_pass_neon(&s);
            let mut target;

            // V6: Override AI to enforce hard physics laws (Inverted Paradigm)
            if t.tx_queue_pressure > 1800 {
                // Buffer saturated. DMA backpressure imminent.
                target = 0; // Shut off ALL parity immediately. Clear the pipes.
            } else if t.tx_queue_pressure > 1000 {
                // Buffer is building up. Throttling requested.
                target = 16; // Minimum parity density (1 per 16)
            } else {
                // Buffer healthy. Emit maximum parity.
                target = 1; // Maximum parity density (1 per 1, 100% redundancy)
            }

            // Apply AI micro-adjustments if buffer is in the sweet spot (100-1000)
            if t.tx_queue_pressure > 100 && t.tx_queue_pressure <= 1000 {
                target += action_delta >> 20;
            }
            
            // Clamp strictly 0 to 16
            current_pacing_map[pidx] = target.clamp(0, 16);

            if should_log {
                if let Some(ref mut f) = log_file {
                    use std::io::Write;
                    let _ = writeln!(f, "{},{},{},{},{},{},{},{},{}",
                        now_ns, pidx, t.tx_queue_pressure, t.rx_loss_q8, t.burst_q8, 
                        t.rx_jitter_us, t.tx_drops, t.recovered_pkts, current_pacing_map[pidx]
                    );
                }
            }

            // SAFETY: Array boundary outlives thread. Pointer indexes into leaked heap array.
            unsafe {
                (*target_pacing_arr)[pidx].store(current_pacing_map[pidx] as u8, now_ns);
            }
        }
    }
}
