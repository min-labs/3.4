# ROADMAP

### ✅ Sprint 1: Foundation — COMPLETED

#### Debt

**[P0-01] VFS Syscall Avalanche (partial)** `← 1.2, 1.3`
**Defect:** Monolithic `loop {}` executing `recvmmsg`/`sendmmsg`/`File::read/write` via legacy POSIX FDs. 4 VFS syscalls per iteration = 8–40 µs static overhead on Cortex-A53, exceeding control-frame inter-arrival by 15×.
**Resolution:** Node datapath replaced with `io_uring` PBR multishot recv + CQE three-pass loop (S1.3). Hub TUN I/O decoupled to SPSC lock-free rings + housekeeping thread (S1.2). Remaining: stack buffer arena migration (→ S4.1), dead code eradication (→ S4.4).

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | Hardware Determinism | AF_XDP zero-copy enforcement, simulation eradication |
| **2** | Datapath VFS Decoupling | Hub SPSC TUN I/O, TUN housekeeping thread |
| **3** | Node io_uring | PBR multishot recv, CQE three-pass loop |
| **4** | FPU Eradication | Q60.4 fixed-point JitterEstimator |
| **5** | Spec Alignment | Closure TX, GraphCtx, dead code, test relocation |

#### Rationale

| # | Rationale |
| --- | --- |
| **1** | AF_XDP `XDP_ZEROCOPY` + `MAP_HUGETLB` strictly enforced. All simulation fallbacks (`M13_SIMULATION`, `XDP_COPY`, `SKB_MODE`) eradicated. Hardware or abort. |
| **2** | VFS `read`/`write` syscalls removed from AF_XDP hot-loops. SPSC lock-free rings decouple TUN I/O to a housekeeping thread. |
| **3** | `recvmmsg`/`sendmmsg` replaced with `io_uring` `SQPOLL` + PBR multishot recv. Zero context switches on the Node datapath. |
| **4** | IEEE 754 `f64` eradicated from `JitterEstimator`. Q60.4 fixed-point integer math per RFC 3550 §A.8. Zero FPU pollution. |
| **5** | Closure-based `send_fragmented_udp`, `GraphCtx` observability fields, dead `Assembler::new()` removed, `ETH_P_M13.to_be()` bug fixed. |

---

### ✅ Sprint 2: The 0-RTT Handshake — COMPLETED

#### Debt

**[P0-03] Synchronous PQC Lattice Math → HoL Blocking** `← 2.3`
**Location:** Node `cryptography/handshake.rs` (`process_handshake_node`) & Hub (`process_client_hello_hub`)
**Defect:** ML-DSA-87 and ML-KEM-1024 evaluated synchronously on the datapath thread. 5–25 ms blackout queues ~300 KB at 100 Mbps, blowing NIC ring limits and crashing BBR `cwnd`.
**Resolution:** PQC offloaded to Core 0 via dual SPSC rings. Datapath continues routing Established flows (MBB) while key-exchange resolves in parallel.

**[P1-02] IP Fragmentation over RF** `← 2.4`
**Location:** Node `main.rs` (`tun_file.read(&mut frame[62..1562])`)
**Defect:** 1562-byte frames over 1500 MTU WiFi forces kernel IP fragmentation. Loss scales geometrically: P(loss) = 1-(1-p)^n.
**Resolution:** USO slices ciphertext into 1380-byte RF chunks in userspace. Zero kernel fragmentation.

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | Stateful Security | MBB, Keepalives |
| **2** | PQC Offload | Dual SPSC, Core 0 worker, FlatHubHandshakeState |
| **3** | USO MTU Slicer | Userspace segmentation, zero kernel IP fragmentation |

#### Rationale

| # | Rationale |
| --- | --- |
| **1** | Make-Before-Break guarantees 0ms stream interruption during keygen. Active Keepalives defeat CGNAT deadlocks. |
| **2** | PQC lattice math (ML-KEM-1024, ML-DSA-87) blocks the datapath for 5-25ms. Offload to Core 0 via SPSC rings preserves Make-Before-Break continuity. |
| **3** | 1562-byte frames over 1500 MTU WiFi forces kernel IP fragmentation. Fragment loss scales geometrically. USO slices ciphertext into 1380-byte chunks in userspace. Zero kernel fragmentation. |

---

### ✅ Sprint 3: RL-AFEC — COMPLETED

#### Debt

**[P0-04] Static Parity Tax → 20% Bandwidth Waste** `← 3.1, 3.6`
**Defect:** Hardcoded `target.clamp(1, 16)` forced a minimum 6.25% parity overhead unconditionally, rising to 20% under steady state. Zero adaptation to link quality.
**Resolution:** SW RLNC encoder/decoder with GF(2^8) SIMD (`SimdGfMultiplier::mac_region`). Dynamic pacing via DRL Action-Space Control. Inverted Redundancy Paradigm baselines at `target = 1` (100% redundancy) with DRL throttling under buffer pressure.

**[P0-05] No FEC Decoder → Zero Loss Recovery** `← 3.2`
**Defect:** Parity frames were generated but never decoded. No packet recovery capability existed.
**Resolution:** Full `SwRlncDecoder` with Progressive Caterpillar R→L Pivot, Forward Elimination, shifted RREF Back-Substitution. NEON `vqtbl1q_u8` LUT-based GF(2^8) MAC at 16B/cycle (ARM64), AVX-512 `_mm512_shuffle_epi8` at 64B/cycle (x86_64).

**[P1-04] No Adaptive Control → Open-Loop FEC** `← 3.3, 3.5`
**Defect:** No feedback loop between link quality and parity rate. FEC was fire-and-forget.
**Resolution:** DRL worker on Core 0 consumes `DrlStateTensor` via wait-free SPSC ring (depth 8192). Q16.16 fixed-point PPO with NEON forward pass (`vmulq_s32`, `vaddvq_s32`, branchless ReLU). `DrlPacingState` AtomicU64 store(Release)/load(Acquire) with 50ms DO-178C watchdog failback.

**[P1-05] No Loss Telemetry → Blind Datapath** `← 3.4, 3.7`
**Defect:** Node had no mechanism to report link quality to Hub. Hub operated blind.
**Resolution:** Continuous Implicit Feedback (CIF). Node stamps `loss_q8` (EMA α=0.25) at `frame[59]` and `burst_q8` (EMA α=0.125) at `frame[60]`. Hub extracts at `m13_ptr.add(45/46)` in `classify_one()` at zero ALU cost.

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | SW RLNC Encoder | GF(2^8) SIMD parity generation, `EncoderWindow` sliding window, `TinyMt32` PRNG coefficients |
| **2** | SW RLNC Decoder | Progressive Caterpillar R→L Pivot, Forward Elimination, RREF Back-Substitution, `SwRlncDecoder` |
| **3** | DRL Action-Space Control | Q16.16 NEON PPO on Core 0, SPSC telemetry bridge, `DrlPacingState` Acquire/Release |
| **4** | CIF Telemetry | Zero-overhead loss/burst stamping in M13 header padding bytes 59–61 |
| **5** | Wire Protocol | `AfecSubHeader` (8B packed), `FLAG_FEC` routing in `classify_route` |
| **6** | Dynamic Redundancy | Inverted paradigm (baseline=100%), V6 bounds (0/1/16), 50ms watchdog failback |
| **7** | SPSC Alignment | Telemetry decoupling, struct offset corrections, parity vectorization proofs |
| **8** | Parity Vectorization | VPP Quad-Unrolling, `prefetch_read_l1`, `SimdGfMultiplier::mac_region` NEON/AVX-512 |

#### Rationale

| # | Rationale |
| --- | --- |
| **1** | Dense RLNC via `encode_parity_payload`: `dst[i] ^= coef * src[i]` across sliding window. NEON `vqtbl1q_u8` LUT eliminates DDR4 log/antilog tables, protecting 32KB L1d. |
| **2** | Caterpillar pivot amortizes Gaussian Elimination across arrivals. Final recovery is instantaneous back-substitution when rank k is achieved. GF(2^8) inversion via 256-byte `INV_TABLE` (Fermat's Little Theorem). |
| **3** | Decoupled AI worker prevents neural network inference from blocking the datapath. 64-byte `DrlStateTensor` alignment prevents AXI false sharing. AtomicU64 packs pacing + timestamp in single cache line. |
| **4** | CIF scavenges 3 padding bytes in the existing M13 header. Zero additional wire overhead. EWMA bit-shift momentum (`>> 2`, `>> 3`) eliminates FPU and array allocations. |
| **5** | `AfecSubHeader` carries `base_seq_low`, `k`, `parity_idx`, `seed`, `density` in 8 packed bytes. `FLAG_FEC` routes parity to `NextNode::Parity` in the VPP classify stage. |
| **6** | Inverted paradigm: high-assurance systems default to maximum redundancy. DRL only throttles under local buffer pressure (`tx_queue_pressure > 1800` → 0, `> 1000` → 16). |
| **7** | Hub telemetry counters (`TUN_R`, `TX`) were falsely summed, masking parity expansion ratios. Node CIF byte offsets corrected to `frame[59..61]` matching Hub `m13_ptr.add(45/46)`. |
| **8** | Outer VPP quad-loop (`wi + 4`) with `prefetch_read_l1` feeds payload tensors into `SimdGfMultiplier`. All GF(2^8) multiplications execute branchlessly in hardware registers. |

---

### Sprint 4: Memory Architecture

#### Debt

**[P0-01] VFS Syscall Avalanche** `← 4.1` `(io_uring delivered S1.3)`
**Location:** Node `main.rs` (`run_udp_worker`) and Hub `datapath.rs` (`tun_read_batch`)
**Defect:** Legacy POSIX `recvmmsg`/`sendmmsg`/`File::read/write` path still exists. Ring 3→Ring 0 context switch costs 2–10 µs per invocation on Cortex-A53. 4 VFS syscalls per iteration = 8–40 µs static overhead, exceeding control-frame inter-arrival time by 15×.
**Mandate:** Eradicate remaining stack buffers. Map into HugePage Arena with zero-copy `UmemSlice`. Legacy `run_udp_worker` dead code eradicated in S4.4.

**[P0-02] Unbounded Heap Allocation → TLB Exhaustion** `← 4.1`
**Location:** Node & Hub `engine/protocol.rs` (`Assembler::feed`)
**Defect:** `Vec::with_capacity(total as usize * 1444)` inside `HashMap<u16, AssemblyBuf>` from untrusted network data. Adversary sweeping `msg_id` 0–65535 with `total=255` forces 23.5 GB allocation, OOM-killing the process.
**Mandate:** Global allocator prohibited post-boot. Assembler must use pre-allocated HugePage Arena matrix with O(1) XOR-folding hash for `msg_id` slot resolution.

**[P2-02] L1d Cache Thrashing via Stack Arrays** `← 4.1`
**Location:** Node `main.rs` (`rx_bufs: [[u8; 2048]; 64]`, `tx_bufs: [[u8; 1600]; 64]`)
**Defect:** 230 KB of stack buffers. Cortex-A53 has 32 KB L1d — guaranteed 100% cache miss rate. DDR4 fetch costs 50–200 cycles per access.
**Mandate:** Packet buffers must never live on the stack. Map into NUMA-aligned HugePage Arena, reference via zero-copy `UmemSlice`.

**[P2-03] Branch Predictor Collapse via Enum Bloat** `← 4.2`
**Location:** Node `engine/runtime.rs` (`NodeState` enum), `main.rs` `process_rx_frame`
**Defect:** Rust enums sized to largest variant inflate `NodeState` to hundreds of bytes (PQC key `Vec`s). Hot-loop `matches!(state, Established)` forces full struct into L1d, evicting network payloads. BHT mispredictions under stochastic RF loss = 15-cycle penalty per miss.
**Mandate:** Compile-Time Typestate ZSTs. Hot loop possesses only memory pointers for `Established` state. Cryptographic state segregated to slow-path arena.

**[P0-01] Legacy VFS Dead Code** `← 4.4` `(see also S4.1)`
**Location:** Node `main.rs` (`run_udp_worker` — `#[allow(dead_code)]`)
**Mandate:** Eradicate legacy `recvmmsg`/`sendmmsg` path. Replaced by io_uring reactor (S1.3).

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | HugePage DMA | Cache-aligned packet arenas |
| **2** | Typestate ZST | Zero-sized type FSM, branch eradication |
| **3** | Memory & Topology | Thread isolation & NUMA |
| **4** | Codebase Ascension | Datapath sanitization & UmemSlice |
| **5** | UmemSlice | Memory safety algebra, bounds-checked pointers |

#### Rationale

| # | Rationale |
| --- | --- |
| **1** | Stack arrays (`[[u8; 2048]; 64]`) exceed the 32KB L1d cache, guaranteeing 100% miss rate. Map buffers into HugePage Arena with 64-byte alignment for hardware prefetcher. |
| **2** | Rust enums sized to largest variant inflate `NodeState` to hundreds of bytes. ZST typestates reduce hot-loop memory footprint to 8 bytes. Branch evaluation eradicated from emitted assembly. |
| **3** | Eradicates the monolithic "God Loop". 64MB HugePage Arena, 128-byte padded SPSC rings, NUMA pinning. Eliminates AXI/UPI bus traversal latency. |
| **4** | Eradicates raw pointer arithmetic via `UmemSlice`. Dynamic ENV configs replace hardcoded IPs. Hot-path syscalls gated. |
| **5** | `unsafe { ctx.umem_base.add(desc.addr) }` from untrusted network data = arbitrary memory access. `UmemSlice` wraps `NonNull<u8>` with one bounds check; LLVM elides all subsequent checks. |

---

### Sprint 5: System I/O

#### Debt

**[P2-01] L1i Annihilation via Subprocess Spawning** `← 5.2`
**Location:** Node `network/datapath.rs` (`create_tun`, `setup_tunnel_routes`)
**Defect:** `Command::new("ip")` = `fork()` + `execve()`. TLB shootdown + page table clone + L1i flush to load shell binaries. Consumes 5–50 ms. RF reconvergence during link flap obliterates the 50 µs transport deadline.
**Mandate:** Shell subprocesses banned. `AF_NETLINK` + `bytemuck` serializes routing changes in ~200 cycles.

| # | Sub-system | Deliverable |
| --- | --- | --- |
| ~~**1**~~ | ~~Kernel Bypass (Node)~~ | ~~io_uring PBR + USO (Node WiFi STA)~~ ✅ Delivered S1.3 |
| **1a** | Kernel Bypass (Hub WiFi AP) | io_uring PBR on Hub's WiFi 7 AP interface (`mac80211` — AF_XDP unsupported) |
| **2** | Netlink Router | Native ABI routing (AF_NETLINK) |
| **3** | Isochronous Physics | HW timestamps & reorder buffer |
| **4** | Symmetric Scaling | RSS & UDP port spraying |
| **5** | Heterogeneous Bond | Multi-path scheduler |

#### Rationale

| # | Rationale |
| --- | --- |
| ~~**1**~~ | ~~Delivered in Sprint 1.3~~ |
| **1a** | Hub runs dual kernel-bypass: `AF_XDP` on WAN-facing satellite NICs, `io_uring` on `mac80211` WiFi AP. Completes the zero-syscall datapath on both sides of the Hub. |
| **2** | `Command::new("ip")` = `fork()` + `execve()` = TLB shootdown + L1i flush. `AF_NETLINK` + `bytemuck` serializes routing changes in ~200 cycles. |
| **3** | Wires `_jbuf_depth`. IEEE 1588 PTP timestamps from MAC registers sequence out-of-order orbital arrivals. Strict playout deadlines before TUN injection. |
| **4** | Mutate outer UDP source port via inner IP hash. Forces NIC Toeplitz hash to spray flows across all CPU cores. |
| **5** | Active/Active bonding of Starlink, AST, Kuiper. Shifts coded blocks proportionally to instantaneous RTT and path capacities. |

---

### Sprint 6: ALU Saturation

#### Debt

**[P1-01] Sequential Cryptographic ALU Bubbles** `← 6.1, 6.2`
**Location:** Node `cryptography/aead.rs` (`encrypt_batch_ptrs`, `decrypt_batch_ptrs`). Hub `cryptography/aead.rs` (scalar only — no batch API exists yet).
**Defect:** Node pre-fetches 4 pointers into L1d but loops `for j in 0..4` calling `decrypt_one()` sequentially via `ring` crate. Hub has no batch AEAD at all — only scalar `seal_frame`/`open_frame`. ARMv8 `AESE`/`AESMC` have 3-cycle latency, 1-cycle throughput — sequential execution achieves 25–33% of silicon throughput.
**Mandate:** (a) Write Hub batch AEAD API. (b) Drop `ring` for hot-path on both sides. Load 4 independent packet state vectors into NEON 128-bit registers. Interleave AES round instructions across v0–v15. 100% ALU saturation.

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | Hub Batch AEAD | Write `decrypt_batch_ptrs`/`encrypt_batch_ptrs` for Hub (currently scalar-only) |
| **2** | Compute Saturation | AES-GCM decrypt pipeline (NEON/AES-NI interleave) — Node & Hub |
| **3** | SIMD Crypto | AES-GCM encrypt pipeline (NEON/AES-NI interleave) — Node & Hub |
| **4** | IP Checksum | Branchless vectorized folding |
| **5** | Compiler Ascendancy | LLVM PGO / BOLT |

#### Rationale

| # | Rationale |
| --- | --- |
| **1** | Hub currently calls scalar `open_frame`/`seal_frame` per packet. Must first have batch API before interleaving is possible. |
| **2** | ARMv8 `AESE`/`AESMC` have 3-cycle latency, 1-cycle throughput. Sequential `decrypt_batch_ptrs` achieves 33% of silicon throughput. 4x interleaved dispatch saturates the decrypt pipeline to 100%. |
| **3** | Mirrors S6.2 for `encrypt_batch_ptrs`. Load 4 independent plaintext state vectors into NEON 128-bit registers. Interleave AES round + GHASH tag generation across v0-v15. |
| **4** | IPv4 header is fixed 20 bytes. Cast to five `u32`, 5 parallel additions, branchless 16-bit carry fold. Drops from loop-based cost to ~12 instructions. |
| **5** | Instruments the binary, processes CSE workloads, and recompiles for perfect branch-prediction assembly alignment via LLVM BOLT. |

---

### Sprint 7: Sovereign Hardening

#### Debt

**[P2-04] Unrecoverable Deadlock in Signal Handlers** `← 7.3`
**Location:** Node `main.rs` (`HUB_IP_GLOBAL.lock()` inside `teardown_node`)
**Defect:** `teardown_node` invoked by `std::panic::set_hook` and standard execution. `std::sync::Mutex` uses `futex` — not async-signal-safe or panic-safe. If panic hook fires while datapath holds lock, process deadlocks. Drone becomes unrecoverable zombie.
**Mandate:** `Mutex` banned. Configuration data in `OnceLock` or `AtomicPtr`. Lock-free, wait-free structures only for signal-safe teardown.

**[P1-03] Asymmetric CPU DoS via Unfiltered Replays** `← 7.4`
**Location:** Node & Hub `cryptography/aead.rs` (`decrypt_one`)
**Defect:** `seq_id` extracted to construct nonce, but AEAD decryption fires before anti-replay validation. 1M replayed frames = 1M GHASH authentications, burning billions of cycles, starving legitimate telemetry.
**Mandate:** RFC 6479 anti-replay bitmask. `seq_id` evaluated against O(1) sliding bitmask via hardware intrinsics. Replays rejected in ~5 clock cycles before any cryptographic instruction.

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | Asymmetric Armor | eBPF PQC rate-limiting |
| **2** | Distributed Trust | CBOR MicroCerts & Swarm PKI |
| **3** | Signal Handlers | Wait-free atomic teardown |
| **4** | GHASH Shield | RFC 6479 anti-replay bitmask + hardware `trailing_zeros()` bitmap iteration |
| **5** | Kinetic Resilience | Merkle integrity & append-log |

#### Rationale

| # | Rationale |
| --- | --- |
| **1** | eBPF XDP/Socket token buckets drop spoofed `ClientHello` floods at L2, protecting the 120µs ML-DSA verification path from CPU exhaustion. |
| **2** | Wires `_now_ns` eviction parameters. Offline Root CA validation, 6-state Peer Lifecycle, Gossip-based Bloom Filter revocation in O(1). |
| **3** | `std::sync::Mutex` in signal handlers deadlocks the process. Replace with `AtomicU32` for wait-free teardown. |
| **4** | Adversary replaying captured frames burns billions of GHASH cycles. RFC 6479 64-bit sliding bitmask rejects replays in O(1) before any cryptographic instruction fires. Hardware `trailing_zeros()` + BLSR finds dropped packets in O(k) where k = actual losses. |
| **5** | Append-only logs prevent eMMC write amplification. SHA-256 Merkle tree detects physical flash tampering post-reboot. |

---

### Sprint 8: VERIFICATION & VALIDATION (V&V)

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | V&V | Tiers 2–5: E2E, Fuzz, Perf, Chaos |

#### V&V Matrix

"Happy Path" testing is prohibited. The system will not enter Phase 1 Flight Trials until it demonstrably passes the Tier 2 through Tier 5 Validation Matrix.

**Tier 1: Core Mathematical Integration** (`tests/integration.rs`)
Validates foundational mathematics and deterministic memory boundaries in absolute isolation. Currently 30 tests covering VPP graph pipeline, AEAD seal/open, PQC handshake round-trip, wire format parity, fragment reassembly, and rekey threshold enforcement.
* **Run:** `cargo test -p m13-tests` or `cargo test --workspace`

**Tier 2: Namespace Bounded Integration** (NetNS E2E)
Linux Network Namespaces (`ns_node`, `ns_hub`) connected via `veth` pair. PQC handshake convergence + `SIGKILL` → `E_PEER_TIMEOUT` detection.

**Tier 3: Cryptographic Fuzzing** (`libfuzzer`)
`cargo-fuzz` against `rx_parse_raw()`, `Assembler::feed()`, `open_frame()`. Must return `false` without panics, OOMs, or segfaults.

**Tier 4: Micro-Architectural Regression** (`criterion`)
`cargo bench` on Core 0 via `taskset`. `aead_decrypt_vector` and `classify_route` must not regress in cycle cost across any commit.

**Tier 5: Kinetic Survival / Chaos** (`tc netem`)
* `loss 30%` → FEC recovery without TCP `DUP-ACK` storms
* `delay 4s` → PQC Handshake survives without timeout
* `delay 6s` → Micro-ARQ retransmits ClientHello every 250ms without FSM reset
* 100K duplicated `seq_id` → `replay_drops` increments perfectly, CPU delta ≈ 0

---

### Sprint 9: Proof of Concept — Solo Hub Flight (within VLOS)

> [!NOTE]
> No daughter drones. No WiFi AP. Single drone, single SATCOM link, within visual line of sight (VLOS). Commodity flight frame (LALE integration is Sprint X). Proves the Hub flies and is controllable over M13. Third-party software: control & telemetry (ArduPilot + MAVLink), vision (GStreamer + V4L2), D&A (uAvionix / Iris Automation). 

#### Phase 1: Bench Validation

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | KV260 Bench Rig | KV260 + MIPI camera (TBD) + SATCOM modem on bench harness, M13 tunnel over live satellite link |

#### Phase 2: First Flight

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | Hardware-Software System Integration | KV260 + MIPI camera (TBD) + SATCOM mounted on commodity flight frame, powered flight with live SATCOM backhaul |

---

### Sprint 10: Block 0 Prototype — Full Architecture

> [!NOTE]
> Hub + WAN-deprived daughter drones (target: 2), WiFi 7 AP/STA, multi-SATCOM bonded backhaul, commodity airframe (LALE and custom PCB are Sprint X). Hardware: KV260 (K26 SOM), multiple SATCOM modems (target: 2), WiFi 7 radio, MIPI camera (TBD), R5F/FreeRTOS flight controller. Software: M13 (encrypted tunnel + multipath scheduler), ArduPilot + MAVLink (control & telemetry), GStreamer + V4L2 (vision), mavlink-router (multiplexing), D&A (uAvionix / Iris Automation), Yocto Linux. 

#### Phase 1: Dev Test Bench

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | Hub + Node Bench Rig | KV260 (Hub) + commodity ARM SBC (Node), WiFi 7 AP/STA pairing, full tunnel E2E on bench |
| **2** | Vision Integration | V4L2/GStreamer ingest interface, M13 tunnel priority class for video streams |
| **3** | Real-Time Telemetry | MAVLink bridge to M13 tunnel, priority scheduling (C2 > safety > telemetry > video) |
| **4** | NetNS Chaos Suite | Full Tier 2–5 V&V under `tc netem` loss/delay/duplication on bench |
| **5** | WiFi Reactor Wiring | Wire `hub/src/network/uring.rs` `WifiReactor` into `hub/src/main.rs` `worker_entry()` — conditional I/O substrate selection: `mac80211` WiFi → `WifiReactor` + `UringTx`, wired NIC → `Engine<ZeroCopyTx>` |

#### Phase 2: FPGA Offload

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | Silicon Ascension | FPGA PL offload (AES-256-GCM pipeline via AXI4-Stream DMA) |
| **2** | Regression Validation | Re-run Phase 1 + Sprint 8 V&V tests with FPGA AES backend, verify identical output |

#### Phase 3: VLOS Flight

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | Hub Flight Rig | KV260 + SATCOM + WiFi 7 AP mounted on commodity airframe |
| **2** | Node Flight Rig | Daughter drone(s) with m13-node, WiFi 7 STA, tethered to Hub AP |
| **3** | Swarm C2 (VLOS) | Ground station controls Hub and Nodes over M13 tunnel, within visual line of sight |
| **4** | D&A (VLOS) | Detect-and-avoid system validation within visual line of sight |

#### Phase 4: Stress & Endurance

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | RF Stress Test | Controlled jamming / interference injection, validate RL-AFEC recovery |
| **2** | Endurance Soak | Continuous flight with full architecture active, measure uptime, rekey cycles, thermal |

#### Phase 5: BVLOS

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | BVLOS C2 | Ground station controls Hub and Nodes over M13 tunnel at >1km range, beyond visual line of sight |
| **2** | D&A (BVLOS) | Detect-and-avoid system active during BVLOS flight, verify regulatory compliance |
| **3** | Redundant C2 (software kill) | Software-kill primary SATCOM interface via M13 tunnel, verify multipath scheduler fails over to remaining links — measure switchover latency, tunnel continuity, session recovery |

---

### Sprint X: End-State Hardware Design (Future Sprint)

> [!NOTE]
> K26 SOM on both low-altitude long endurance airborne network gateway (LALE-ANG) and WAN-deprived attritable daughter drone swarm (ADDS) are end-state hardware targets. LALE and ADDS are made feasible via custom PCBs. 

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | LALE-ANG | Airframe integration, SATCOM modem mounting, power budget, long-endurance, target altitude (TBD) |
| **2** | ADDS | Stable swarm flight and connection to LALE-ANG, form factor, price point |
| **3** | Custom PCB | KiCad schematic, layout, BOM — weight reduction, connector elimination |

#### Rationale

| # | Rationale |
| --- | --- |
| **1** | Hub airframe must carry SATCOM modem(s), Kria K26 SOM, WiFi 7 AP, and power supply within LALE flight envelope. Physical integration defines weight/power constraints. |
| **2** | Daughter drones must be cheap enough to attrit. WAN-deprived by design — WiFi 7 STA only, no SATCOM. Form factor drives PCB requirements. |
| **3** | COTS dev boards add ~200g of unnecessary connectors, peripherals, and packaging. Custom PCB strips to essentials: SOM + radio + power regulation. Enables attritability economics at scale. |


