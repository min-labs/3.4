// M13 NODE — NETWORK MODULE
// Datapath (TUN device, routing, cleanup).
// uring_reactor: io_uring SQPOLL + PBR zero-syscall reactor.

pub mod datapath;
pub mod uring_reactor;
