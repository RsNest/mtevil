//! Replay protection cache and admission guard primitives for mtevil.
pub mod replay;
pub use replay::{Decision, ReplayCache, ReplayLoadStatus};
