//! Egress failover cooldown backoff and jitter primitives for mtevil.
use std::time::Duration;

/// Exponential backoff duration in milliseconds (`base * 2^(failures - 1)`), clamped to `max_ms`.
pub fn compute_egress_cooldown_unclamped_ms(base_ms: u64, max_ms: u64, failures: u32) -> u64 {
    let shift = failures.saturating_sub(1).min(20);
    let mul = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    base_ms.saturating_mul(mul).min(max_ms.max(base_ms))
}

/// Apply symmetric jitter (`sample_permille` in `-200..=200` for `±20%`), preserving at least 1 ms.
pub fn apply_cooldown_jitter_ms(clamped_ms: u64, sample_permille: i64) -> u64 {
    let factor = (1000i64 + sample_permille.clamp(-200, 200)).max(1) as u128;
    let ms = ((clamped_ms as u128).saturating_mul(factor) / 1000).max(1);
    ms.min(u64::MAX as u128) as u64
}

/// Compute jittered (`±20%`) exponential backoff duration for the given consecutive failure count.
pub fn compute_egress_cooldown(base: Duration, max: Duration, failures: u32) -> Duration {
    use rand::Rng;
    let base_ms = (base.as_millis() as u64).max(1);
    let max_ms = (max.as_millis() as u64).max(base_ms);
    let clamped = compute_egress_cooldown_unclamped_ms(base_ms, max_ms, failures);
    let jitter_permille: i64 = rand::rngs::OsRng.gen_range(-200..=200);
    Duration::from_millis(apply_cooldown_jitter_ms(clamped, jitter_permille))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_clamps_and_applies_jitter_bounds() {
        assert_eq!(compute_egress_cooldown_unclamped_ms(3000, 60000, 1), 3000);
        assert_eq!(compute_egress_cooldown_unclamped_ms(3000, 60000, 2), 6000);
        assert_eq!(compute_egress_cooldown_unclamped_ms(3000, 60000, 5), 48000);
        assert_eq!(compute_egress_cooldown_unclamped_ms(3000, 60000, 6), 60000);
        assert_eq!(apply_cooldown_jitter_ms(10000, -200), 8000);
        assert_eq!(apply_cooldown_jitter_ms(10000, 200), 12000);
        let d =
            compute_egress_cooldown(Duration::from_millis(1000), Duration::from_millis(5000), 1);
        assert!((800..=1200).contains(&d.as_millis()));
    }
}
