//! Replay cache with optional file persistence across restarts/upgrades.
use anyhow::Result;
use std::{
    collections::{HashMap, VecDeque},
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant;

const SWEEP_LIMIT: usize = 64;
const RECORD_BYTES: usize = 40; // 32-byte key + 8-byte BE unix_expiry_secs

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayLoadStatus {
    Disabled,
    Fresh,
    Loaded(usize),
    CorruptedReinitialized,
}

impl ReplayLoadStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Fresh => "fresh",
            Self::Loaded(_) => "loaded",
            Self::CorruptedReinitialized => "corrupted_reinitialized",
        }
    }

    pub fn loaded_entries(self) -> usize {
        match self {
            Self::Loaded(n) => n,
            _ => 0,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Fresh,
    Duplicate,
    Full,
}

pub type SnapshotEntry = ([u8; 32], u64);

pub struct ReplayCache {
    entries: HashMap<[u8; 32], (Instant, u64)>,
    expiry: VecDeque<([u8; 32], Instant)>,
    capacity: usize,
    ttl: Duration,
    persist_path: Option<PathBuf>,
    generation: u64,
    flushed_generation: u64,
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl ReplayCache {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity),
            expiry: VecDeque::with_capacity(capacity),
            capacity,
            ttl,
            persist_path: None,
            generation: 0,
            flushed_generation: 0,
        }
    }

    #[cfg(test)]
    pub fn load_or_new(path: PathBuf, capacity: usize, ttl: Duration) -> Result<Self> {
        let (cache, _) = Self::load_with_status(path, capacity, ttl);
        Ok(cache)
    }

    pub fn load_with_status(
        path: PathBuf,
        capacity: usize,
        ttl: Duration,
    ) -> (Self, ReplayLoadStatus) {
        let mut cache = Self::new(capacity, ttl);
        let status = if path.exists() {
            match fs::read(&path) {
                Ok(bytes) if bytes.len().is_multiple_of(RECORD_BYTES) => {
                    let now_mono = Instant::now();
                    let now_unix = unix_now_secs();
                    let mut loaded: Vec<([u8; 32], Instant, u64)> = Vec::new();
                    for chunk in bytes.as_chunks::<RECORD_BYTES>().0 {
                        let Ok(key): std::result::Result<[u8; 32], _> = chunk[..32].try_into()
                        else {
                            break;
                        };
                        let Ok(exp_bytes): std::result::Result<[u8; 8], _> =
                            chunk[32..40].try_into()
                        else {
                            break;
                        };
                        let exp_unix = u64::from_be_bytes(exp_bytes);
                        if exp_unix <= now_unix {
                            continue;
                        }
                        let rem = Duration::from_secs((exp_unix - now_unix).min(ttl.as_secs()));
                        let exp_mono = now_mono + rem;
                        loaded.push((key, exp_mono, exp_unix));
                    }
                    // Sort ascending by expiry so front-of-queue lazy sweep never gets blocked
                    // behind a longer-lived entry loaded earlier from HashMap iteration order.
                    loaded.sort_unstable_by_key(|(_, exp_mono, _)| *exp_mono);
                    for (key, exp_mono, exp_unix) in loaded {
                        if cache.entries.len() >= capacity {
                            break;
                        }
                        if cache.entries.insert(key, (exp_mono, exp_unix)).is_none() {
                            cache.expiry.push_back((key, exp_mono));
                        }
                    }
                    ReplayLoadStatus::Loaded(cache.entries.len())
                }
                _ => ReplayLoadStatus::CorruptedReinitialized,
            }
        } else {
            ReplayLoadStatus::Fresh
        };
        cache.persist_path = Some(path);
        (cache, status)
    }

    /// Caller holds one async mutex across check and insert. Work per call is bounded.
    pub fn check_and_insert(&mut self, key: [u8; 32], now: Instant) -> Decision {
        for _ in 0..SWEEP_LIMIT {
            match self.expiry.front().copied() {
                Some((key, expiry)) if expiry <= now => {
                    self.expiry.pop_front();
                    if self.entries.get(&key).map(|v| v.0) == Some(expiry) {
                        self.entries.remove(&key);
                    }
                }
                _ => break,
            }
        }
        if let Some((expiry, _)) = self.entries.get(&key) {
            if *expiry > now {
                return Decision::Duplicate;
            }
            self.entries.remove(&key);
        }
        // Never evict a live key to admit a new one: saturation falls back to cover.
        if self.entries.len() >= self.capacity || self.expiry.len() >= self.capacity {
            return Decision::Full;
        }
        let expiry = now + self.ttl;
        let exp_unix = unix_now_secs().saturating_add(self.ttl.as_secs());
        self.entries.insert(key, (expiry, exp_unix));
        self.expiry.push_back((key, expiry));
        self.generation += 1;
        Decision::Fresh
    }

    pub fn dirty_snapshot(&self) -> Option<(PathBuf, u64, Vec<SnapshotEntry>)> {
        let path = self.persist_path.as_ref()?.clone();
        if self.generation == self.flushed_generation {
            return None;
        }
        let now_unix = unix_now_secs();
        let items = self
            .entries
            .iter()
            .filter_map(|(k, (_, exp))| (*exp > now_unix).then_some((*k, *exp)))
            .collect();
        Some((path, self.generation, items))
    }

    pub fn mark_flushed(&mut self, generation: u64) {
        self.flushed_generation = self.flushed_generation.max(generation);
    }

    pub fn flush_snapshot(&mut self) -> Result<()> {
        let Some((path, gen, items)) = self.dirty_snapshot() else {
            return Ok(());
        };
        write_snapshot_items(&path, &items)?;
        self.mark_flushed(gen);
        Ok(())
    }
}

static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn write_snapshot_items(path: &Path, items: &[SnapshotEntry]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let seq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = path.with_extension(format!("tmp.{}.{}", std::process::id(), seq));
    let now_unix = unix_now_secs();
    {
        let mut f = fs::File::create(&tmp)?;
        for (key, exp_unix) in items {
            if *exp_unix > now_unix {
                f.write_all(key)?;
                f.write_all(&exp_unix.to_be_bytes())?;
            }
        }
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;
    #[test]
    fn inv02_saturation_does_not_evict_live_keys_and_ttl_is_exact() {
        let now = Instant::now();
        let ttl = Duration::from_secs(300);
        let mut cache = ReplayCache::new(1, ttl);
        assert_eq!(cache.check_and_insert([1; 32], now), Decision::Fresh);
        assert_eq!(cache.check_and_insert([2; 32], now), Decision::Full);
        assert_eq!(
            cache.check_and_insert([1; 32], now + ttl - Duration::from_nanos(1)),
            Decision::Duplicate
        );
        assert_eq!(cache.check_and_insert([1; 32], now + ttl), Decision::Fresh);
        assert_eq!(
            cache.check_and_insert([1; 32], now + ttl),
            Decision::Duplicate
        );
    }
    #[test]
    fn inv03_expiry_work_and_memory_are_bounded() {
        let now = Instant::now();
        let ttl = Duration::from_secs(300);
        let mut cache = ReplayCache::new(1024, ttl);
        for n in 0..1024u32 {
            let mut key = [0; 32];
            key[..4].copy_from_slice(&n.to_le_bytes());
            assert_eq!(cache.check_and_insert(key, now), Decision::Fresh);
        }
        assert_eq!(
            cache.check_and_insert([255; 32], now + ttl),
            Decision::Fresh
        );
        assert_eq!(cache.expiry.len(), 1024 - SWEEP_LIMIT + 1);
        assert_eq!(cache.entries.len(), 1024 - SWEEP_LIMIT + 1);
        for _ in 0..10000 {
            assert_eq!(
                cache.check_and_insert([255; 32], now + ttl),
                Decision::Duplicate
            );
            assert!(cache.expiry.len() <= 1024 && cache.entries.len() <= 1024);
        }
    }

    #[test]
    fn inv02_persistent_replay_survives_reload() -> Result<()> {
        let dir = std::env::temp_dir().join(format!(
            "mtevil-replay-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let path = dir.join("replay.bin");
        let ttl = Duration::from_secs(300);
        let mut cache = ReplayCache::load_or_new(path.clone(), 64, ttl)?;
        assert_eq!(
            cache.check_and_insert([42; 32], Instant::now()),
            Decision::Fresh
        );
        // Unflushed snapshot remains dirty until mark_flushed is called.
        let (_, gen, _) = cache.dirty_snapshot().context("dirty snapshot")?;
        assert!(cache.dirty_snapshot().is_some());
        cache.flush_snapshot()?;
        assert!(cache.dirty_snapshot().is_none());
        let _ = gen;
        drop(cache);

        let mut reloaded = ReplayCache::load_or_new(path.clone(), 64, ttl)?;
        assert_eq!(
            reloaded.check_and_insert([42; 32], Instant::now()),
            Decision::Duplicate
        );

        // Corrupted (truncated non-multiple of 40 bytes) replay file never fails startup:
        // it reinitializes an empty cache and reports CorruptedReinitialized status.
        fs::write(&path, b"corrupted-incomplete-record")?;
        let (mut recovered, status) = ReplayCache::load_with_status(path.clone(), 64, ttl);
        assert_eq!(status, ReplayLoadStatus::CorruptedReinitialized);
        assert_eq!(status.as_str(), "corrupted_reinitialized");
        assert_eq!(status.loaded_entries(), 0);
        assert_eq!(
            recovered.check_and_insert([42; 32], Instant::now()),
            Decision::Fresh
        );
        recovered.flush_snapshot()?;
        let (_, status_after_flush) = ReplayCache::load_with_status(path.clone(), 64, ttl);
        assert_eq!(status_after_flush, ReplayLoadStatus::Loaded(1));

        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn inv02_loaded_expiry_queue_is_sorted_by_expiry_time() -> Result<()> {
        let path = std::env::temp_dir().join(format!(
            "mtevil-replay-sort-{}-{}.bin",
            std::process::id(),
            unix_now_secs()
        ));
        let now_unix = unix_now_secs();
        let key_a = [0x0au8; 32];
        let key_b = [0x0bu8; 32];
        let key_c = [0x0cu8; 32];
        // Deliberately write A (expires in 120s) BEFORE B (expires in 1s).
        let items: Vec<SnapshotEntry> = vec![(key_a, now_unix + 120), (key_b, now_unix + 1)];
        write_snapshot_items(&path, &items)?;

        let (mut cache, status) =
            ReplayCache::load_with_status(path.clone(), 2, Duration::from_secs(120));
        assert_eq!(status, ReplayLoadStatus::Loaded(2));

        // After 2 seconds, B has expired while A is still live; inserting C MUST succeed (Fresh).
        let later = Instant::now() + Duration::from_secs(2);
        assert_eq!(cache.check_and_insert(key_c, later), Decision::Fresh);
        assert_eq!(cache.check_and_insert(key_a, later), Decision::Duplicate);
        let _ = fs::remove_file(&path);
        Ok(())
    }
}
