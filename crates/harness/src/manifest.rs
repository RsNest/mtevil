//! Типы manifest и событий прогона — docs/specs/phase-0.md §8.
//!
//! Формат сырых данных — контракт между collect/report и публикуемыми прогонами;
//! изменения только через коммит в спеку + обратную совместимость чтения.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Netem-профили прогона (§2.2).
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct NetemProfile {
    pub client: String,
    pub egress: String,
}

/// Инъекция отказа (§9): t0 — offset от старта измеряемого окна.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct InjectionRecord {
    pub t0_offset_ms: u64,
    /// Канонический ID из failure-matrix.md (F-01..F-35) либо инъекционный сценарий F1..F10.
    pub kind: String,
    pub target: String,
}

/// manifest.json прогона (§8) — минимум.
#[derive(Debug, Serialize, Deserialize)]
pub struct RunManifest {
    pub run_id: String,
    /// telemt | mtg | mtdd | cover-ref
    pub dut: String,
    pub versions_lock_sha256: String,
    /// idle|messaging|messaging_hot|mixed_media|reconnect_storm|probe
    pub profile: String,
    pub netem: NetemProfile,
    pub seed: u64,
    pub sysctl_sha256: String,
    pub host: BTreeMap<String, String>,
    #[serde(default)]
    pub injections: Vec<InjectionRecord>,
    /// Хеш-чейн: relpath → {sha256, bytes}.
    pub files: BTreeMap<String, FileEntry>,
}

/// Запись хеш-чейна manifest (§8).
#[derive(Debug, Serialize, Deserialize)]
pub struct FileEntry {
    pub sha256: String,
    pub bytes: u64,
}

/// Событие единой timeline (§8): {ts_ns, source, kind, session?, attrs}.
/// Контрактный тип этапов collect/observe (§16 этапы 2/5) — используется отчётом и генератором.
#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct Event {
    pub ts_ns: u64,
    /// "generator" | "observer" | "chaos" | "dut" | "cover" | "upstream"
    pub source: String,
    /// Примеры: injection_start, connect, ch_sent, first_byte_back, rst_seen, writer_ready.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    #[serde(default)]
    pub attrs: BTreeMap<String, String>,
}
