//! Приёмка wire-корпуса — docs/specs/phase-0.md §3.
//!
//! Два уровня проверки, не смешивать:
//!
//! **structural** — каждый вектор структурно корректен: JSON-схема, hex,
//! decoded-границы, совпадение sha256 с index.json, согласованность id.
//!
//! **acceptance** — structural + приёмочные критерии §3.3 (покрытие классов,
//! минимум от стоковых клиентов, негативные классы INV-04).
//!
//! `corpus verify --mode structural` НЕ заявляет приёмку корпуса.
//! index.json = {"version": 1, "vectors": [{"id","file","sha256","class","transport"}]}.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// Границы split-CH (ADR-000 §5.2): ≤16 записей, ≤4096 Б тело — применяются к
/// векторам транспорта `faketls` (движок обязан их принимать).
const FAKETLS_MAX_RECORDS: usize = 16;
const FAKETLS_MAX_RECORD_BODY: usize = 4096;
/// Санитарный предел файла вектора любого класса (не протокольная граница).
const MAX_VECTOR_FILE_BYTES: u64 = 64 * 1024;

/// Классы probe-suite (phase-0.md §10) — для приёмки §3.3(a).
const PROBE_CLASSES: [&str; 11] = [
    "P01-browser-ch-no-secret",
    "P02-replay-in-window",
    "P03-replay-out-window",
    "P04-garbage",
    "P05-not-tls",
    "P06-tls12-only",
    "P07-resumption-ch",
    "P08-silent",
    "P09-valid-probe",
    "P10-skew",
    "P11-probes-under-load",
];
/// Негативные классы INV-04 PreAuth — §3.3(c).
const NEGATIVE_CLASSES: [&str; 5] = [
    "P04-garbage",
    "P05-not-tls",
    "P06-tls12-only",
    "P07-resumption-ch",
    "P10-skew",
];

#[derive(Deserialize)]
struct Index {
    version: u32,
    vectors: Vec<IndexEntry>,
}

#[derive(Deserialize)]
struct IndexEntry {
    id: String,
    file: String,
    sha256: String,
    #[allow(dead_code)]
    class: String,
    #[allow(dead_code)]
    transport: String,
}

/// Схема файла вектора — phase-0.md §3.2.
#[derive(Deserialize)]
struct VectorFile {
    id: String,
    /// Дублирует index.class; читается только приёмкой — здесь валидируется наличие.
    #[serde(default)]
    #[allow(dead_code)]
    class: String,
    transport: String,
    /// capture|synthetic — участвует в приёмке §3.3(b).
    #[serde(default)]
    source: Option<String>,
    /// android-<ver>|ios-<ver>|desktop-<ver>|tdlib-<ver>|synthetic — §3.3(b).
    #[serde(default)]
    client: Option<String>,
    #[serde(default)]
    records: Vec<VectorRecord>,
}

#[derive(Deserialize)]
struct VectorRecord {
    direction: String,
    /// Hex-строка payload (без пробелов).
    hex: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Structural,
    Acceptance,
}

impl Mode {
    pub fn from_str(s: &str) -> Result<Self> {
        match s {
            "structural" => Ok(Mode::Structural),
            "acceptance" => Ok(Mode::Acceptance),
            other => bail!("неизвестный режим '{other}' (допустимо: structural|acceptance)"),
        }
    }
}

/// Структурная валидация содержимого файла вектора: схема, hex, decoded-границы.
/// Возвращает список проблем; пустой список = вектор структурно корректен.
fn validate_vector_content(bytes: &[u8], index_entry_id: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let v: VectorFile = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(e) => return vec![format!("JSON/схема вектора: {e}")],
    };
    if v.id != index_entry_id {
        problems.push(format!(
            "id вектора '{}' не совпадает с index.json '{}'",
            v.id, index_entry_id
        ));
    }
    if v.transport.is_empty() {
        problems.push("пустой transport".into());
    }
    if v.records.is_empty() {
        problems.push("records пуст — вектор без байтов не проверяет ничего".into());
    }
    let is_faketls = v.transport == "faketls";
    if is_faketls && v.records.len() > FAKETLS_MAX_RECORDS {
        problems.push(format!(
            "faketls: записей {} > лимита split-CH {FAKETLS_MAX_RECORDS}",
            v.records.len()
        ));
    }
    for (i, rec) in v.records.iter().enumerate() {
        if rec.direction != "c2p" && rec.direction != "p2c" {
            problems.push(format!(
                "record[{i}]: direction '{}' вне c2p|p2c",
                rec.direction
            ));
        }
        let decoded_len = if rec.hex.len() % 2 != 0 {
            problems.push(format!(
                "record[{i}]: hex нечётной длины ({} символов)",
                rec.hex.len()
            ));
            0
        } else {
            match hex::decode(&rec.hex) {
                Ok(b) => b.len(),
                Err(e) => {
                    problems.push(format!("record[{i}]: hex не декодируется: {e}"));
                    0
                }
            }
        };
        if is_faketls && decoded_len > FAKETLS_MAX_RECORD_BODY {
            problems.push(format!(
                "record[{i}]: decoded-тело {decoded_len} Б > лимита {FAKETLS_MAX_RECORD_BODY} (ADR-000 §5.2)"
            ));
        }
    }
    problems
}

pub fn verify(vectors_dir: &Path, mode: Mode) -> Result<()> {
    let index_path = vectors_dir.join("index.json");
    if !index_path.exists() {
        bail!(
            "корпус не собран: {} не найден. Приёмка — specs/phase-0.md §3.3; \
             захват/синтез векторов — этап 3 §16",
            index_path.display()
        );
    }
    let raw = fs::read(&index_path).context("чтение index.json")?;
    let index: Index =
        serde_json::from_slice(&raw).context("index.json: некорректный JSON или схема")?;
    if index.version != 1 {
        bail!("index.json: неизвестная версия схемы {}", index.version);
    }
    if index.vectors.is_empty() {
        bail!("index.json: ноль векторов — корпус пуст");
    }

    let mut structural_problems = Vec::new();
    let mut seen_ids = BTreeSet::new();
    let mut classes = BTreeSet::new();
    let mut faketls_clients = BTreeSet::new();
    let mut faketls_capture_count = 0usize;

    for v in &index.vectors {
        if !seen_ids.insert(v.id.clone()) {
            structural_problems.push(format!("дубликат id: {}", v.id));
            continue;
        }
        classes.insert(v.class.clone());
        let path = vectors_dir.join(&v.file);
        match fs::read(&path) {
            Ok(bytes) => {
                if bytes.len() as u64 > MAX_VECTOR_FILE_BYTES {
                    structural_problems.push(format!(
                        "{}: файл {} Б > санитарного предела {MAX_VECTOR_FILE_BYTES}",
                        v.id,
                        bytes.len()
                    ));
                }
                let got = hex::encode(Sha256::digest(&bytes));
                if got != v.sha256.to_lowercase() {
                    structural_problems.push(format!(
                        "{}: sha256 mismatch (index {} / файл {got})",
                        v.id, v.sha256
                    ));
                }
                structural_problems.extend(validate_vector_content(&bytes, &v.id));
            }
            Err(e) => {
                structural_problems.push(format!("{}: файл {} недоступен: {e}", v.id, v.file))
            }
        }
    }

    // Метаданные для приёмки: client/source из самих файлов векторов (не из index).
    for v in &index.vectors {
        let path = vectors_dir.join(&v.file);
        if let Ok(bytes) = fs::read(&path) {
            if let Ok(vf) = serde_json::from_slice::<VectorFile>(&bytes) {
                if vf.transport == "faketls" {
                    if let Some(c) = vf.client {
                        if !c.is_empty() && c != "synthetic" {
                            faketls_clients.insert(c);
                        }
                    }
                    if vf.source.as_deref() == Some("capture") {
                        faketls_capture_count += 1;
                    }
                }
            }
        }
    }

    if mode == Mode::Structural {
        if structural_problems.is_empty() {
            println!(
                "STRUCTURAL OK: {} векторов корректны (hex, границы, sha256). \
                 Приёмка корпуса НЕ заявлялась — используйте --mode acceptance",
                index.vectors.len()
            );
            return Ok(());
        }
        for p in &structural_problems {
            eprintln!("STRUCTURAL FAIL: {p}");
        }
        bail!(
            "корпус не структурно корректен: {} проблем",
            structural_problems.len()
        );
    }

    // --- acceptance (§3.3) ---
    let mut acceptance_failures = Vec::new();
    for required in PROBE_CLASSES {
        if !classes.contains(required) {
            acceptance_failures.push(format!("§3.3(a): нет векторов класса {required}"));
        }
    }
    if faketls_capture_count < 20 || faketls_clients.len() < 2 {
        acceptance_failures.push(format!(
            "§3.3(b): faketls capture-векторов {} (<20), стоковых клиентов {} (<2)",
            faketls_capture_count,
            faketls_clients.len()
        ));
    }
    for required in NEGATIVE_CLASSES {
        if !classes.contains(required) {
            acceptance_failures.push(format!(
                "§3.3(c): нет негативных векторов класса {required}"
            ));
        }
    }
    if !structural_problems.is_empty() {
        acceptance_failures.insert(
            0,
            format!(
                "structural: {} проблем (см. выше)",
                structural_problems.len()
            ),
        );
    }
    for p in &structural_problems {
        eprintln!("STRUCTURAL FAIL: {p}");
    }
    if acceptance_failures.is_empty() {
        println!(
            "ACCEPTANCE OK: {} векторов; покрытие §3.3(a,b,c) выполнено",
            index.vectors.len()
        );
        Ok(())
    } else {
        for p in &acceptance_failures {
            eprintln!("ACCEPTANCE FAIL: {p}");
        }
        bail!(
            "корпус не прошёл приёмку §3.3: {} критериев не выполнено",
            acceptance_failures.len()
        );
    }
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn temp_dir(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("mtevil-corpus-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn write_vector(
        dir: &Path,
        name: &str,
        id: &str,
        class: &str,
        transport: &str,
        hex: &str,
    ) -> String {
        let body = format!(
            r#"{{"id":"{id}","class":"{class}","transport":"{transport}","records":[{{"direction":"c2p","hex":"{hex}"}}]}}"#
        );
        fs::write(dir.join(name), &body).unwrap();
        hex::encode(Sha256::digest(body.as_bytes()))
    }

    fn write_index(dir: &Path, entries: &[String]) {
        let idx = format!(r#"{{"version":1,"vectors":[{}]}}"#, entries.join(","));
        fs::write(dir.join("index.json"), idx).unwrap();
    }

    #[test]
    fn structural_ok_but_acceptance_fails_on_sparse_corpus() {
        let dir = temp_dir("sparse");
        let sha = write_vector(
            &dir,
            "v1.json",
            "x-1",
            "P09-valid-probe",
            "faketls",
            "16030100",
        );
        write_index(
            &dir,
            &[format!(
                r#"{{"id":"x-1","file":"v1.json","sha256":"{sha}","class":"P09-valid-probe","transport":"faketls"}}"#
            )],
        );
        // Структурная валидность не заявляет приёмку:
        assert!(verify(&dir, Mode::Structural).is_ok());
        // Приёмка на разреженном корпусе обязана падать (false acceptance regression):
        assert!(verify(&dir, Mode::Acceptance).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_hex_rejected() {
        let dir = temp_dir("badhex");
        let sha = write_vector(&dir, "v1.json", "x-1", "P04-garbage", "faketls", "zz0010");
        write_index(
            &dir,
            &[format!(
                r#"{{"id":"x-1","file":"v1.json","sha256":"{sha}","class":"P04-garbage","transport":"faketls"}}"#
            )],
        );
        assert!(
            verify(&dir, Mode::Structural).is_err(),
            "нечётный hex не может быть структурно корректен"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_faketls_record_rejected() {
        let dir = temp_dir("oversize");
        let big = "41".repeat(4097); // 4097 Б > лимита §5.2
        let sha = write_vector(&dir, "v1.json", "x-1", "P09-valid-probe", "faketls", &big);
        write_index(
            &dir,
            &[format!(
                r#"{{"id":"x-1","file":"v1.json","sha256":"{sha}","class":"P09-valid-probe","transport":"faketls"}}"#
            )],
        );
        assert!(verify(&dir, Mode::Structural).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn id_mismatch_between_index_and_file_rejected() {
        let dir = temp_dir("idmismatch");
        let sha = write_vector(&dir, "v1.json", "other-id", "P04-garbage", "faketls", "ff");
        write_index(
            &dir,
            &[format!(
                r#"{{"id":"x-1","file":"v1.json","sha256":"{sha}","class":"P04-garbage","transport":"faketls"}}"#
            )],
        );
        assert!(
            verify(&dir, Mode::Structural).is_err(),
            "несовпадение id index<->файл — false acceptance"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sha_mismatch_rejected() {
        let dir = temp_dir("shabad");
        let _ = write_vector(&dir, "v1.json", "x-1", "P04-garbage", "faketls", "ff");
        write_index(&dir, &[r#"{"id":"x-1","file":"v1.json","sha256":"deadbeef","class":"P04-garbage","transport":"faketls"}"#.to_string()]);
        assert!(verify(&dir, Mode::Structural).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
