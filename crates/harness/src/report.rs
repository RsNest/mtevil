//! Валидация каталога прогона — docs/specs/phase-0.md §8.
//!
//! lint: manifest.json читается, обязательные поля/метаданные присутствуют,
//! хеш-чейн сходится, **наличие сырых улик обязательно**. Прогон без
//! events/nstat/summary — не прогон (ADR-000 §11.6: отчёт без сырых данных
//! не принимается).
//!
//! seed — произвольный u64; seed 0 валиден (спека не запрещает).

use crate::manifest::RunManifest;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// Артефакты, без которых каталог не считается прогоном (§8):
/// (префикс пути в хеш-чейне, описание). `raw/nstat/` и `logs/` — «минимум один».
const REQUIRED_SINGLE: [(&str, &str); 2] = [
    ("raw/events.jsonl.gz", "единая timeline всех источников"),
    ("report/summary.json", "агрегаты прогона"),
];
const REQUIRED_GROUP_MIN_ONE: [(&str, &str); 2] = [
    ("raw/nstat/", "снапшоты nstat (минимум один)"),
    ("logs/", "логи сервисов (минимум один .gz)"),
];
/// Обязательные ключи host-метаданных (§8 manifest: kernel/cpu/runtime).
const REQUIRED_HOST_KEYS: [&str; 3] = ["kernel", "cpu", "runtime"];

/// Переопределения host-метаданных для seal (не-Linux машины или тесты).
#[derive(Clone, Default)]
pub struct HostOverrides {
    pub kernel: String,
    pub cpu: String,
    pub runtime: String,
}

/// Параметры seal — сгруппированы, чтобы не держать 9 аргументов.
pub struct SealParams<'a> {
    pub run_dir: &'a Path,
    pub dut: &'a str,
    pub profile: &'a str,
    pub seed: u64,
    pub versions_lock_sha256: &'a str,
    pub sysctl_sha256: &'a str,
    pub netem_client: &'a str,
    pub netem_egress: &'a str,
    pub host: HostOverrides,
}

pub fn lint(run_dir: &Path) -> Result<()> {
    let manifest_path = run_dir.join("manifest.json");
    if !manifest_path.exists() {
        bail!(
            "{} не найден — это не каталог прогона (§8)",
            manifest_path.display()
        );
    }
    let raw = fs::read(&manifest_path).context("чтение manifest.json")?;
    let manifest: RunManifest =
        serde_json::from_slice(&raw).context("manifest.json: некорректный JSON или схема")?;

    let mut problems = Vec::new();
    if manifest.run_id.is_empty() {
        problems.push("пустой run_id".into());
    }
    if !matches!(
        manifest.dut.as_str(),
        "telemt" | "mtg" | "mtdd" | "cover-ref"
    ) {
        problems.push(format!("dut вне реестра §1: {}", manifest.dut));
    }
    if !matches!(
        manifest.profile.as_str(),
        "idle" | "messaging" | "messaging_hot" | "mixed_media" | "reconnect_storm" | "probe"
    ) {
        problems.push(format!("профиль вне §4.2: {}", manifest.profile));
    }
    // seed 0 валиден: спека §4.1 требует фиксации seed'а, а не ненулевости.
    if manifest.versions_lock_sha256.is_empty() || manifest.sysctl_sha256.is_empty() {
        problems.push("нет sha256 versions.lock/sysctl — воспроизводимость не привязана".into());
    }
    for key in REQUIRED_HOST_KEYS {
        match manifest.host.get(key) {
            None => problems.push(format!("host.{key}: отсутствует (§8 обязателен)")),
            Some(v) if v.trim().is_empty() => problems.push(format!("host.{key}: пустой")),
            Some(_) => {}
        }
    }

    // Сырые улики: обязательные артефакты должны быть в хеш-чейне, существовать,
    // быть непустыми и иметь сходящийся sha256.
    for (path, what) in REQUIRED_SINGLE {
        match manifest.files.get(path) {
            None => problems.push(format!("{path}: отсутствует в хеш-чейне manifest ({what})")),
            Some(entry) => problems.extend(check_chain_entry(run_dir, path, entry)),
        }
    }
    for (prefix, what) in REQUIRED_GROUP_MIN_ONE {
        let matches: Vec<_> = manifest
            .files
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect();
        if matches.is_empty() {
            problems.push(format!(
                "{prefix}*: нет ни одной записи в хеш-чейне ({what})"
            ));
        } else {
            for path in &matches {
                problems.extend(check_chain_entry(run_dir, path, &manifest.files[path]));
            }
        }
    }
    // Всё, что заявлено в хеш-чейне, обязано существовать и сходиться (в т.ч. вне required).
    for (relpath, entry) in &manifest.files {
        if !REQUIRED_SINGLE.iter().any(|(p, _)| p == relpath)
            && !REQUIRED_GROUP_MIN_ONE
                .iter()
                .any(|(p, _)| relpath.starts_with(p))
        {
            problems.extend(check_chain_entry(run_dir, relpath, entry));
        }
    }

    if problems.is_empty() {
        println!(
            "OK: {} — dut={}, профиль={}, seed={} (0 валиден), файлов в хеш-чейне: {}, сырые улики: events+nstat+logs+summary",
            manifest.run_id,
            manifest.dut,
            manifest.profile,
            manifest.seed,
            manifest.files.len()
        );
        Ok(())
    } else {
        for p in &problems {
            eprintln!("FAIL: {p}");
        }
        bail!(
            "прогон {} не проходит lint: {} проблем",
            manifest.run_id,
            problems.len()
        );
    }
}

fn check_chain_entry(
    run_dir: &Path,
    relpath: &str,
    entry: &crate::manifest::FileEntry,
) -> Vec<String> {
    let path = run_dir.join(relpath);
    match fs::read(&path) {
        Ok(bytes) => {
            let mut problems = Vec::new();
            if bytes.is_empty() {
                problems.push(format!("{relpath}: пустой файл — не улика"));
            }
            if bytes.len() as u64 != entry.bytes {
                problems.push(format!(
                    "{relpath}: bytes {} != manifest {}",
                    bytes.len(),
                    entry.bytes
                ));
            }
            let got = hex::encode(Sha256::digest(&bytes));
            if got != entry.sha256.to_lowercase() {
                problems.push(format!("{relpath}: sha256 mismatch"));
            }
            problems
        }
        Err(e) => vec![format!("{relpath}: отсутствует или не читается: {e}")],
    }
}

/// `report seal` — собрать manifest.json по каталогу прогона (§8).
/// Выполняется на машине прогона (VM): host-метаданные читаются из /proc,
/// с возможностью переопределить флагами.
pub fn seal(p: SealParams<'_>) -> Result<()> {
    let run_dir = p.run_dir;
    let manifest_path = run_dir.join("manifest.json");
    if manifest_path.exists() {
        bail!(
            "{} уже существует — seal идемпотентен, перезапись запрещена",
            manifest_path.display()
        );
    }

    // host-метаданные: Linux /proc; на иных платформах — только через overrides
    // (lint честно отклонит пустые).
    let kernel = if p.host.kernel.is_empty() {
        fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    } else {
        p.host.kernel.clone()
    };
    let cpu = if p.host.cpu.is_empty() {
        fs::read_to_string("/proc/cpuinfo")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("model name"))
                    .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string())
            })
            .unwrap_or_default()
    } else {
        p.host.cpu.clone()
    };
    let runtime = if p.host.runtime.is_empty() {
        "docker".to_string()
    } else {
        p.host.runtime.clone()
    };

    let mut files = std::collections::BTreeMap::new();
    collect_chain(run_dir, run_dir, &mut files)?;

    let manifest = RunManifest {
        run_id: run_dir
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default(),
        dut: p.dut.to_string(),
        versions_lock_sha256: p.versions_lock_sha256.to_string(),
        profile: p.profile.to_string(),
        netem: crate::manifest::NetemProfile {
            client: p.netem_client.to_string(),
            egress: p.netem_egress.to_string(),
        },
        seed: p.seed,
        sysctl_sha256: p.sysctl_sha256.to_string(),
        host: {
            let mut h = std::collections::BTreeMap::new();
            h.insert("kernel".to_string(), kernel);
            h.insert("cpu".to_string(), cpu);
            h.insert("runtime".to_string(), runtime);
            h
        },
        injections: Vec::new(),
        files,
    };
    let json = serde_json::to_vec_pretty(&manifest).context("сериализация manifest")?;
    fs::write(&manifest_path, json).context("запись manifest.json")?;
    println!("sealed: {}", manifest_path.display());
    Ok(())
}

/// Рекурсивный сбор хеш-чейна: все файлы каталога прогона, кроме manifest.json.
fn collect_chain(
    root: &Path,
    dir: &Path,
    out: &mut std::collections::BTreeMap<String, crate::manifest::FileEntry>,
) -> Result<()> {
    for entry in fs::read_dir(dir).context("чтение каталога прогона")? {
        let entry = entry.context("readdir entry")?;
        let path = entry.path();
        if path.is_dir() {
            collect_chain(root, &path, out)?;
        } else if path.is_file() {
            let rel = path
                .strip_prefix(root)
                .context("strip_prefix")?
                .to_string_lossy()
                .replace('\\', "/");
            if rel == "manifest.json" {
                continue;
            }
            let bytes = fs::read(&path).with_context(|| format!("чтение {}", path.display()))?;
            out.insert(
                rel,
                crate::manifest::FileEntry {
                    sha256: hex::encode(Sha256::digest(&bytes)),
                    bytes: bytes.len() as u64,
                },
            );
        }
    }
    Ok(())
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn temp_dir(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("mtevil-lint-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn write_run(dir: &Path, events: &[u8]) {
        fs::create_dir_all(dir.join("raw/nstat")).unwrap();
        fs::create_dir_all(dir.join("logs")).unwrap();
        fs::create_dir_all(dir.join("report")).unwrap();
        fs::write(dir.join("raw/events.jsonl.gz"), events).unwrap();
        fs::write(dir.join("raw/nstat/dut.jsonl.gz"), b"nstat-delta").unwrap();
        fs::write(dir.join("logs/dut.log.gz"), b"log-bytes").unwrap();
        fs::write(dir.join("report/summary.json"), b"{\"status\":\"smoke\"}").unwrap();
        // Прогон собирается через seal: хеш-чейн строится по факту.
        seal(SealParams {
            run_dir: dir,
            dut: "cover-ref",
            profile: "probe",
            seed: 0, // seed 0 валиден
            versions_lock_sha256: "vl",
            sysctl_sha256: "sl",
            netem_client: "zero",
            netem_egress: "zero",
            host: HostOverrides {
                kernel: "test-kernel".into(),
                cpu: "test-cpu".into(),
                runtime: "test".into(),
            },
        })
        .unwrap();
    }

    #[test]
    fn seed_zero_is_valid() {
        let dir = temp_dir("seed0");
        write_run(&dir, b"{\"ts\":1}\n");
        assert!(
            lint(&dir).is_ok(),
            "seed 0 не может быть причиной отказа — спека его не запрещает"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_events_rejected() {
        let dir = temp_dir("empty-events");
        write_run(&dir, b""); // пустая timeline — не улика
        assert!(
            lint(&dir).is_err(),
            "пустой events.jsonl.gz обязан отклоняться"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_raw_evidence_rejected() {
        let dir = temp_dir("no-evidence");
        fs::create_dir_all(dir.join("report")).unwrap();
        fs::write(dir.join("report/summary.json"), b"{}").unwrap();
        seal(SealParams {
            run_dir: &dir,
            dut: "cover-ref",
            profile: "probe",
            seed: 7,
            versions_lock_sha256: "vl",
            sysctl_sha256: "sl",
            netem_client: "zero",
            netem_egress: "zero",
            host: HostOverrides {
                kernel: "test-kernel".into(),
                cpu: "test-cpu".into(),
                runtime: "test".into(),
            },
        })
        .unwrap();
        assert!(
            lint(&dir).is_err(),
            "manifest без events/nstat/logs обязан отклоняться"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_host_metadata_rejected() {
        let dir = temp_dir("no-host");
        write_run(&dir, b"{\"ts\":1}\n");
        // Портим host-метаданные: удаляем kernel.
        let mp = dir.join("manifest.json");
        let mut m: serde_json::Value = serde_json::from_slice(&fs::read(&mp).unwrap()).unwrap();
        m["host"].as_object_mut().unwrap().remove("kernel");
        fs::write(&mp, serde_json::to_vec(&m).unwrap()).unwrap();
        assert!(
            lint(&dir).is_err(),
            "отсутствие host.kernel обязано отклоняться"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_file_rejected() {
        let dir = temp_dir("tampered");
        write_run(&dir, b"{\"ts\":1}\n");
        // Меняем содержимое после seal — хеш-чейн обязан поймать.
        fs::write(
            dir.join("report/summary.json"),
            b"{\"status\":\"TAMPERED\"}",
        )
        .unwrap();
        assert!(
            lint(&dir).is_err(),
            "подмена файла после seal обязана отклоняться"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
