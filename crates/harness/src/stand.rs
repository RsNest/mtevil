//! Стенд Phase 0 — docs/specs/phase-0.md §2: docker compose orchestration.
//!
//! Честность префлайта: реализованная проверка возвращает PASS/FAIL;
//! нереализованная — `UNIMPLEMENTED` и preflight в целом **не может** вернуть
//! успех (exit 2 при инфраструктурном pass + незакрытые пункты, 1 при fail).
//! Успех (0) только когда все заявленные проверки реализованы и прошли.

use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

const COMPOSE_FILE: &str = "crates/harness/stand/compose.yaml";
const VERSIONS_LOCK: &str = "crates/harness/config/versions.lock.toml";
/// Сервисы, обязанные быть running для префлайта стенда (scaffold: telemt-топология).
const EXPECTED_SERVICES: [&str; 5] = [
    "dut-telemt",
    "cover",
    "upstream-farm",
    "nstat-observer",
    "rst-observer",
];
/// Клиентский stub-контейнер нужен, но не как сервис топологии (probe-on-demand).
const CLIENT_STUB: &str = "client-stub";

fn sh(program: &str, args: &[&str]) -> Result<(bool, String)> {
    let out = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("запуск {program} {}", args.join(" ")))?;
    let mut text = String::from_utf8_lossy(&out.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok((out.status.success(), text))
}

fn docker_compose_args(extra: &[&str]) -> Vec<String> {
    let mut v = vec![
        "compose".to_string(),
        "-f".to_string(),
        COMPOSE_FILE.to_string(),
    ];
    v.extend(extra.iter().map(|s| s.to_string()));
    v
}

fn compose(extra: &[&str]) -> Result<(bool, String)> {
    let args = docker_compose_args(extra);
    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    sh("docker", &args_ref)
}

/// Минимальный парсер TOML-секции `key = "value"` для versions.lock.
/// Специализирован под наш файл: секция + строковые/булевы значения.
/// Ограничения (честно): '#' внутри кавычек не поддержан (в lock-файле таких
/// значений нет); массивы/таблицы в секции игнорируются.
/// НЕ полный TOML-парсер — расширяется вместе с файлом.
fn read_lock_section(section: &str) -> Result<BTreeMap<String, String>> {
    let raw = fs_lock()?;
    let mut result = BTreeMap::new();
    let mut inside = false;
    for line in raw.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            inside = line == format!("[{section}]");
            continue;
        }
        if inside {
            if let Some((k, v)) = line.split_once('=') {
                let key = k.trim().to_string();
                // Порядок важен: сначала убрать inline-комментарий, потом кавычки
                // (иначе trailing quote не снимется и значение испортится).
                let val = v
                    .split('#')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .trim_matches('"')
                    .trim()
                    .to_string();
                result.insert(key, val);
            }
        }
    }
    Ok(result)
}

fn fs_lock() -> Result<String> {
    std::fs::read_to_string(VERSIONS_LOCK).context("чтение versions.lock.toml")
}

pub fn up(allow_unpinned: bool) -> Result<()> {
    // 1. Pinning: DUT обязан быть pinned; cover digest — либо pinned, либо
    //    явное --allow-unpinned (digest запишется в env при pull).
    let dut = read_lock_section("candidates.telemt")?;
    match dut.get("status").map(|s| s.as_str()) {
        Some("pinned-immutable") => {}
        other => bail!(
            "telemt не pinned-immutable (status={other:?}) — стенд без pinned DUT не поднимается"
        ),
    }
    if dut.get("vcs_ref").map(|s| s.len()) != Some(40) {
        bail!("telemt vcs_ref не полный sha — pinning недействителен");
    }
    let cover = read_lock_section("cover")?;
    let cover_digest = cover.get("image_digest").map(|s| s.as_str()).unwrap_or("");
    if cover_digest.starts_with("TBD") {
        if allow_unpinned {
            eprintln!("WARN: cover image_digest не зафиксирован (--allow-unpinned); digest будет записан в env прогона при pull");
        } else {
            bail!("cover image_digest = TBD — сначала запиньте digest или запустите с --allow-unpinned");
        }
    }

    // 2. Docker daemon.
    let (ok, text) = sh("docker", &["info", "--format", "{{.ServerVersion}}"])?;
    if !ok {
        bail!("docker daemon недоступен: {}", text.trim());
    }

    // 3. Compose валидация + подъём.
    let (ok, text) = compose(&["config", "--quiet"])?;
    if !ok {
        bail!("compose.yaml невалиден: {}", text.trim());
    }
    let (ok, text) = compose(&["up", "-d", "--build"])?;
    if !ok {
        bail!("compose up: {}", text.trim());
    }

    // 4. Записать env прогона (CPU allocation, версии, ps, digests).
    let run_id = chrono_stamp();
    let env_dir = PathBuf::from("runs").join(run_id).join("env");
    std::fs::create_dir_all(&env_dir).context("создание каталога env")?;
    write_env(&env_dir)?;

    println!("stand up: OK (env: {})", env_dir.display());
    Ok(())
}

fn write_env(env_dir: &Path) -> Result<()> {
    let put = |name: &str, body: String| -> Result<()> {
        let mut f = std::fs::File::create(env_dir.join(name))?;
        f.write_all(body.as_bytes())?;
        Ok(())
    };
    put(
        "cpu-allocation.txt",
        format!(
            "# CPU allocation стенда (scaffold: без cpu-лимитов compose)\n\
             # generator/DUT/observer делят host CPU — contention возможен; smoke не бенчмарк.\n\
             nproc={}\nloadavg={}\n",
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(0),
            sh("sh", &["-c", "cat /proc/loadavg"])
                .map(|(_, t)| t.trim().to_string())
                .unwrap_or_default(),
        ),
    )?;
    let (_, docker_version) = sh("docker", &["--version"])?;
    put("docker-version.txt", docker_version)?;
    let (_, lscpu) = sh("lscpu", &[])?;
    put("lscpu.txt", lscpu)?;
    let (_, ps) = compose(&["ps"])?;
    put("compose-ps.txt", ps)?;
    // digests фактически использованных образов.
    let mut digests = String::from("# Digests образов на момент pull/build\n");
    for image in [
        "nginx:stable",
        "python:3.13-alpine",
        "bpftrace/bpftrace:latest",
    ] {
        let (ok, text) = sh(
            "docker",
            &[
                "image",
                "inspect",
                "--format",
                "{{.Id}} {{index .RepoDigests 0}}",
                image,
            ],
        )?;
        digests.push_str(&format!(
            "{image}: {}{}\n",
            if ok { "" } else { "NOT-PULLED " },
            text.trim()
        ));
    }
    put("image-digests.txt", digests)?;
    // versions.lock копия как часть улик.
    let lock = fs_lock()?;
    put("versions.lock.snapshot.toml", lock)?;
    Ok(())
}

pub fn down() -> Result<()> {
    let (ok, text) = compose(&["down", "-v"])?;
    if !ok {
        bail!("compose down: {}", text.trim());
    }
    println!("stand down: OK (каталоги runs/ сохранены)");
    Ok(())
}

/// Preflight. Возвращает код: 0 = всё реализовано и прошло; 2 = инфраструктура
/// прошла, есть UNIMPLEMENTED-пункты; 1 = инфраструктурный fail.
pub fn preflight(dut: &str, allow_unimplemented: bool) -> Result<i32> {
    let mut failures: Vec<String> = Vec::new();
    let mut unimplemented: Vec<String> = Vec::new();

    // 1. Docker daemon.
    let (ok, text) = sh("docker", &["info", "--format", "{{.ServerVersion}}"])?;
    if ok {
        println!("PASS: docker daemon {}", text.trim());
    } else {
        failures.push(format!("docker daemon недоступен: {}", text.trim()));
    }

    // 2. Compose валидация.
    let (ok, text) = compose(&["config", "--quiet"])?;
    if ok {
        println!("PASS: compose.yaml валиден");
    } else {
        failures.push(format!("compose.yaml невалиден: {}", text.trim()));
    }

    // 3. Pinning DUT.
    let section = format!("candidates.{dut}");
    if let Ok(pin) = read_lock_section(&section) {
        match pin.get("status").map(|s| s.as_str()) {
            Some(s) if s.starts_with("pinned") => println!("PASS: {dut} pinning: {s}"),
            Some(s) => failures.push(format!("{dut} status='{s}' — не pinned")),
            None => failures.push(format!("{dut}: в versions.lock нет status")),
        }
    } else {
        failures.push(format!(
            "{dut}: секция {section} отсутствует в versions.lock"
        ));
    }

    // 4. Сервисы running.
    let (ok, text) = compose(&["ps", "--format", "{{.Service}} {{.State}}"])?;
    if !ok {
        failures.push(format!("compose ps недоступен: {}", text.trim()));
    } else {
        let running: BTreeMap<&str, &str> =
            text.lines().filter_map(|l| l.split_once(' ')).collect();
        for svc in EXPECTED_SERVICES {
            match running.get(svc) {
                Some(&"running") => println!("PASS: service {svc} running"),
                Some(other) => failures.push(format!("service {svc} state={other}")),
                None => failures.push(format!("service {svc} отсутствует в compose ps")),
            }
        }
        if !running.contains_key(CLIENT_STUB) {
            println!(
                "NOTE: {CLIENT_STUB} не running — probe-контейнер запускается on-demand (не fail)"
            );
        }
    }

    // 5. DUT/cover слушают: проверка ВНУТРИ контейнера — docker-proxy на
    //    published-порту принимает TCP даже при мёртвом бэкенде (false positive
    //    обнаружен 2026-11-17), host-чек подходит только как доп. информация.
    let in_container_checks = [
        (
            "mtveil-dut-telemt",
            443u16,
            "dut-telemt:443 (MTProto/FakeTLS listen)",
        ),
        ("mtveil-cover", 80, "cover:80 (эталонный сайт)"),
    ];
    for (container, port, what) in in_container_checks {
        let cmd = format!("exec 3<>/dev/tcp/127.0.0.1/{port}");
        let (ok, text) = sh("docker", &["exec", container, "bash", "-c", &cmd])?;
        if ok {
            println!("PASS: {container} слушает {port} ({what}) — проверка внутри контейнера");
        } else {
            failures.push(format!(
                "{container} не слушает {port} ({what}): {}",
                text.trim()
            ));
        }
    }

    // 6. Свежесть nstat-сбора наблюдателем.
    match fresh_nstat() {
        Ok(age) => println!("PASS: nstat-сбор активен (свежий снапшот {age} с назад)"),
        Err(e) => failures.push(format!("nstat-сбор: {e}")),
    }

    // 7. eBPF reset-обозреватель: attach подтверждается фактом записи событий.
    match rst_observer_alive() {
        Ok(lines) => println!("PASS: reset-observer пишет события ({lines} строк)"),
        Err(e) => failures.push(format!("reset-observer: {e}")),
    }

    // 8. НЕ реализовано в scaffold: MTProto probe P09 (positive control).
    // Честность: отсутствие проверки не превращается в успех.
    unimplemented
        .push("MTProto probe P09 valid-probe (требует corpus + кодеки — этап 3–4 §16)".to_string());

    if !failures.is_empty() {
        for f in &failures {
            eprintln!("FAIL: {f}");
        }
        bail!(
            "preflight: {} инфраструктурных проверок провалено",
            failures.len()
        );
    }
    if !unimplemented.is_empty() {
        for u in &unimplemented {
            eprintln!("UNIMPLEMENTED: {u}");
        }
        if allow_unimplemented {
            eprintln!(
                "PREFLIGHT=2: инфраструктура OK; проверки UNIMPLEMENTED: {} — успех НЕ заявляется",
                unimplemented.len()
            );
            return Ok(2);
        }
        bail!(
            "preflight: инфраструктура OK, но {} проверок не реализовано — полный preflight НЕ пройден (запустите с --allow-unimplemented для явного exit 2)",
            unimplemented.len()
        );
    }
    println!("PREFLIGHT=0: все проверки реализованы и прошли");
    Ok(0)
}

fn fresh_nstat() -> Result<u64> {
    let dir = PathBuf::from("runs/current/raw/nstat");
    let mut newest: Option<std::time::SystemTime> = None;
    if dir.exists() {
        for e in std::fs::read_dir(&dir)? {
            let e = e?;
            if e.metadata()?.is_file() {
                let m = e.metadata()?.modified()?;
                if newest.map(|t| m > t).unwrap_or(true) {
                    newest = Some(m);
                }
            }
        }
    }
    match newest {
        Some(t) => {
            let age = t
                .elapsed()
                .map_err(|_| anyhow::anyhow!("clock skew"))?
                .as_secs();
            if age > 60 {
                bail!("свежий снапшот отсутствует: последний {age} с назад (лимит 60 с)");
            }
            Ok(age)
        }
        None => bail!("{} пуст или отсутствует", dir.display()),
    }
}

fn rst_observer_alive() -> Result<usize> {
    let path = PathBuf::from("runs/current/raw/ebpf/reset.log");
    let text =
        std::fs::read_to_string(&path).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    let n = validated_reset_events(&text);
    if n == 0 {
        bail!(
            "{}: нет распознанных reset-событий с положительным 64-bit timestamp",
            path.display()
        );
    }
    Ok(n)
}

fn validated_reset_events(text: &str) -> usize {
    text.lines()
        .filter(|line| {
            let mut words = line.split_whitespace();
            let timestamp = words.next().and_then(|s| s.parse::<u64>().ok());
            matches!(timestamp, Some(t) if t > 0)
                && matches!(words.next(), Some("SEND_RESET" | "RECV_RESET"))
                && ["skaddr=0x", "netns=", "saddr=", "daddr="]
                    .iter()
                    .all(|key| line.contains(key))
        })
        .count()
}

fn chrono_stamp() -> String {
    // Без внешних chrono-зависимостей: UTC-метка через SystemTime (секунды с epoch).
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("epoch{secs}")
}

#[cfg(test)]
mod observer_tests {
    use super::*;
    #[test]
    fn inv04_observer_errors_and_truncated_timestamps_are_not_evidence() {
        assert_eq!(
            validated_reset_events("Error: No such container\nAttached 2 probes\n"),
            0
        );
        assert_eq!(
            validated_reset_events("-1764675935 SEND_RESET skaddr=0x0 netns=1 saddr=x daddr=y"),
            0
        );
        assert_eq!(
            validated_reset_events(
                "12345678901234 SEND_RESET skaddr=0x0 netns=4026532554 saddr=x daddr=y"
            ),
            1
        );
    }
}
