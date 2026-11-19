//! mtevil-harness — артефакты Phase 0 (docs/specs/phase-0.md).
//!
//! Реализовано: `corpus verify` (structural|acceptance), `report lint`,
//! `report seal`, `stand up/down/preflight`. Каркасы с зафиксированными
//! контрактами: `gen` (этап 4 §16). Каркасные подкоманды возвращают ошибку,
//! а не успех — фальшивые успехи запрещены.

mod corpus;
mod manifest;
mod report;
mod stand;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "mtevil-harness",
    about = "Phase 0 harness: корпус, генератор, стенд, отчёты",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// P09: full MTProto auth + encrypted ping through a FakeTLS test DUT.
    /// Requires Python, cryptography and Telethon; no Telegram account or API key.
    Probe {
        #[arg(long)]
        host: String,
        #[arg(long)]
        port: u16,
        #[arg(long)]
        secret_file: PathBuf,
        #[arg(long)]
        sni: String,
    },
    /// Wire-корпус (§3). Режимы: structural (валидность векторов) ≠ acceptance (приёмка §3.3).
    Corpus {
        #[command(subcommand)]
        action: CorpusAction,
    },
    /// Стенд (§2): поднять/опустить compose-топологию, preflight с честными статусами.
    Stand {
        #[command(subcommand)]
        action: StandAction,
    },
    /// Генератор нагрузки (§4): профили ADR-000 §6.2, seed-детерминизм.
    Gen {
        /// Профиль нагрузки: idle|messaging|messaging_hot|mixed_media|reconnect_storm
        #[arg(long)]
        profile: String,
        /// Seed детерминизма (пишется в manifest). seed 0 валиден.
        #[arg(long, default_value_t = 0)]
        seed: u64,
        /// Длительность измеряемого окна, сек.
        #[arg(long, default_value_t = 300)]
        duration_s: u64,
    },
    /// Отчёты (§8, §12): lint — валидация прогона; seal — сборка manifest.json по каталогу.
    Report {
        #[command(subcommand)]
        action: ReportAction,
    },
}

#[derive(Subcommand)]
enum CorpusAction {
    /// Проверить корпус. structural: схема/hex/границы/sha256. acceptance: + критерии §3.3.
    Verify {
        /// Каталог корпуса (по умолчанию tests/vectors).
        #[arg(long, default_value = "tests/vectors")]
        vectors_dir: PathBuf,
        /// structural | acceptance
        #[arg(long, default_value = "structural")]
        mode: String,
    },
}

#[derive(Subcommand)]
enum StandAction {
    /// Поднять стенд: pinned DUT + cover + наблюдатели; записывает env (CPU allocation, digests).
    Up {
        /// Разрешить поднять стенд с непоз pinning'ом cover (digest запишется в env).
        #[arg(long)]
        allow_unpinned: bool,
    },
    /// Остановить стенд (runs/ сохраняются).
    Down,
    /// Preflight: реализованные проверки PASS/FAIL; нереализованные — UNIMPLEMENTED.
    /// Успех (exit 0) только если все проверки реализованы и прошли.
    /// exit 2 = инфраструктура OK + есть UNIMPLEMENTED (--allow-unimplemented).
    Preflight {
        /// DUT для preflight: telemt|mtg|mtdd|cover-ref
        #[arg(long)]
        dut: String,
        /// Разрешить exit 2 при инфраструктурном pass с незакрытыми пунктами.
        #[arg(long)]
        allow_unimplemented: bool,
    },
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // CLI-структура, живёт до конца main — boxing не оправдан
enum ReportAction {
    /// Валидировать каталог прогона: manifest.json, host-метаданные, сырые улики, хеш-чейн.
    Lint {
        /// Каталог прогона runs/<run_id>.
        #[arg(long)]
        run_dir: PathBuf,
    },
    /// Собрать manifest.json по каталогу прогона (хеш-чейн по фактическим файлам).
    /// Идемпотентен: существующий manifest не перезаписывается.
    Seal {
        #[arg(long)]
        run_dir: PathBuf,
        /// telemt | mtg | mtdd | cover-ref
        #[arg(long)]
        dut: String,
        /// idle|messaging|messaging_hot|mixed_media|reconnect_storm|probe
        #[arg(long, default_value = "probe")]
        profile: String,
        #[arg(long, default_value_t = 0)]
        seed: u64,
        /// sha256 versions.lock (или явная метка "unpinned" для env-прогонов).
        #[arg(long, default_value = "unpinned")]
        versions_lock_sha256: String,
        #[arg(long, default_value = "unpinned")]
        sysctl_sha256: String,
        #[arg(long, default_value = "zero")]
        netem_client: String,
        #[arg(long, default_value = "zero")]
        netem_egress: String,
        /// Переопределение host.kernel (для не-Linux машин).
        #[arg(long, default_value = "")]
        host_kernel: String,
        /// Переопределение host.cpu.
        #[arg(long, default_value = "")]
        host_cpu: String,
        /// Переопределение host.runtime (по умолчанию "docker" на Linux).
        #[arg(long, default_value = "")]
        host_runtime: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Probe {
            host,
            port,
            secret_file,
            sni,
        } => {
            let python = std::env::var("MTEVIL_PYTHON").unwrap_or_else(|_| {
                if cfg!(windows) {
                    "python".into()
                } else {
                    "python3".into()
                }
            });
            let status = std::process::Command::new(python)
                .arg("crates/harness/stand/client-stub/protocol_probe.py")
                .args(["--host", &host, "--port", &port.to_string(), "--sni", &sni])
                .arg("--secret-file")
                .arg(secret_file)
                .status()?;
            anyhow::ensure!(
                status.success(),
                "P09 failed or Python probe dependencies are missing"
            );
            Ok(())
        }
        Command::Corpus { action } => match action {
            CorpusAction::Verify { vectors_dir, mode } => {
                corpus::verify(&vectors_dir, corpus::Mode::from_str(&mode)?)
            }
        },
        Command::Stand { action } => match action {
            StandAction::Up { allow_unpinned } => stand::up(allow_unpinned),
            StandAction::Down => stand::down(),
            StandAction::Preflight {
                dut,
                allow_unimplemented,
            } => {
                let code = stand::preflight(&dut, allow_unimplemented)?;
                std::process::exit(code);
            }
        },
        Command::Gen {
            profile,
            seed,
            duration_s,
        } => {
            anyhow::bail!(
                "generator: профиль={profile} seed={seed} duration={duration_s}s — каркас Phase 0; \
                 реализация — этап 4 §16 (docs/specs/phase-0.md §4). Контракт: \
                 детерминизм по seed, кадры из pcap-таблиц corpus'а, метрики drift. \
                 Инфраструктурный smoke использует client-stub (см. crates/harness/stand/)."
            )
        }
        Command::Report { action } => match action {
            ReportAction::Lint { run_dir } => report::lint(&run_dir),
            ReportAction::Seal {
                run_dir,
                dut,
                profile,
                seed,
                versions_lock_sha256,
                sysctl_sha256,
                netem_client,
                netem_egress,
                host_kernel,
                host_cpu,
                host_runtime,
            } => report::seal(report::SealParams {
                run_dir: &run_dir,
                dut: &dut,
                profile: &profile,
                seed,
                versions_lock_sha256: &versions_lock_sha256,
                sysctl_sha256: &sysctl_sha256,
                netem_client: &netem_client,
                netem_egress: &netem_egress,
                host: report::HostOverrides {
                    kernel: host_kernel,
                    cpu: host_cpu,
                    runtime: host_runtime,
                },
            }),
        },
    }
}
