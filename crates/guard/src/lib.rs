//! `mtveil-guard` — replay-таблица (tmpfs-mmap, robust mutex), suspects, shadow-ban, canary.
//!
//! **Статус: пуст.** Код — после ADR-001 и спеки `docs/specs/guard.md`.
//!
//! Контракт (ADR-000 INV-02, INV-04):
//! - таблица `/run/mtveil/replay.tbl`, N шардов (напр. 256), каждый шард — process-shared
//!   robust mutex; `check_and_insert` — одна критическая секция;
//! - ключ = canonical HMAC (32 Б), TTL 300 с; ленивое протухание + bounded sweep в control plane;
//! - duplicate → CoverRelay + метрика; saturated → sweep, при переполнении — CoverRelay новых CH;
//! - upgrade/crash: старый/новый процесс мапят один файл; reboot → честный рестарт с пустой
//!   таблицей, остаточный риск <120 с документируется (ADR-000 §4 INV-02);
//! - тесты-обязательства: барьер двух worker'ов (ровно один Accepted), кросс-процессность,
//!   смерть владельца мьютекса (`EOWNERDEAD` + recovery), насыщение.
