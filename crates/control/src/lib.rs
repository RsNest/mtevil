//! `mtveil-control` — control plane: epoch-конфиги, пользователи, localhost API, /metrics, lifecycle.
//!
//! **Статус: пуст.** Код — после ADR-001 и спеки `docs/specs/control.md`.
//!
//! Контракт (ADR-000 §3, INV-06, INV-07, INV-08):
//! - отдельный однопоточный runtime; bounded blocking-пул для DNS/файлов/cert/nft-helper;
//! - lifecycle prepare → commit → retire: fallible только в prepare (владельческие токены
//!   `PrepareSet`), после commit — никаких fallible-операций; retire асинхронен, ошибки
//!   логируются/ретраятся, reconcile против сирот;
//! - API: localhost + Bearer + scopes (admin/read/metrics); секреты one-time, никогда в логах;
//! - триггер ADR-002: если chaos «flood control API + шторм blocking-операций» ломает p99
//!   data plane — control plane выносится в отдельный процесс (тюнинг приоритетов — не решение).
