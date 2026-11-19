//! `mtveil-egress` — egress plane: direct/socks5/interface/bind + scopes, health, `me_nat_ip`.
//!
//! **Статус: пуст.** Код — после ADR-001 и спеки `docs/specs/egress.md`.
//!
//! Контракт (ADR-000 §3, §7): изолированные пулы; сбой/перегрузка egress-health
//! не деградирует установленные MTProto-сессии (INV-07); upstream fail — новые conn
//! на здоровый маршрут, старые дренируются (F-23/F-24); DNS и прочие blocking-операции —
//! только в bounded `spawn_blocking`, никогда на data-потоках.
