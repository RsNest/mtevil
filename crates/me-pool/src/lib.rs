//! `mtveil-me-pool` — ME-writer'ы (Dialing → Handshaking → Ready → Draining → Dead) и Direct.
//!
//! **Статус: пуст.** Код — после ADR-001 и спеки `docs/specs/me-pool.md`.
//!
//! Контрактные инварианты (ADR-000 §5.3/§5.4, INV-05, INV-03):
//! - клиент привязан ровно к одному writer'у на всю сессию; перепривязок нет;
//!   потеря writer'а → закрытие привязанных клиентов (`me_writer_lost`);
//! - per-client FIFO через mux; outbound FIFO по enqueue; частичная запись —
//!   точный byte-offset, без повторного шифрования;
//! - eviction по совокупности признаков (PONG просрочен + запросы без ответа),
//!   не чаще одного на DC за интервал; последний живой writer DC не выселяется;
//! - каждое ожидание имеет конечный deadline (ME blackhole → eviction deadline);
//! - ad_tag-политика по official MTProto + верификация векторами (§16.1 — открытый вопрос Phase 0).
