# tests/vectors — wire-корпус

Формат, источники и приёмка — [docs/specs/phase-0.md §3](../../docs/specs/phase-0.md).

- `index.json` — индекс: `{"version":1,"vectors":[{"id","file","sha256","class","transport"}]}`.
- Векторы — JSON по схеме §3.2 (records hex, expect по INV-01/INV-04).
- Приёмка: `cargo run -p mtevil-harness -- corpus verify`.
- `clients.lock` — версии стоковых клиентов, с которых сняты захваты.
- `pcap-derived/` — нормализованные таблицы кадров генератора (§4.3) + sha256.

До сборки корпуса каталог намеренно пуст — векторы не синтезируются «для вида»,
а фиксируются как обязательный артефакт Phase 0 (этап 3 §16).
