# tests/inv — тесты инвариантов

Правила ADR-000 §0/§14.2:

1. Каждый тест обязан ссылаться на `INV-xx` **в имени** (`#[test] fn inv02_replay_barrier_two_workers`)
   и на ID сбоя из [docs/failure-matrix.md](../../docs/failure-matrix.md), если покрывает строку матрицы.
2. PR без INV-проверки при затрагивании инварианта не принимается.
3. Изменение инварианта — только ADR + одновременное обновление тестов.

Каталог намеренно пуст на старте: тесты инвариантов пишутся вместе со спеками компонентов
(Spec → INV-check → тесты → код, ADR-000 §14.3) и не появляются раньше спецификаций.
Первые тесты здесь появятся вместе с `crates/guard`/`crates/proto` после ADR-001.

Планируемые семейства (якоря из ADR-000 §4, не реализация):

| Приоритет | Тест-обязательство | INV |
|---|---|---|
| 1 | барьер двух worker'ов с идентичным CH (ровно один Accepted) | INV-02 |
| 1 | порядок write/commit: revoke/overload между генерацией SH и флашем → cover | INV-01 |
| 1 | ошибка после коммита → drain/close, не cover | INV-01 |
| 2 | смерть владельца replay-мьютекса (EOWNERDEAD recovery) | INV-02 |
| 2 | chaos «все paused + ME blackhole» → освобождение ресурсов за ограниченное время | INV-03 |
| 2 | probe-сьют по классам INV-04 + сверка intent vs kernel RST | INV-04 |
| 3 | потеря writer'а / partial-write offset / FIFO под нагрузкой | INV-05 |
| 3 | падение на каждой стадии prepare; retire-ошибки; orphan-reconcile | INV-06 |
| 3 | chaos изоляции: flood control API + blocking-шторм (триггер ADR-002) | INV-07 |
| 3 | тесты логов/API на утечку секретов; fuzz парсеров | INV-08 |
