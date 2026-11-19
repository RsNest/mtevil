# ADR-001: собственное ядро mtveil и ограниченный gate прототипа

- Статус: accepted по явному решению Руслана в чате 17.11.2026.
- Дата: 2026-11-17.
- Уточняет ADR-000 §1, §11.5, §13: предварительный выбор fork/new-core заменён
  продуктовым решением. ADR-000 как исторический baseline не переписывается.

Цель — собственная реализация совместимого MTProto-прокси. Превосходство над
telemt и неотличимость от браузера НЕ доказаны и не являются следствием решения.
Проверенный DE smoke `20261117T084609Z-de-protocol-smoke` подтвердил пригодность
клиента: FakeTLS HMAC, RSA/DH, зашифрованный ping через telemt. Он не проверяет mtveil.

Разрешён ограниченный прототип: один секрет, bounded ClientHello parser,
FakeTLS + padded intermediate/obfuscated2 + Direct к явно разрешённым DC,
byte relay на настоящий TLS cover для входов без валидного секрета.
Только тестовые экземпляры. Нельзя заменять рабочие сервисы этим бинарником.

До испытаний прототипа обязательны спецификация, тесты INV-01 (после SH нет
перехода на cover), ограничений входа, неверной аутентификации и сохранения
байтов cover. Перед тестом в Telegram Desktop — автоматический полный обмен
ключами и encrypted ping, затем обычный TLS/HTTP через cover на том же порту.

Stock-client wire corpus собирается параллельно; его отсутствие не выдаётся за
приёмку совместимости. Сравнительные бенчмарки, N>=5, chaos/soak, mmap replay,
ME-пул, горячие конфиги, multi-process upgrade, production hardening остаются
обязательствами следующих этапов, а не выполненными критериями Phase 0.

Prototype replay: bounded process-local cache, TTL 300 s, timestamp ±120 s.
Отступление от INV-02 (нет crash/upgrade persistence) явно принимается ТОЛЬКО
для этого тестового прототипа. Нельзя объявлять полную реализацию INV-02.
Ресурсные таймауты и bounded buffers не доказывают весь INV-03/INV-04/INV-07.

Gate прототипа: unit/integration tests, Windows/Linux build + clippy, synthetic
full MTProto auth + encrypted ping, настоящий TLS cover; Desktop smoke отмечается
отдельно. Никаких заявлений о статистическом сходстве до отдельного измерения.
