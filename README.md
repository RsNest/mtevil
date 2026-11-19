# mtveil

MTProto FakeTLS-прокси с внешним HTTPS-cover, поддержкой мульти-секретов, персистентного replay-кэша, неравномерной нарезкой `ServerHello` и схемой `edge -> egress` с failover.

## Быстрый старт (без сборки и `git clone`)

На Linux VPS (нужны Docker Engine, плагин Docker Compose и Python 3):

```bash
curl -fsSL https://github.com/RsNest/mtevil/releases/download/v0.1.0-alpha.2/install.sh -o install.sh
bash install.sh
```

Скрипт проверит Docker Compose и Python 3, скачает `setup.py` и готовый образ `ghcr.io/rsnest/mtevil:v0.1.0-alpha.2` и запустит интерактивный мастер без локальной сборки Rust.

## Вариант из исходников (`git clone`)

```bash
git clone https://github.com/RsNest/mtevil.git
cd mtevil
python3 deploy/setup.py
```

- Для одного зарубежного сервера выберите роль **`direct`** (по умолчанию).
- Для схемы РФ `edge` → зарубежный `egress` сначала запустите `python3 deploy/setup.py` с ролью **`egress`** на зарубежных узлах, затем с ролью **`edge`** на узле в РФ (если между ними policy-routed туннель вроде SharX/WireGuard — запускайте на `edge` с флагом `--network-host`).

Подробности, диагностика (`check-egress`), обновление и откат — в [deploy/README.md](deploy/README.md).

---

Тестовый Direct-релиз **0.1.0-alpha.1**: [запуск через Docker Compose](deploy/README.md).
Конфигурация проверяется до старта, секрет хранится отдельно от image/config,
предусмотрены лимиты ресурсов, перезапуск процесса и процедура отката.
Это alpha для ограниченного тестирования; production-готовность не заявляется.

MTProto proxy data plane с covert-обложкой (FakeTLS + внешний cover), ownership-моделью
ME-writer'ов и измеримым поведением при отказах. Цель — не «больше функций», а детерминированные
инварианты и честные, методологически подтверждённые гарантии.

## Иерархия документов

1. [docs/adr/000-architecture-baseline.md](docs/adr/000-architecture-baseline.md) — **baseline v1.3**, обязателен. Изменения — только через ADR.
2. [docs/specs/](docs/specs/) — спецификации компонентов, методики верификации.
3. Код.

**Текущее решение:** [ADR-001](docs/adr/001-own-core-prototype.md) разрешает
собственное тестовое ядро по сокращённому gate. Полный Phase 0 не объявляется
завершённым. Контракт прототипа: [prototype.md](docs/specs/prototype.md).

## Структура (§14.1 baseline)

```text
docs/adr/                  ADR-000 (baseline), ADR-001 (gate), ...
docs/specs/                спеки компонентов, failure-matrix, методики
crates/
  proto/                   чистые парсеры/кодеки, без I/O          [spec-first, после ADR-001]
  data-plane/              listener/demux/faketls/transport        [запрещён до ADR-001]
  me-pool/                 writer'ы, Direct                        [spec-first, после ADR-001]
  egress/                  upstreams, health, routing              [spec-first, после ADR-001]
  control/                 epoch-конфиги, users, API, metrics      [spec-first, после ADR-001]
  guard/                   replay (tmpfs robust-mutex), suspects   [spec-first, после ADR-001]
  harness/                 генератор, стенд, eBPF/nstat, отчёты    [Phase 0 — активная работа]
tests/vectors/             wire-векторы
tests/inv/                 тесты инвариантов (имена ссылаются на INV-xx)
```

## Процесс (§14.3)

`Spec → INV-check → тесты → код`. Каждый тест, защищающий инвариант, ссылается на `INV-xx`
в имени. PR без INV-проверки при затрагивании инварианта не принимается. Код конкурентов
не заимствуется до проверки лицензии (§15 baseline).

## Статус

- Phase 0 (baseline harness + wire-корпус + генератор + методики + бенчмарк конкурентов) — в работе.
- Gate: exit-критерии §11.5 baseline → ADR-001.

### Direct-прототип, 17.11.2026

Собственное ядро `mtveil` принимает FakeTLS, проверяет секрет/timestamp/replay,
преобразует obfuscated2 и пересылает MTProto в разрешённые DC. Неавторизованные
входы передаются byte relay на настоящий HTTPS-cover. Прототип прошёл полный
обмен ключами и encrypted ping, TLS cover HTTP 200 и ручной smoke Telegram
Desktop (отправка сообщений, обновления, медиа). Это не production-релиз и
не доказательство браузерной неотличимости. Replay-cache пока process-local.

Сборка: `cargo build --release --locked -p mtveil-data-plane`.
Пример тестового запуска (секрет — отдельный файл с 32 hex-символами):

```text
mtveil --listen 127.0.0.1:24443 --secret-file /path/to/test-secret --sni example.com --cover example.com:443 --dc 2=149.154.167.51:443
```

Для прямого теста padded intermediate включите `"enable_dd": true` в JSON или
передайте `--enable-dd` при ручном запуске. Тот же порт принимает `ee` и `dd`.
Команда `mtveil link --config config.json --server proxy.example.com --port 24443 --dd`
выдаёт отдельную ссылку для `dd`.

Проверка P09 из корня workspace:

```text
mtveil-harness probe --host 127.0.0.1 --port 24443 --secret-file /path/to/test-secret --sni example.com
```

P09 требует Python с `cryptography` и `Telethon`; пользовательский аккаунт/API
ключи не нужны, сессия не сохраняется. Интерпретатор можно задать переменной
`MTVEIL_PYTHON`. Этот отдельный тест не превращает полный preflight Phase 0 в PASS.
Wire-корпус стоковых клиентов и сравнительные/нагрузочные испытания ещё не завершены.
