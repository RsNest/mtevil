# ADR-002: Режим Middle-End (ME) и рекламный тег (`ad_tag`)

- **Статус:** proposed
- **Дата:** 2026-11-22
- **Затрагивает:** INV-01, INV-03, INV-08, INV-10 · `crates/proto`, `crates/me-pool` (новый), `crates/data-plane`, `deploy/setup.py`
- **Суперсеидит:** —

## 1. Контекст

В `v0.2.0` `mtevil` поддерживает только прямое проксирование клиентского потока на Telegram DC (`direct` и `edge → egress` по `MTV2`/`MTV3`), без пула Middle-End (ME) и без рекламного тега (`ad_tag` от `@MTProxybot`).

Поддержка ME-режима нужна для:
1. Передачи `ad_tag` (16 байт / 32 hex-символа от `@MTProxybot`) через `RPC_PROXY_REQ` (`flags |= 0x08`, TL `extra`), чтобы операторы могли показывать спонсорский канал и получать статистику в `@MTProxybot`.
2. Мультиплексирования клиентских сессий поверх пула постоянных шифрованных (`AES-256-CBC`) TCP-соединений к ME-серверам из `https://core.telegram.org/getProxyConfig` (`proxy-multi.conf`) и `https://core.telegram.org/getProxySecret` (`proxy-secret`).

### Лицензионные ограничения и clean-room подход (0.1)
Проект `mtevil` распространяется под `MIT OR Apache-2.0`. Референсные реализации ME-протокола:
- `TelegramMessenger/MTProxy` — **GPLv2 (or later) + OpenSSL exemption** — **копирование кода запрещено**.
- `alexbers/mtprotoproxy` — **MIT** (совместима).
- `seriyps/mtproto_proxy` — **Apache-2.0** (совместима).
- `9seconds/mtg` — **MIT** (совместима).

Реализация в `mtevil` выполняется с нуля по спецификации wire-протокола и проверяется детерминированными векторами и живым спайком ([scripts/me_spike.py](../../scripts/me_spike.py)), который уже подтвердил полный обмен `getProxySecret` (128 B) + `getProxyConfig` (12 DC) → `RPC_NONCE` → `AES-256-CBC KDF` → `RPC_HANDSHAKE` → `RPC_PROXY_REQ(req_pq_multi)` → `RPC_PROXY_ANS(resPQ#05162463)` (`100 B`, `RTT = 16.7 ms` на DC 2).

---

## 2. Варианты архитектуры

### (а) ME в режиме `direct`

Клиентский вход (FakeTLS + `obfuscated2`, `proxy-secret`, `users.json`, `sni`) не меняется. После дешифровки `obfuscated2` `mtevil` извлекает MTProto-кадры клиентского транспорта (`padded-intermediate` `0xdd`, при необходимости `intermediate`/`abridged`) и мультиплексирует их через `crates/me-pool` в `RPC_PROXY_REQ` (с опциональным `ad_tag`), получая ответы через `RPC_PROXY_ANS` и перекодируя обратно в клиентский `obfuscated2` + FakeTLS.

- **Включение:** `me.enabled: false` по умолчанию (полная обратная совместимость `config.json`).
- **Кэш конфигурации Telegram:** `proxy-secret` и `proxy-multi.conf` скачиваются при старте и периодически обновляются (раз в 12–24 ч) с атомарным сохранением last-known-good копии в `/var/lib/mtevil-replay/me-cache/` (том `state` остаётся `:ro`, `ad_tag` хранится в `state` как секрет или в `config.json` без вывода в логи).

### (б) ME в split-режиме `edge → egress`

| Критерий | Вариант 1: ME только на `edge` | Вариант 2 (выбран): `edge` передаёт кадры по `MTV4`, ME ведёт `egress` |
|---|---|---|
| **Что видит `edge`** | Клиентский FakeTLS/`obfuscated2`, `users.json`, расшифрованный транспортный кадр MTProto, `proxy-secret`/`proxy-multi.conf`, `ad_tag`. | Клиентский FakeTLS/`obfuscated2`, `users.json`, расшифрованный транспортный кадр MTProto (внутренний MTProto остаётся E2E-шифрованным ключом клиента), `remote_ip:port`. Не требует доступа к `core.telegram.org` и ME-серверам. |
| **Что видит `egress`** | Не участвует в ME (либо вообще не используется). | `dc_id`, `remote_ip:port`, транспортные кадры MTProto, ME-пул, `proxy-secret`/`proxy-multi.conf`, `ad_tag`. Не видит клиентский FakeTLS и `users.json`. |
| **Доступность в блокируемой сети** | **Неработоспособен в РФ/блокируемых сетях:** `edge` не имеет прямого доступа к `core.telegram.org` и ME-серверам (подтверждено отказом `WinError 10060` в спайке 0.3). | **Работает в split-топологии:** весь доступ к `core.telegram.org` и ME-серверам идёт с зарубежного `egress`. |
| **Безопасность канала `edge ↔ egress`** | Не меняется. | `MTV4` сохраняет HMAC-SHA256 аутентификацию префейса `MTV3` (`timestamp ±30s`, `nonce`-replay, CIDR `egress_allow_from`), добавляет флаг режима `framed_me` + `remote_ip:port` + length-prefixed кадры с проверкой max-frame-size до аллокации (INV-08). |
| **Failover (`breaker`/`hedge`/`cooldown`)** | Нет failover между `egress`. | Полностью сохраняются `EgressHealth`, `egress_hedge_ms`, per-node адаптивный `per_try`, `DcAckTimeout` + F3b-эскалация. `egress` шлёт `EGRESS_ACK_OK` только если выбран живой ME-канал (или разрешённый Direct-fallback), иначе `EGRESS_ACK_ERR`. |
| **Таймауты и backpressure (INV-03)** | Локально на `edge`. | На `edge` сохраняются `handshake_timeout` и `idle_timeout`. Между `edge ↔ egress` и внутри `me-pool` — ограниченные каналы (`mpsc::channel(64)` на сессию) и лимит pending-кадров на ME-сокет. Медленный клиент не блокирует общий ME-сокет: при переполнении очереди сессии она закрывается через `RPC_CLOSE_EXT`, остальные сессии на том же ME-сокете продолжают работу. |
| **Обновление `v0.2 → v0.3`** | Не требует смены протокола. | Строго обратно совместимо: `egress v0.3` принимает `MTV2` (legacy), `MTV3` (direct stream) и `MTV4` (framed ME). Порядок обновления прежний: сначала `egress`, затем `edge`. Пока `me.enabled = false`, `edge` продолжает использовать `MTV3`. |

---

## 3. Анализ и политика Fallback (`ME → Direct`)

### Поведение при недоступности ME
Вводится явная настройка `me.fallback_to_direct: bool` (по умолчанию `true`):
1. **Сбой загрузки `getProxySecret`/`getProxyConfig` на старте:**
   - Используется last-known-good кэш из `/var/lib/mtevil-replay/me-cache/` (если есть и не повреждён).
   - Если кэша нет и `fallback_to_direct = true`: сервис стартует в Direct-режиме с предупреждением и метрикой `mtevil_me_config_refresh_errors_total`, продолжая фоновый ретрай с экспоненциальным backoff (30 с → 10 мин).
   - Если кэша нет и `fallback_to_direct = false` (strict ME): сервис стартует, но клиентские попытки для недоступных DC возвращают ошибку до появления валидного конфига ME (healthcheck процесса остаётся управляемым, процесс не падает в crash-loop).
2. **Падение всех ME-соединений для конкретного DC / пустой пул:**
   - Если `fallback_to_direct = true`: новые сессии для этого DC немедленно открываются в Direct (с инкрементом `mtevil_me_fallback_direct_total` и одноразовым лог-событием `me_fallback_direct`, предупреждающим, что fallback-сессии идут без `ad_tag`).
   - Если `fallback_to_direct = false`: `egress` возвращает `EGRESS_ACK_ERR` (в split `edge` пробует резервный `egress`), в `direct` сессия закрывается.
   - Фоновый менеджер пула переподключает ME-сокеты с backoff + jitter и автоматически возвращает новые сессии в ME после успешного `RPC_HANDSHAKE` + `RPC_PING`/`RPC_PONG`.
3. **Разрыв активной сессии при падении ME-сокета:**
   - Все клиентские сессии, мультиплексированные на упавшем ME-сокете, получают EOF/FIN (без зависания); Telegram-клиент автоматически переподключается и попадает на здоровый ME-сокет или Direct-fallback.

---

## 4. Решение

Приняты:
1. **В `direct`:** встроенный `crates/me-pool`, выключенный по умолчанию (`me.enabled = false`), с `fallback_to_direct = true` по умолчанию и last-known-good кэшем `proxy-secret` / `proxy-multi.conf` в томе `replay`.
2. **В split `edge → egress`:** **Вариант 2** — `edge` расшифровывает клиентский транспорт (`FakeTLS` + `obfuscated2`) и передаёт MTProto-кадры и `remote_ip:port` на `egress` по версионированному протоколу **`MTV4`**, а `egress` держит ME-пул, `ad_tag` и обновление конфигов с `core.telegram.org`. Протоколы `MTV2` и `MTV3` остаются полностью рабочими.

---

## 5. Спецификация тестов (0.4)

### 5.1. Детерминированные тесты на моках (в CI, без сети)
- **Криптография и фрейминг (`crates/me-pool`):**
  - Векторы KDF (`CLIENT`/`SERVER` AES-256-CBC key/IV), `pack_rpc_frame` / `CRC32`, 4-байтовый padding `0x00000004`, `tl_encode_bytes`, `ipv4_mapped_16`.
  - Полный mock ME-сервер на `127.0.0.1`: `RPC_NONCE` → `RPC_HANDSHAKE` → `RPC_PROXY_REQ` (без `ad_tag` и с 16-байтовым `ad_tag`, проверка `flags & 0x08` и `extra`) → `RPC_PROXY_ANS`, `RPC_SIMPLE_ACK`, `RPC_CLOSE_EXT`, `RPC_PING`/`RPC_PONG`.
  - Мультиплексирование: 50 параллельных `conn_id` поверх 1 ME-сокета, изоляция закрытия одной сессии (`RPC_CLOSE_EXT`) без влияния на остальные 49.
  - Backpressure (INV-03): медленный клиент с заполненным каналом `mpsc` отбрасывается (`RPC_CLOSE_EXT`), не блокируя чтение `RPC_PROXY_ANS` для остальных клиентов.
- **Конфиг и обратная совместимость:**
  - Старые `config.json` без секции `me` грузятся с `me.enabled = false`.
  - Валидация `ad_tag` (строго 32 hex-символа), `pool_size` (1..16), `refresh_interval_secs`, запрет неизвестных полей.
  - Маскирование `ad_tag` и `proxy-secret` в логах и `mtevilctl status`.
- **Протокол `MTV4` (`crates/proto`, `crates/data-plane`):**
  - Совместимость `MTV2`, `MTV3`, `MTV4` на одном `egress`; отклонение поддельного HMAC, replay `nonce`, skew > 30 с, oversize frame до аллокации (INV-08).

### 5.2. Проверки только на живом Telegram (ручные / `#[ignore]` / стенд)
- Загрузка актуальных `getProxySecret` и `proxy-multi.conf` с `core.telegram.org`.
- Живой handshake + `req_pq_multi` → `resPQ` через ME-серверы всех рабочих DC (`1..5`, медиа `-2/-4`).
- Проверка реального отображения спонсорского канала и учёта статистики в `@MTProxybot` при передаче зарегистрированного `ad_tag` (требует регистрации прокси оператором в `@MTProxybot`).

### 5.3. Chaos-сценарии (интеграционные с `tokio::time::pause` и mock ME)
1. **ME-узел недоступен (TCP refused / blackhole):** автоматический fallback на Direct (при `fallback_to_direct = true`) с 0 ошибок или `EGRESS_ACK_ERR` (при `fallback_to_direct = false`), восстановление пула после возврата ME-узла.
2. **Пул пуст / все ME-сокеты упали одновременно:** корректное закрытие активных сессий, отсутствие утечек задач/FD, отсутствие бесконечного tight-loop реконнекта (backoff + jitter).
3. **Смена конфигурации (`proxy-multi.conf` / `proxy-secret` refresh):** горячая замена пула (drain старых ME-сокетов, новые сессии идут на новые узлы без разрыва процесса); повреждённый ответ `core.telegram.org` не затирает last-known-good кэш.
4. **Медленный ACK / зависший ME-сокет:** `RPC_PING` таймаут или `handshake_timeout` помечает ME-сокет мёртвым, переподключает его и не вешает соседние пулы.

### 5.4. Fuzz-цели (`fuzz/fuzz_targets/`)
1. `fuzz_me_rpc_frame`: парсер расшифрованного RPC-фрейма (длина, padding `0x00000004`, `seq_no`, `CRC32`, `RPC_NONCE`/`RPC_HANDSHAKE`/`RPC_PROXY_ANS`/`RPC_CLOSE_EXT`/`RPC_SIMPLE_ACK`) — без паник и OOM.
2. `fuzz_me_proxy_conf`: парсер `proxy-multi.conf` — произвольные строки, комментарии, невалидные IP/порты/DC.
3. `fuzz_mtv4_preface_and_frame`: парсер префейса `MTV4` и фреймов `edge ↔ egress` — проверка границ до аллокации.

---

## 6. План фаз 1–5 (0.5)

| Фаза | Содержание | Оценка объёма | Критерии приёмки |
|---|---|---|---|
| **Фаза 1: `crates/me-pool`** | Clean-room ME-клиент: KDF, AES-256-CBC RPC framing, `RPC_NONCE`/`RPC_HANDSHAKE`/`RPC_PROXY_REQ`/`RPC_PROXY_ANS`/`RPC_CLOSE_EXT`/`RPC_PING`, парсер `proxy-multi.conf`, кэш на диске, пул с per-DC реконнектом и backpressure, 2 fuzz-таргета. | ~1200–1600 LOC Rust + тесты | Все mock- и chaos-тесты пула зелёные, 0 `unsafe`/`unwrap`/`expect`/`panic`, fuzz smoke 60s без сбоев, живой `#[ignore]` тест `req_pq_multi → resPQ` проходит. |
| **Фаза 2: Интеграция в `data-plane` (`direct`) + Fallback** | Конфиг `me.*` (default выключен), распаковка/упаковка `obfuscated2` кадров (`0xdd`), маршрутизация в `me-pool`, `fallback_to_direct`, метрики Prometheus (`mtevil_me_*`), лог-события без секретов/`ad_tag`. | ~600–900 LOC Rust + тесты | Старые `config.json` грузятся без изменений; ME в `direct` проходит e2e-тест и fallback-chaos; `clippy -D warnings` и workspace tests зелёные. |
| **Фаза 3: Split `edge → egress` (`MTV4`)** | Версионированный протокол `MTV4` в `crates/proto`, передача кадров и `remote_ip:port` от `edge` к `egress`, сохранение `MTV2`/`MTV3` и всех механизмов failover (`breaker`/`hedge`/`F3b`), fuzz-таргет `MTV4`. | ~500–800 LOC Rust + тесты | Смешанные версии (`egress v0.3` + `edge v0.2` по `MTV3`; `egress v0.3` + `edge v0.3` по `MTV4`) проходят тесты; failover с 2 `egress` и 0 ошибок. |
| **Фаза 4: Управление (`deploy/setup.py`, `mtevilctl`)** | Команды `mtevilctl adtag set/show/clear`, опция ME в мастере установки, отображение состояния ME-пула и режима (`ME` / `Direct fallback`) в `mtevilctl status`, работа под `state:ro` + `replay`-кэш. | ~400–600 LOC Python + тесты | Полный `deploy/run_tests.py` (`MTEVIL_REQUIRE_ALL_TESTS=1`, `skipped=0`) зелёный; `ad_tag` не попадает в логи/вывод в открытом виде. |
| **Фаза 5: Документация, живая проверка `@MTProxybot`, подготовка `v0.3.0-rc.1`** | Обновление `README.md`, `deploy/README.md`, `docs/failure-matrix.md`, `docs/evidence-log.md`; живая проверка с реальным `ad_tag` от `@MTProxybot` на тестовом стенде; A/B замер `direct` vs `ME`. | ~200–300 LOC docs + прогон стенда | Полный зелёный CI, подтверждена работа реального клиента Telegram + спонсорский канал `@MTProxybot` и корректный `rollback` на `v0.2.0`. |

---

## 7. Последствия и риски

- **Зависимости Rust (`Cargo.lock`):** в Фазе 1 потребуются проверенные MIT/Apache-2.0 крейты `md-5`, `sha-1`, `cbc`, `crc32fast` (проходят `cargo-deny` и `cargo-audit`; криптография не пишется вручную в продуктовом коде).
- **Риски:**
  - Изменение формата `proxy-multi.conf` или `proxy-secret` со стороны Telegram → митигация: строгая валидация перед заменой last-known-good кэша и автоматический `fallback_to_direct`.
  - Устаревание `proxy-secret` при долгой недоступности `core.telegram.org` → митигация: алерт в лог/метрики при возрасте кэша > 48 ч и fallback на Direct.
- **Триггеры ревизии ADR:** если Telegram прекратит поддержку `RPC_PROXY_REQ`/`ad_tag` для сторонних прокси или изменит транспорт ME на несовместимый протокол.
