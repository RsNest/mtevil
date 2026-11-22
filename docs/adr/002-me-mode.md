# ADR-002: Режим Middle-End (ME) и рекламный тег (`ad_tag`)

- **Статус:** accepted
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

Реализация в `mtevil` выполняется с нуля по спецификации wire-протокола и проверяется детерминированными векторами и живым спайком ([scripts/me_spike.py](../../scripts/me_spike.py)), который подтвердил полный обмен `getProxySecret` (128 B) + `getProxyConfig` (12 DC) → `RPC_NONCE` → `AES-256-CBC KDF` → `RPC_HANDSHAKE` → `RPC_PROXY_REQ(req_pq_multi)` → `RPC_PROXY_ANS(resPQ#05162463)` (`100 B`, `RTT = 16.7 ms` на DC 2).

### Криптографические зависимости (`md-5`, `sha1`, `cbc`, `crc32fast`)
В продуктовом крейте `crates/me-pool` используются стандартные MIT/Apache-2.0 крейты `md-5`, `sha1`, `cbc`, `crc32fast` (поверх уже входящего в workspace `aes`).
- **Зачем `MD5` и `SHA-1`:** они **не** используются для хэширования паролей, подписей, целостности файлов или клиентской аутентификации — они требуются исключительно в фиксированной формуле KDF протокола Telegram ME (`key = MD5(s[1:])[..12] || SHA1(s)`, `iv = MD5(s[2:])`) для совместимости с серверами Telegram.
- Все зависимости должны проходить `cargo deny check advisories licenses` и `cargo audit`.

---

## 2. Варианты архитектуры

### (а) ME в режиме `direct`

Клиентский вход (FakeTLS + `obfuscated2`, `proxy-secret`, `users.json`, `sni`) не меняется. После дешифровки `obfuscated2` `mtevil` извлекает MTProto-кадры клиентского транспорта (`padded-intermediate` `0xdd`, при необходимости `intermediate`/`abridged`) и мультиплексирует их через `crates/me-pool` в `RPC_PROXY_REQ` (с опциональным `ad_tag`), получая ответы через `RPC_PROXY_ANS` и перекодируя обратно в клиентский `obfuscated2` + FakeTLS.

- **Включение:** `me.enabled: false` по умолчанию (полная обратная совместимость `config.json`).
- **Кэш конфигурации Telegram:** `proxy-secret` и `proxy-multi.conf` скачиваются при старте и периодически обновляются (раз в 12–24 ч) с атомарным сохранением last-known-good копии в `/var/lib/mtevil-replay/me-cache/` (том `state` остаётся `:ro`).

### (б) ME в split-режиме `edge → egress`

| Критерий | Вариант 1: ME только на `edge` | Вариант 2 (выбран): `edge` передаёт кадры по `MTV4`, ME ведёт `egress` |
|---|---|---|
| **Что видит `edge`** | Клиентский FakeTLS/`obfuscated2`, `users.json`, расшифрованный транспортный кадр MTProto, `proxy-secret`/`proxy-multi.conf`, `ad_tag`. | Клиентский FakeTLS/`obfuscated2`, `users.json`, расшифрованный транспортный кадр MTProto (внутренний MTProto остаётся E2E-шифрованным ключом клиента). Не требует доступа к `core.telegram.org` и ME-серверам. |
| **Что видит `egress`** | Не участвует в ME (либо вообще не используется). | `dc_id`, транспортные кадры MTProto, ME-пул, `proxy-secret`/`proxy-multi.conf`, `ad_tag`, и клиентский `remote_ip:port` при `me.send_client_ip: true` (по умолчанию, как в официальном MTProxy; при экспериментальном `me.send_client_ip: false` передаётся `0.0.0.0:0`). **Клиентские IP на `egress` никогда не пишутся в логи.** Не видит клиентский FakeTLS и `users.json`. |
| **Доступность в блокируемой сети** | **Неработоспособен в РФ/блокируемых сетях:** `edge` не имеет прямого доступа к `core.telegram.org` и ME-серверам (подтверждено отказом `WinError 10060` в спайке 0.3). | **Работает в split-топологии:** весь доступ к `core.telegram.org` и ME-серверам идёт с зарубежного `egress`. |
| **Безопасность канала `edge ↔ egress`** | Не меняется. | `MTV4` сохраняет HMAC-SHA256 аутентификацию префейса `MTV3` (`timestamp ±30s`, `nonce`-replay, CIDR `egress_allow_from`), добавляет флаг режима `framed_me` + опциональный `remote_ip:port` + length-prefixed кадры с проверкой max-frame-size до аллокации (INV-08). |
| **Failover (`breaker`/`hedge`/`cooldown`)** | Нет failover между `egress`. | Полностью сохраняются `EgressHealth`, `egress_hedge_ms`, per-node адаптивный `per_try`, `DcAckTimeout` + F3b-эскалация. `egress` шлёт `EGRESS_ACK_OK` только если выбран живой ME-канал (или разрешённый Direct-fallback), иначе `EGRESS_ACK_ERR`. |
| **Таймауты и backpressure (INV-03)** | Локально на `edge`. | На `edge` сохраняются `handshake_timeout` и `idle_timeout`. Между `edge ↔ egress` и внутри `me-pool` — ограниченные каналы (`mpsc::channel(64)` на сессию) и лимит pending-кадров на ME-сокет. Медленный клиент не блокирует общий ME-сокет: при переполнении очереди сессии она закрывается через `RPC_CLOSE_EXT`, остальные сессии на том же ME-сокете продолжают работу. |
| **Обновление `v0.2 → v0.3`** | Не требует смены протокола. | Строго обратно совместимо: `egress v0.3` принимает `MTV2` (legacy), `MTV3` (direct stream) и `MTV4` (framed ME). Порядок обновления прежний: сначала `egress`, затем `edge`. Пока `me.enabled = false`, `edge` продолжает использовать `MTV3`. |

---

## 3. Приватность, NAT/Docker, `ad_tag` и политика Fallback

### 3.1. Приватность (`me.send_client_ip`)
- В протоколе ME пакет `RPC_PROXY_REQ` содержит поля `remote_ip` и `remote_port` — в отличие от Direct-режима, где Telegram видит только IP прокси, в ME-режиме по умолчанию Telegram (ME-сервер) получает реальный IP-адрес клиента (как в официальном MTProxy).
- **Эмпирическая проверка спайком (`scripts/me_spike.py --dc 2 --remote-ip 0.0.0.0 --remote-port 0`):** Telegram ME **принимает** нулевой адрес `0.0.0.0:0` на уровне `req_pq_multi → resPQ#05162463` (`100 B`, `RTT = 22.1 ms`), однако полная пользовательская сессия реального клиента Telegram (авторизация, чаты, медиа, `ad_tag`) с `0.0.0.0:0` ещё не проверялась.
- **Решение:** вводится явная настройка `me.send_client_ip: bool`:
  - **По умолчанию `true`** — отправляется реальный адрес клиента (`remote_ip:port`), как в официальном MTProxy.
  - **Значение `false` (`0.0.0.0:0`) — помечено «экспериментально»** до проверки реальной сессии реальным клиентом Telegram.
- **Split-правило:** на `egress` клиентский IP используется только в памяти для заполнения `RPC_PROXY_REQ` и **никогда не записывается в логи, метрики или файлы**.
- **Предупреждение для README и мастера установки:** при включении ME мастер и `README.md` обязаны явно предупреждать оператора о том, что при `me.send_client_ip: true` (по умолчанию) Telegram видит реальный IP клиента, а режим `me.send_client_ip: false` (`0.0.0.0:0`) является экспериментальным.

### 3.2. NAT и Docker (`me.public_ipv4`)
- В формуле KDF ME-протокола участвуют локальный IPv4 (`clt_ip`) и локальный порт (`clt_port`) TCP-сокета. Telegram ME подставляет в KDF тот публичный IPv4 и порт, с которого пришло соединение.
- **Эмпирическая проверка спайком в Docker bridge (NAT):**
  - Контейнер в Docker bridge **без** `--public-ipv4` (`clt_ip = 172.17.x.x`): **FAIL** (`EOF` на `RPC_HANDSHAKE` — несовпадение ключей KDF).
  - Контейнер в Docker bridge **с** `--public-ipv4 <публичный IPv4 хоста>`: **PASS** (`RPC_HANDSHAKE` + `RPC_PROXY_ANS` `resPQ#05162463`, `100 B`, `RTT = 26.2 ms`), поскольку Linux Docker MASQUERADE сохраняет исходный порт (1:1 port-preserving NAT).
- **Решение:** вводится параметр `me.public_ipv4: Option<Ipv4Addr>`:
  - По умолчанию `None` (автоопределение: если локальный IP сокета глобальный — используется он; если приватный, например в Docker bridge или за 1:1 NAT — автоопределение внешнего IPv4 или явное значение из `MTEVIL_PUBLIC_HOST` / `me.public_ipv4`).
  - Ручное задание `me.public_ipv4: "x.x.x.x"` всегда имеет приоритет (для серверов за 1:1 NAT / облачным EIP).
  - Ограничение: за симметричным NAT с перезаписью исходного порта (`clt_port`) KDF не совпадёт — в этом случае требуется `network_mode: host` или неперезаписывающий порт 1:1 NAT.

### 3.3. `ad_tag` и регистрация в `@MTProxybot`
- **Что регистрировать в `@MTProxybot` (`/newproxy`):**
  - **Режим `direct`:** публичный `IP:PORT` сервера `mtevil` и 32-hex секрет прокси (чистые 16 байт без префиксов `ee`/`dd`).
  - **Режим split `edge → egress`:** публичный `IP:PORT` сервера **`edge`** (именно его проверяет `@MTProxybot` как входную точку клиентов) и 32-hex клиентский секрет `edge`; полученный от `@MTProxybot` 32-hex `ad_tag` прописывается на узлах **`egress`** (которые формируют `RPC_PROXY_REQ` к Telegram ME).
- **Хранение и горячая перезагрузка `ad_tag`:**
  - Хранится в отдельном файле тома `state` (`/var/lib/mtevil/ad-tag`, права **`0600`**, владелец `10001:10001`), путь задаётся через `me.ad_tag_file` (default `None`).
  - В логи, метрики и вывод `mtevilctl status` сам `ad_tag` никогда не выводится (только статус `configured` / `disabled` или маскированный индикатор).
  - Перечитывается демоном по `mtime` (горячая перезагрузка **без рестарта контейнера**, аналогично `users.json`), запись через `mtevilctl adtag set/clear` выполняется через сервис `init` при `state:ro`.

### 3.4. Поведение при недоступности ME и Fallback (`ME → Direct`)
- Настройка `me.fallback_to_direct: bool` по умолчанию **`true`**.
- **При недоступности `getProxySecret`/`getProxyConfig` на старте:** используется last-known-good кэш из `/var/lib/mtevil-replay/me-cache/`. Если кэша нет и `fallback_to_direct = true`, сервис стартует в Direct и продолжает фоновый ретрай с backoff (`30 с → 10 мин`).
- **При падении всех ME-соединений для DC / пустом пуле:**
  - При `fallback_to_direct = true`: новые сессии немедленно уходят в Direct с метрикой `mtevil_me_fallback_direct_total` и событием `me_fallback_direct` (сессии в fallback идут без `ad_tag`). В `mtevilctl status` и `runtime-stats.json` явно отображается состояние **`ME degraded (fallback to Direct)`**.
  - При `fallback_to_direct = false` (strict ME): `egress` возвращает `EGRESS_ACK_ERR` (в split `edge` переключается на резервный `egress`), в `direct` сессия закрывается.
- Фоновый менеджер пула переподключает ME-сокеты с экспоненциальным backoff + jitter и автоматически возвращает новые сессии в ME после успешного `RPC_HANDSHAKE` + `RPC_PING`/`RPC_PONG`.

---

## 4. Решение

1. **В `direct`:** встроенный `crates/me-pool`, выключенный по умолчанию (`me.enabled = false`), явная настройка `me.send_client_ip = true` по умолчанию (как в официальном MTProxy; `false` / `0.0.0.0:0` помечено «экспериментально» до проверки реальным клиентом Telegram), `me.fallback_to_direct = true` (с индикацией `ME degraded` в `status`), `me.public_ipv4` (авто + ручной), `ad_tag` в отдельном файле `0600` с горячим перечитыванием без рестарта, кэш `proxy-secret`/`proxy-multi.conf` в томе `replay`.
2. **В split `edge → egress`:** **Вариант 2** — `edge` расшифровывает клиентский транспорт и передаёт MTProto-кадры на `egress` по версионированному протоколу **`MTV4`**, а `egress` ведёт ME-пул, `ad_tag` и `core.telegram.org` refresh (не логируя клиентские IP). `MTV2` и `MTV3` остаются рабочими; порядок обновления `v0.2 → v0.3` — сначала `egress`, потом `edge`.

---

## 5. Спецификация тестов (0.4)

### 5.1. Детерминированные тесты на моках (в CI, без сети)
- **Криптография и фрейминг (`crates/me-pool`):** векторы KDF (`CLIENT`/`SERVER`), `CRC32`, 4-байтовый padding `0x00000004`, `tl_encode_bytes`, `ipv4_mapped_16`, `proxy-multi.conf` парсер, last-known-good кэш на диске.
- **Mock ME-сервер:** `RPC_NONCE` → `RPC_HANDSHAKE` → `RPC_PROXY_REQ` (без `ad_tag`, с 16-байтовым `ad_tag`, с `0.0.0.0:0` и с явным `remote_ip`) → `RPC_PROXY_ANS`, `RPC_SIMPLE_ACK`, `RPC_CLOSE_EXT`, `RPC_PING`/`RPC_PONG`.
- **Мультиплексирование и INV-03:** 50 параллельных `conn_id` поверх 1 ME-сокета; изоляция `RPC_CLOSE_EXT`; медленный клиент с заполненным `mpsc` каналом отбрасывается без блокировки остальных сессий.
- **Конфиг и безопасность:** обратная совместимость старых `config.json`, валидация `ad_tag` (32 hex) и прав `0600`, отсутствие `ad_tag`/клиентских IP в логах.
- **`MTV4`:** совместимость `MTV2`/`MTV3`/`MTV4` на одном `egress`, HMAC/replay/skew/oversize-до-аллокации.

### 5.2. Проверки только на живом Telegram (`#[ignore]` / стенд)
- Загрузка `getProxySecret`/`getProxyConfig`, живой `req_pq_multi → resPQ` через ME (включая `0.0.0.0:0` и Docker bridge с `me.public_ipv4`).
- Реальный `ad_tag` и отображение спонсорского канала в клиенте Telegram после регистрации тестового прокси в `@MTProxybot`.

### 5.3. Chaos-сценарии (`tokio::time::pause` + mock ME)
1. ME-узел недоступен (refused / blackhole) → fallback на Direct (`fallback_to_direct=true`) или `EGRESS_ACK_ERR` (`false`) и возврат после восстановления.
2. Пул пуст / одновременный обрыв всех ME-сокетов → чистое закрытие сессий, отсутствие утечек FD/задач, backoff + jitter.
3. Обновление `proxy-multi.conf` / `proxy-secret` → drain старых ME-сокетов, битый ответ не затирает last-known-good кэш.
4. Медленный ACK / зависший ME-сокет → таймаут `RPC_PING` / handshake переводит сокет в реконнект без блокировки других DC.

### 5.4. Fuzz-цели (`fuzz/fuzz_targets/`)
1. `fuzz_me_rpc_frame` — парсер расшифрованных RPC-фреймов и opcodes (`RPC_NONCE`/`RPC_HANDSHAKE`/`RPC_PROXY_ANS`/`RPC_CLOSE_EXT`/`RPC_SIMPLE_ACK`/`RPC_PONG`).
2. `fuzz_me_proxy_conf` — парсер `proxy-multi.conf`.
3. `fuzz_mtv4_preface_and_frame` (в Фазе 3) — парсер префейса и кадров `MTV4`.

---

## 6. План фаз 1–5 (0.5)

| Фаза | Содержание | Оценка объёма | Критерии приёмки |
|---|---|---|---|
| **Фаза 1: `crates/me-pool`** | Clean-room ME-клиент: KDF (`md-5`, `sha1`, `cbc`), RPC framing (`crc32fast`), `RPC_NONCE`/`RPC_HANDSHAKE`/`RPC_PROXY_REQ`/`RPC_PROXY_ANS`/`RPC_CLOSE_EXT`/`RPC_PING`, парсер `proxy-multi.conf`, last-known-good кэш, пул с реконнектом/backoff/jitter и backpressure, mock ME-сервер, 2 fuzz-таргета, живой `#[ignore]` тест `req_pq_multi → resPQ`. | ~1200–1600 LOC Rust | Все mock/chaos-тесты зелёные, 0 `unsafe`/`unwrap`/`expect`/`panic`, `cargo-deny`/`cargo-audit` и fuzz smoke 60s зелёные, живой `#[ignore]` тест проходит. |
| **Фаза 2: Интеграция в `data-plane` (`direct`) + Fallback** | Конфиг `me.*` (default выключен), `ad_tag_file` (`0600`, hot-reload), `obfuscated2` фрейминг, маршрутизация в `me-pool`, `fallback_to_direct`, `ME degraded` в `runtime-stats.json`, метрики `mtevil_me_*`. | ~600–900 LOC Rust | Старые `config.json` грузятся без изменений; ME в `direct` + fallback-chaos зелёные; `clippy -D warnings` и workspace tests зелёные. |
| **Фаза 3: Split `edge → egress` (`MTV4`)** | `MTV4` в `crates/proto`, передача кадров + опционального `remote_ip:port` (`me.send_client_ip`, без логирования IP на `egress`), сохранение `MTV2`/`MTV3` и failover, fuzz-таргет `MTV4`. | ~500–800 LOC Rust | Смешанные версии `v0.2`/`v0.3` и failover с 2 `egress` проходят без ошибок. |
| **Фаза 4: Управление (`deploy/setup.py`, `mtevilctl`)** | `mtevilctl adtag set/show/clear` (`0600` через `init`), опция ME и предупреждение приватности в мастере, `ME degraded` в `mtevilctl status`. | ~400–600 LOC Python | `deploy/run_tests.py` (`MTEVIL_REQUIRE_ALL_TESTS=1`, `skipped=0`) зелёный; `ad_tag` не попадает в логи/вывод. |
| **Фаза 5: Документация, живая проверка `@MTProxybot`, подготовка `v0.3.0-rc.1`** | `README.md`, `deploy/README.md`, `docs/failure-matrix.md`, `docs/evidence-log.md`; живая проверка с `ad_tag` от `@MTProxybot` и `rollback` на `v0.2.0`. | ~200–300 LOC docs | Полный зелёный CI, подтверждена работа Telegram-клиента + спонсорский канал + откат. |
