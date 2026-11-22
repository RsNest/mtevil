# Развёртывание и эксплуатация mtevil

Нужен Linux-сервер (`x86_64`) с публичным IPv4, Docker Engine с плагином Docker Compose v2, исходящим TCP-доступом к Telegram DC и выбранному HTTPS-cover. Проверенная область: Linux/IPv4 для режимов `direct` и `edge → egress` (основной + резервный выход). Сквозная работа по IPv6 не проверялась.

## Первый запуск

На сервере, в каталоге исходников mtevil, в Bash:

```bash
docker compose -f deploy/compose.yaml build
docker compose -f deploy/compose.yaml --profile tools run --rm init
docker compose -f deploy/compose.yaml run --rm --no-deps mtevil --config /etc/mtevil/config.json --check-config
docker compose -f deploy/compose.yaml up -d mtevil
docker compose -f deploy/compose.yaml ps
```

По умолчанию порт доступен только на `127.0.0.1:24443`. Для первого smoke
используйте SSH-туннель. `healthy` означает, что listener доступен внутри
контейнера; работоспособность DC этим healthcheck не проверяется. Docker
сам по себе не перезапускает контейнер только из-за статуса `unhealthy`.
Падение процесса обрабатывает `restart: unless-stopped`.

Секрет генерируется внутри именованного тома `state`, не печатается и не
включается в конфиг/image. Повторный `init` завершается ошибкой, сохраняя
прежний секрет. Обычная остановка/пересоздание контейнера не меняет ссылку.
Процесс работает UID/GID 10001, без capabilities, с read-only rootfs и лимитами.
При старте процесс читает `RLIMIT_NOFILE` (`/proc/self/limits`), ограничивает
эффективный лимит сессий формулой `effective_max = min(max_connections, (nofile - 128) / 2)`
(логируя оба значения в событии `startup` и завершаясь с ошибкой при `effective_max < 16`),
а мастер `deploy/setup.py` выставляет в `compose.yaml` `ulimits.nofile = max(4096, max_connections * 2 + 512)`.

## Публичный порт и ссылка

Сначала проверьте, что выбранный порт свободен и на сервере нет конфликтующего
NAT/прокси. На действующей ноде не используйте занятые 443/8443.
После проверки задайте адрес/порт публикации; например для отдельного сервера:

```bash
MTEVIL_BIND=0.0.0.0 MTEVIL_PORT=443 docker compose -f deploy/compose.yaml up -d mtevil
docker compose -f deploy/compose.yaml exec mtevil mtevil link --config /etc/mtevil/config.json --server YOUR_SERVER_IP --port 443
```

Команда `link` намеренно раскрывает секрет в ссылке — выдавайте её только
предназначенным тестировщикам. Для повторных deploy сохраните MTEVIL_BIND/PORT
в локальном `deploy/.env` (этот файл не включается в git/build context).
Шаблон — `deploy/.env.example`. Compose читает `.env` рядом с выбранным
Compose-файлом; при необходимости укажите его явно через `--env-file`
([документация Docker](https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/)).
Firewall и маршрутизацию пакет не меняет; правила доступа настраиваются отдельно.
Docker-публикация портов взаимодействует с firewall хоста: доступ проверяйте
снаружи после запуска, не полагайтесь только на наличие правила UFW.

Настройки — `deploy/config.json`. `sni` должен соответствовать имени настоящего
HTTPS-cover; пример использует `example.com`. Перед изменением проверьте
доступность cover с сервера. Адрес `cover` резолвится фоновым `CoverResolver` с TTL-кэшем (`cover_dns_ttl_secs`, по умолчанию `60 с`) и сохранением `last-known-good` при сбоях/таймаутах DNS (без блокирующих DNS-запросов на data-потоках, метрика и событие `cover_dns_fail`). При смене `SNI` через `mtevilctl sni` или мастер
предыдущие домены сохраняются в `/var/lib/mtevil/allowed-sni.txt` внутри тома
`state`, поэтому прежние ссылки клиентов продолжают работать; новые ссылки
формируются уже с новым `SNI`. Изменение самого секрета требует новых ссылок.

## Диагностика и остановка

```bash
docker compose -f deploy/compose.yaml logs --tail=100 mtevil
docker compose -f deploy/compose.yaml stats --no-stream mtevil
docker compose -f deploy/compose.yaml stop mtevil
docker compose -f deploy/compose.yaml down
```

SIGTERM прекращает приём, затем даёт сессиям drain_timeout_secs (5 с по умолчанию).
Ошибки `accept()` классифицируются: транзиентные (`ECONNABORTED`/`ECONNRESET`/`EINTR`/`EAGAIN`) игнорируются сразу, ресурсные (`EMFILE`/`ENFILE`/`ENOBUFS`/`ENOMEM`) обрабатываются с экспоненциальным backoff `10 мс .. 1 с` и rate-limited событием `accept_error` (1/с на вид) без завершения процесса и без разрыва активных сессий.
Счётчик TCP-ретрансмиссий (`TCP_INFO`) в `upload()`/`download()`/`counted_copy()` опрашивается не на каждый пакет, а раз в `1 с` на сессию и при её закрытии; детальная покадровая трассировка `timeline.mark` выключена по умолчанию и включается флагом `diagnostics: true` (`--diagnostics`).
Опциональный Prometheus-эндпоинт `/metrics` включается через `metrics_listen` (`--metrics-listen`, строго loopback `127.0.0.1` / `::1`, выключен по умолчанию) и отдаёт в отдельной задаче tokio метрики `mtevil_active_sessions`, `mtevil_accept_errors_total{kind}`, `mtevil_breaker_state{node}`, `mtevil_egress_failover_total`, `mtevil_hedge_*`, `mtevil_cover_rejected_total`, `mtevil_replay_full_total`, `mtevil_replay_flush_failed_total`, `mtevil_forced_close_total`, `mtevil_fd_used`, `mtevil_fd_limit`.
Оставшиеся сессии закрываются; клиентам потребуется reconnect. Секрет остаётся
в томе. `down -v` удаляет том и секрет — для обычной остановки его не используйте.
Перед удалением тома обеспечьте защищённую резервную копию секрета.

## Обновление и откат

Перед изменением исходников сохраните image текущей версии под отдельным тегом:

```bash
docker image tag mtevil:0.1.0-alpha.1 mtevil:rollback
```

Сохраните копию config.json. Соберите новую версию, выполните `--check-config`,
затем `up -d mtevil`. Для отката восстановите совместимый config.json и выполните:

```bash
MTEVIL_IMAGE=mtevil:rollback docker compose -f deploy/compose.yaml up -d --no-build mtevil
```

При откате используйте прежние MTEVIL_BIND/PORT. Том секрета не удаляйте.
Обновление перезапускает единственный процесс: zero-downtime здесь не обещается,
а replay-кэш при заданном `replay_file` (`/var/lib/mtevil-replay/replay.bin` в отдельном rw-томе `replay` с узкими правами `0700`, тогда как том `state` с секретами, `users.json` и `allowed-sni.txt` смонтирован `:ro`, а корневая ФС контейнера `read_only: true`) атомарно сбрасывается каждые 5 с и при остановке (`tmp + fsync + rename`), переживает рестарт и `docker compose up -d` после обновления, а при повреждении файла переинициализируется с пустой таблицей без падения старта (`replay_load_status` и `replay_loaded_entries` фиксируются в событии `startup`, ошибки записи учитываются в метрике и событии `replay_flush_failed`). Базовые образы закреплены digest'ами;
байт-идентичность сборки и registry publication пока не заявляются.

Пакет проверен на Linux/amd64. На `direct` и `egress` список резервных и медиа-кандидатов DC конфигурируется через `dc_media_override` (по умолчанию содержит штатные медиа-IP Telegram для `2`, `-2`, `4`, `-4`), а раз в `dc_probe_interval_secs` (`60 с` по умолчанию, `0` = выкл) выполняется фоновая самопроверка TCP-достижимости DC (метрики `dc_self_check_ok` / `dc_self_check_failed`, событие `dc_self_check` без влияния на маршрутизацию клиентов). Прикладная проверка Telegram DC — отдельная
команда `mtevil-harness probe`, она требует тестового секрета и Python-клиента.
Перед выдачей ссылки тестировщикам выполните её либо ручную проверку настоящим
Telegram с отправкой и загрузкой медиа. Наличие `healthy` этого не заменяет.

---

## Интерактивный мастер установки (Direct / Egress / Edge)

Из корня репозитория на Linux VPS (требуются Docker Engine и плагин Docker Compose):

```bash
python3 deploy/setup.py
```

Режим мастера можно выбрать явно через `--mode` (флаг также пробрасывается через `install.sh`):

```bash
bash install.sh --mode simple    # Простая установка на один VPS (direct)
bash install.sh --mode advanced  # Расширенная настройка (ручные параметры, direct / edge / egress)
```

Если `edge` ходит к `egress` по policy-routed mesh/VPN-туннелю (например, SharX или WireGuard), при котором трафик работает с хоста, но теряется из Docker bridge, включите сетевой режим `host` в расширенной настройке или передайте `--network-host`:

```bash
python3 deploy/setup.py --mode advanced --network-host
```

Мастер сохраняет файлы развёртывания в `deploy/wizard/` (или `~/mtevil` при запуске через `install.sh`: `compose.yaml`, `config.json`, `.env`), не затрагивая ручной `deploy/compose.yaml`. Перед перезаписью существующего комплекта мастер запрашивает подтверждение, подставляет текущие значения по умолчанию (включая `network_mode: host`), проверяет конфиг в кандидатных файлах (`--check-config`, TLS-проверка HTTPS-cover с нужным `SNI` и `check-egress`), а прежние файлы сохраняет как `*.bak`. Существующий том `state` (секреты, пользователи и токены `MTV2`) сохраняется без перезаписи.

### Режимы мастера

- **Простая установка (`--mode simple`, по умолчанию):** разворачивает `direct` на одном VPS. Автоматически определяет публичный IPv4 и проверяет доступность порта `443` (при конфликте предлагает свободный порт), затем показывает один экран подтверждения с возможностью перейти в расширенный режим (`a`) или отменить (`n`). В конце выводит ссылку `t.me/proxy` на отдельной строке, каталог установки и команду `status`.
- **Расширенная настройка (`--mode advanced`):** пошаговая настройка с показом текущих значений по умолчанию в скобках:
  - **Шаг 1. Роль сервера:** `direct`, `edge` или `egress` (можно зафиксировать через `--role`).
  - **Шаг 2. Сеть и адрес:** публичный адрес/домен (или туннельный IP для `egress`), TCP-порт, IP привязки на хосте и переключение `bridge` / `host` (`--network-host`).
  - **Шаг 3. Маскировка (HTTPS-cover):** домен `SNI`, адрес `cover` (`host:port`) и опциональная сверка DNS-записей `A`/`AAAA` (для `direct` и `edge`).
  - **Шаг 4. Узлы egress и отказоустойчивость:** список `egress_upstreams` (`IP:port`), резервные узлы и стратегия `ordered` / `round-robin` (для `edge`).
  - Перед применением выводится сводка всех параметров (без раскрытия секретов и токенов) и запрашивается подтверждение.

### Поддерживаемые роли

1. **`direct` (один зарубежный VPS):**
   - Подходит для простой установки (2 шага при наличии публичного IPv4 и свободного порта `443`) или для ручной настройки IP привязки, SNI/cover и `--network-host` в расширенном режиме.
   - Генерирует секрет в томе `state`, проверяет конфиг (`--check-config`) и HTTPS-cover, запускает контейнер и выводит ссылку `t.me/proxy`.
2. **`egress` (зарубежный сервер выхода, настраивается до `edge` в расширенном режиме):**
   - Запрашивает локальный туннельный IP и порт (по умолчанию `29443`) — порт публикуется строго на этом IP, а не на `0.0.0.0`.
   - На первом узле генерирует 16-байтовый токен `MTV2` (показывается только по явному запросу); на резервных узлах принимает тот же токен через скрытый ввод.
   - Выводит `IP:PORT`, команду безопасного чтения токена и следующий шаг для `edge`.
3. **`edge` (входной сервер, настраивается в расширенном режиме):**
   - Запрашивает публичный адрес/порт, IP привязки, сетевой режим, SNI/cover, список `egress_upstreams` в порядке приоритета, стратегию (`ordered` / `round-robin`) и общий токен `MTV2` (скрытый ввод).
   - Перед запуском выполняет `mtevil check-egress --config /etc/mtevil/config.json --dc 2` из сетевого контекста edge-контейнера (отдельно показывает TCP-доступность, проверку токена и связность до Telegram DC).

### Туннели (SharX, WireGuard, AmneziaWG) и безопасность

- Мастер **не настраивает** туннели, маршруты и firewall — поднимите их заранее.
- На `egress` указывайте именно внутренний IP интерфейса туннеля:
  - **SharX:** IP mesh-интерфейса (например, `10.203.0.x`), слушающего на данной ноде.
  - **WireGuard / AmneziaWG:** локальный IP `wg*`/`awg*`-интерфейса (например, `10.250.x.y`).
- Для отказоустойчивости маршруты от `edge` к основному и резервному `egress` должны идти по **независимым** туннелям/путям.
- **Важно:** между `edge` и `egress` по умолчанию используется протокол `MTV3` (`magic | dc | timestamp | nonce | HMAC-SHA256(token, magic||dc||timestamp||nonce||dc_header)` с constant-time проверкой, окном `±30 с` и replay-кэшем `nonce`), при этом `egress` по умолчанию принимает и `MTV2` (`egress_accept_legacy = true`) для плавного обновления. При включённом режиме Middle-End (`me.enabled = true`) между `edge` и `egress` используется протокол `MTV4` с поддержкой `ad_tag`, фреймингом и отдельным cooldown `MTV4` (`30 с`) на случай, если часть узлов `egress` ещё на `v0.2.0` (трафик прозрачно переходит на `MTV3` Direct при `fallback_to_direct = true`, без блокировки узла для Direct). При обновлении схемы `edge → egress` **всегда обновляйте сначала все узлы `egress` (резервный → основной), затем `edge`**. На `egress` дополнительно поддерживаются список разрешённых CIDR источников (`egress_allow_from`, по умолчанию пусто), лимит неудачных попыток на IP в 60-секундном скользящем окне (`egress_max_failed_per_ip`, по умолчанию `16`), отдельный лимит одновременных незавершённых handshake и предупреждение `egress_public_listen_warning` при привязке не к loopback/приватному адресу. Шифрование канала между `edge` и `egress` обеспечивает сам туннель (SharX / WG / AWG).

### Режим Middle-End (ME), `ad_tag`, приватность и NAT/bridge

- По умолчанию `me.enabled = false`; существующие конфиги работают в режиме Direct без изменений.
- В расширенном режиме мастера (`mtevilctl setup` / `deploy/setup.py --mode advanced`) можно включить ME (`direct`, `egress`, `edge`), задать `me.public_ipv4` (обязателен за 1:1 NAT и в Docker `bridge`), `me.pool_size` (по умолчанию `2`), `me.fallback_to_direct` (`true`) и `me.send_client_ip` (`true`).
- **Рекламный тег (`ad_tag`, 32 hex из `@MTProxybot`):** управляйте им через `mtevilctl adtag set`, `show`, `clear`. **Рекомендуется запускать `mtevilctl adtag set` без аргумента** (скрытый ввод в терминале или через `stdin`), чтобы не оставлять тег в истории shell. Файл записывается в том `state` с правами `0600`, владельцем `10001:10001` и проверкой чтения от UID `10001`; демон перечитывает его автоматически каждые `2 с` без перезапуска контейнера.
- **Приватность:** при `me.send_client_ip = true` (по умолчанию) Telegram получает реальный IPv4 клиента в `RPC_PROXY_REQ` (при включённом `proxy_protocol` — из PROXY protocol v2; для IPv6-клиентов передаётся `0.0.0.0:0`). В split-схеме передача IP клиента активна только при `send_client_ip = true` на обоих узлах (AND-логика); на `egress` клиентский IP не логируется. Значение `me.send_client_ip = false` (`0.0.0.0:0`) помечено как экспериментальное до проверки полной сессии реальным клиентом Telegram.
- **Статус и откат:** `mtevilctl status` показывает состояние ME-пула, статус `ad_tag` (значение маскируется) и предупреждение, если ME включён на `edge` (напоминание включить ME и обновить все `egress`). При `mtevilctl rollback` или `mtevilctl update --version v0.2.0` несовместимый блок `me` автоматически вырезается из `config.json` с сохранением резервной копии `config.json.pre-me-downgrade` (`0600`). Подробная инструкция ручной проверки ME — [docs/me-manual-test.md](../docs/me-manual-test.md).

### Что происходит при сбое egress и оповещения (`edge-alerts.jsonl`)

- Активные сессии на упавшем `egress` могут оборваться.
- Пользователь на клиенте Telegram видит кратковременное «Подключение…» — менять ссылку не нужно: клиент переподключается на тот же `edge`, а `edge` для новых соединений выбирает живой резервный `egress` (при отказе TCP, записи префикса, таймауте ACK или отрицательном ACK). Если все узлы `egress` одновременно оказались в cooldown, `edge` работает в режиме **fail-open**: выполняет принудительную пробу узла с ближайшим сроком окончания cooldown (с защитой от шторма — не более одной параллельной пробы на узел), поэтому при восстановлении связи трафик поднимается сразу, без 15-секундной паузы.
- События смены состояния пишутся в `/var/lib/mtevil/edge-alerts.jsonl` (и при заданном `alert_webhook_url` отправляются вебхуком) строго **один раз на смену состояния**:
  - В режиме **`ordered`**: `primary_ok` → `failover_backup` (основной недоступен, трафик пошёл через резерв) → `all_down` (недоступны все выходы) → `primary_ok` (основной восстановился после окончания cooldown; длительность cooldown настраивается через `egress_cooldown_base_ms` = `3000` мс по умолчанию и `egress_cooldown_max_ms` = `60000` мс с экспоненциальным ростом `×2` за каждый подряд сбой, jitter `±20%` и сбросом на успехе; кроме того, если основной узел не прислал ACK за `egress_hedge_ms` = `400` мс по умолчанию, `0` = выкл, параллельно стартует hedged-попытка на резервный узел — не более одного хеджа на соединение, метрики `hedge_started` и `hedge_won_by_backup`).
  - В режиме **`round-robin`**: штатное чередование соединений между здоровыми узлами `egress` **не вызывает оповещений**. Circuit breaker (`EgressHealth`) активен и в `round-robin`: отказавший узел переводится в cooldown и пропускается новыми соединениями с сохранением RR-смещения. Состояние строится по доступности узлов: `primary_ok` (все узлы доступны) → `degraded` (часть узлов недоступна, указано число здоровых из общего числа) → `all_down` (все узлы недоступны) → `primary_ok` (все узлы снова успешно обслужили соединения).
- **Как обнаруживается смена состояния:** `edge` обнаруживает сбои как на входящих клиентских подключениях, так и с помощью фонового пробинга каждого `egress` с ротацией по DC (`2, 4, -2, -4`). В штатном состоянии период проверки составляет `egress_probe_interval_secs` (`30 с` по умолчанию), а пока хотя бы один узел недоступен — ускоряется до `egress_probe_degraded_interval_secs` (`5 с` по умолчанию). Фоновая проба напрямую управляет circuit breaker: ставит узел в cooldown при сбое и снимает cooldown при восстановлении (failback происходит без жертвования живым клиентом), а оповещения подтверждаются двумя замерами подряд.

### Канал релизов и обновление (`mtevilctl`)

Для установок, созданных мастером, используйте `mtevilctl` (или `python3 deploy/setup.py <команда> --dir <путь>`):

```bash
mtevilctl status                 # Версия, роль, SNI, статус контейнера, uptime и доступная версия для отката
mtevilctl link                   # Показать текущую ссылку для подключения (--sni <домен>, --user <имя>, --all)
mtevilctl sni [домен]            # Сменить основной SNI с сохранением работы прежних ссылок (/var/lib/mtevil/allowed-sni.txt)
mtevilctl user add <имя>         # Добавить пользователя и вывести его ссылку (user list / user del <имя>)
mtevilctl adtag set              # Задать рекламный тег ME (@MTProxybot) скрытым вводом (без истории shell)
mtevilctl adtag show             # Показать статус рекламного тега ME (значение маскируется)
mtevilctl adtag clear            # Удалить рекламный тег ME
mtevilctl setup                  # Запустить интерактивный мастер перенастройки текущей установки (reconfigure)
mtevilctl update                 # Обновить до свежего стабильного релиза (с re-exec, проверкой Telegram и автооткатом)
mtevilctl update --prerelease    # Обновить с учётом предварительных релизов (alpha/beta/rc)
mtevilctl update --version v0.2.0  # Установить конкретный тег (при понижении до v0.2.0 блок me вырезается с бэкапом)
mtevilctl rollback               # Откатить к предыдущему рабочему образу и конфигу локально (без интернета)
mtevilctl traffic                # Активные сессии, байты по направлениям/участкам и период счётчиков
mtevilctl traffic --live         # Обновление раз в секунду: скорость приёма/отдачи, отключения, ретрансмиссии TCP
mtevilctl traf --live            # Короткий псевдоним для traffic
mtevilctl --help                 # Справка и примеры на русском языке
```

По умолчанию и `deploy/install.sh`, и `mtevilctl update` работают в канале `MTEVIL_CHANNEL=stable` и выбирают только стабильные SemVer-теги (`vX.Y.Z`), даже если на GitHub Latest помечен предварительный тег. Если стабильных релизов ещё нет, выводится подсказка с явными вариантами установки предварительной версии (`MTEVIL_CHANNEL=prerelease`, `--prerelease` или `MTEVIL_VERSION=<тег>`).

При установке и обновлении проверяются SHA-256 файлов по `SHA256SUMS` из релиза.
Релизы до `v0.1.1` включительно поддерживаются без этого файла, если сервер вернул HTTP 404.
При несовпадении хэша установка или обновление останавливается до запуска скачанных файлов.
Хэши подтверждают совпадение файлов с манифестом релиза.

Edge каждые 30 секунд проверяет TCP и ответ MTV2 для DC2 на каждом egress. Два
одинаковых результата подряд могут вызвать уведомление даже без клиентских подключений.
При настроенном HTTP-вебхуке доставка повторяется до трёх попыток и считается успешной
после ответа HTTP 2xx. После исчерпания попыток событие остаётся в `edge-alerts.jsonl`.


### Анонсы релизов в Telegram

После публикации и проверки файлов workflow **Release** отправляет стабильные и RC-релизы в тему «Релизы» группы `@mtevil_chat`. Скрипт `.github/announce_release.py` форматирует сообщение в Telegram HTML с заголовком, вводным описанием, разделами (`### Что нового`, `### Скорость и надёжность` и др.), командой обновления (`mtevilctl update`) и кнопками на релиз и документацию. Описание берётся из `docs/releases/<тег>.md` (если файла нет — из заметок GitHub).

Бот должен состоять в группе и иметь право писать в теме. Токен хранится в GitHub Actions Secret `TELEGRAM_BOT_TOKEN`. Переменные `TELEGRAM_CHAT_ID` и `TELEGRAM_MESSAGE_THREAD_ID` задают группу и ID темы.

Чтобы объявить уже опубликованный релиз, запустите **Actions → Release → Run workflow** и укажите тег в `announce_tag`. Образ при этом не пересобирается. Анонс отмечается скрытым комментарием в заметках релиза. Если при отправке оборвалось соединение, проверьте канал перед удалением этой отметки и повторным запуском.

### Переход с `v0.1.0-alpha.9`

В `v0.1.0-alpha.9` скрипт `setup.py` ещё не выполнял `re-exec` в новую версию перед заменой контейнера, поэтому при прямом запуске `mtevilctl update` обновление завершалось бы по старой логике (только проверка Docker `healthy`, без сквозной пробы Telegram и автоотката по ней).

Чтобы перейти с `v0.1.0-alpha.9` с полноценной сквозной проверкой и автооткатом, предварительно подгрузите `setup.py` и `mtevilctl` целевого релиза (например, `TARGET=v0.1.0` или `TARGET=v0.1.0-rc.1`), а затем запустите `mtevilctl update`:

```bash
TARGET=v0.1.0-rc.1
MTEVIL_DIR="${MTEVIL_DIR:-$HOME/mtevil}"
curl -fsSL "https://github.com/RsNest/mtevil/releases/download/${TARGET}/setup.py" -o "${MTEVIL_DIR}/setup.py"
curl -fsSL "https://github.com/RsNest/mtevil/releases/download/${TARGET}/mtevilctl" -o "${MTEVIL_DIR}/mtevilctl"
chmod +x "${MTEVIL_DIR}/setup.py" "${MTEVIL_DIR}/mtevilctl"
MTEVIL_DIR="$MTEVIL_DIR" mtevilctl update --version "$TARGET"
```

При обновлении схемы `edge → egress` начинайте с **резервного** `egress`, затем обновляйте **основной** `egress` и в последнюю очередь — `edge`.

### Проверенная производительность при отказе основного egress

На изолированном Linux-стенде (4 vCPU `Intel Xeon E5-2698 v4 @ 2.20GHz`, 3.8 GiB RAM, `Linux 6.18.38`) при внезапной остановке основного `egress` (`docker kill`) и волне из 30 параллельных внешних клиентов (запущенных на хосте вне контейнера `edge`):
- переподключились через резервный `egress`: **30 / 30** (`0` ошибок);
- общее время волны: **2.54 с**, задержка подключения: `p50 = 2205.6 мс`, `p95 = 2294.8 мс`, `max = 2322.1 мс` (включая таймаут первичной попытки к упавшему `egress`);
- пиковое потребление ресурсов во время волны: `edge` — `3.13% CPU` / `2.87 MiB RAM`, резервный `egress` — `33.98% CPU` / `1.28 MiB RAM`;
- в `edge-alerts.jsonl` записано ровно одно событие `failover_backup`.

В режиме `round-robin` серия из 6 внешних подключений при двух исправных `egress` не создала ни одного оповещения (`0` событий).

Ручные команды Docker Compose:

```bash
# Статус, логи и диагностика egress
docker compose --env-file deploy/wizard/.env -f deploy/wizard/compose.yaml ps
docker compose --env-file deploy/wizard/.env -f deploy/wizard/compose.yaml logs --tail=100 mtevil
docker compose --env-file deploy/wizard/.env -f deploy/wizard/compose.yaml exec mtevil mtevil check-egress --config /etc/mtevil/config.json --dc 2

# Перезапуск и откат на предыдущий образ (сохраняя state-том с секретом/токеном)
docker compose --env-file deploy/wizard/.env -f deploy/wizard/compose.yaml restart mtevil
MTEVIL_IMAGE=mtevil:rollback docker compose --env-file deploy/wizard/.env -f deploy/wizard/compose.yaml up -d --no-build mtevil
```

Статус `healthy` означает только доступность listener'а внутри контейнера; сквозную работу проверяйте через `check-egress` и реальный клиент Telegram.
