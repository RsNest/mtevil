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
HTTPS-cover; пример использует example.com. Перед изменением проверьте
доступность cover с сервера. Изменения SNI/секрета требуют новых клиентских ссылок.

## Диагностика и остановка

```bash
docker compose -f deploy/compose.yaml logs --tail=100 mtevil
docker compose -f deploy/compose.yaml stats --no-stream mtevil
docker compose -f deploy/compose.yaml stop mtevil
docker compose -f deploy/compose.yaml down
```

SIGTERM прекращает приём, затем даёт сессиям drain_timeout_secs (5 с по умолчанию).
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
replay-cache при перезапуске очищается. Базовые образы закреплены digest'ами;
байт-идентичность сборки и registry publication пока не заявляются.

Пакет проверен на Linux/amd64. Прикладная проверка Telegram DC — отдельная
команда `mtevil-harness probe`, она требует тестового секрета и Python-клиента.
Перед выдачей ссылки тестировщикам выполните её либо ручную проверку настоящим
Telegram с отправкой и загрузкой медиа. Наличие `healthy` этого не заменяет.

---

## Интерактивный мастер установки (Direct / Egress / Edge)

Из корня репозитория на Linux VPS (требуются Docker Engine и плагин Docker Compose):

```bash
python3 deploy/setup.py
```

Если `edge` ходит к `egress` по policy-routed mesh/VPN-туннелю (например, SharX или WireGuard), при котором трафик работает с хоста, но теряется из Docker bridge, запускайте мастер на `edge` с `--network-host`:

```bash
python3 deploy/setup.py --network-host
```

Мастер сохраняет файлы развёртывания в `deploy/wizard/` (`compose.yaml`, `config.json`, `.env`), не затрагивая ручной `deploy/compose.yaml`. Перед перезаписью существующего комплекта конфиг проверяется в кандидатных файлах (`--check-config`, TLS-проверка HTTPS-cover с нужным `SNI` и `check-egress`), а прежние файлы сохраняются как `*.bak`. При повторном запуске существующие секреты и токены в volume `state` переиспользуются без перезаписи.

### Поддерживаемые роли

1. **`direct` (один зарубежный VPS, по умолчанию):**
   - Запрашивает публичный адрес (IP или домен) и TCP-порт (по умолчанию `443`, с ранней проверкой занятости порта); IP привязки, SNI/cover и ожидаемые DNS-записи убраны в «Расширенные настройки».
   - Генерирует секрет в томе `state`, проверяет конфиг (`--check-config`) и HTTPS-cover, запускает контейнер и выводит ссылку `t.me/proxy`.
2. **`egress` (зарубежный сервер выхода, настраивается до `edge`):**
   - Запрашивает локальный туннельный IP и порт (по умолчанию `29443`) — порт публикуется строго на этом IP, а не на `0.0.0.0`.
   - На первом узле генерирует 16-байтовый токен `MTV2` (показывается только по явному запросу); на резервных узлах принимает тот же токен через скрытый ввод.
   - Выводит `IP:PORT`, команду получения токена и следующий шаг для `edge`.
3. **`edge` (входной сервер, например в РФ):**
   - Запрашивает публичный адрес/порт, SNI и cover, список `egress_upstreams` в порядке приоритета, общий токен `MTV2` (скрытый ввод) и стратегию:
     - `ordered` — всегда начинает с первого (primary) egress и при сбое перебирает резервные по порядку;
     - `round-robin` — балансирует новые сессии по кругу (поведение по умолчанию для старых конфигов без `egress_strategy`).
   - Перед запуском выполняет `mtevil check-egress --config /etc/mtevil/config.json --dc 2` из сетевого контекста edge-контейнера (отдельно показывает TCP-доступность, проверку токена и связность до Telegram DC).

### Туннели (SharX, WireGuard, AmneziaWG) и безопасность

- Мастер **не настраивает** туннели, маршруты и firewall — поднимите их заранее.
- На `egress` указывайте именно внутренний IP интерфейса туннеля:
  - **SharX:** IP mesh-интерфейса (например, `10.203.0.x`), слушающего на данной ноде.
  - **WireGuard / AmneziaWG:** локальный IP `wg*`/`awg*`-интерфейса (например, `10.250.x.y`).
- Для отказоустойчивости маршруты от `edge` к основному и резервному `egress` должны идти по **независимым** туннелям/путям.
- **Важно:** заголовок `MTV2` только аутентифицирует `edge` (и не должен открываться в публичный интернет); шифрование канала между `edge` и `egress` обеспечивает сам туннель (SharX / WG / AWG).

### Что происходит при сбое egress и оповещения (`edge-alerts.jsonl`)

- Активные сессии на упавшем `egress` могут оборваться.
- Пользователь на клиенте Telegram видит кратковременное «Подключение…» — менять ссылку не нужно: клиент переподключается на тот же `edge`, а `edge` для новых соединений выбирает живой резервный `egress` (при отказе TCP, записи префикса, таймауте ACK или отрицательном ACK).
- События смены состояния пишутся в `/var/lib/mtevil/edge-alerts.jsonl` (и при заданном `alert_webhook_url` отправляются вебхуком) строго **один раз на смену состояния**:
  - В режиме **`ordered`**: `primary_ok` → `failover_backup` (основной недоступен, трафик пошёл через резерв) → `all_down` (недоступны все выходы) → `primary_ok` (основной восстановился после окончания cooldown).
  - В режиме **`round-robin`**: штатное чередование соединений между здоровыми узлами `egress` **не вызывает оповещений**. Состояние строится по доступности узлов: `primary_ok` (все узлы доступны) → `degraded` (часть узлов недоступна, указано число здоровых из общего числа) → `all_down` (все узлы недоступны) → `primary_ok` (все узлы снова успешно обслужили соединения).
- **Когда обнаруживается смена состояния:** `edge` не запускает отдельный фоновый цикл пробинга `egress` — смена состояния обнаруживается **лениво на входящих клиентских подключениях** (в момент, когда новая сессия обращается к `egress` и получает ошибку/таймаут либо снова успешно устанавливает соединение после cooldown).

### Канал релизов и обновление (`mtevilctl`)

Для установок, созданных мастером, используйте `mtevilctl` (или `python3 deploy/setup.py <команда> --dir <путь>`):

```bash
mtevilctl status                 # Версия, роль, статус контейнера, uptime и доступная версия для отката
mtevilctl update                 # Обновить до свежего стабильного релиза (с re-exec, проверкой Telegram и автооткатом)
mtevilctl update --prerelease    # Обновить с учётом предварительных релизов (alpha/beta/rc)
mtevilctl update --version v0.1.0-rc.1  # Установить конкретный тег (переопределяет канал)
mtevilctl rollback               # Откатить к предыдущему рабочему образу и конфигу локально (без интернета)
mtevilctl traffic                # Активные сессии, байты по направлениям/участкам и период счётчиков
mtevilctl traffic --live         # Обновление раз в секунду: скорость приёма/отдачи, отключения, ретрансмиссии TCP
mtevilctl traf --live            # Короткий псевдоним для traffic
mtevilctl --help                 # Справка и примеры на русском языке
```

По умолчанию и `deploy/install.sh`, и `mtevilctl update` работают в канале `MTEVIL_CHANNEL=stable` и выбирают только стабильные SemVer-теги (`vX.Y.Z`), даже если на GitHub Latest помечен предварительный тег. Если стабильных релизов ещё нет, выводится подсказка с явными вариантами установки предварительной версии (`MTEVIL_CHANNEL=prerelease`, `--prerelease` или `MTEVIL_VERSION=<тег>`).

### Анонсы релизов в Telegram

После публикации и проверки файлов workflow **Release** отправляет стабильные и RC-релизы в тему «Релизы» группы `@mtevil_chat`. Для короткого описания на русском добавьте до четырёх пунктов в `docs/releases/<тег>.md`. Если файла нет, анонс берёт пункты из заметок GitHub.

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
