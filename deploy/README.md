# Тестовый релиз mtveil 0.1.0-alpha.1

Нужен Linux-сервер с Docker Engine и плагином Docker Compose, исходящим TCP
доступом к Telegram DC и выбранному HTTPS-cover. Это experimental alpha:
один секрет, Direct, process-local replay. Полная нагрузка, Android/iOS,
длительный soak и браузерная неотличимость ещё не подтверждены.

## Первый запуск

На сервере, в каталоге исходников mtveil, в Bash:

```bash
docker compose -f deploy/compose.yaml build
docker compose -f deploy/compose.yaml --profile tools run --rm init
docker compose -f deploy/compose.yaml run --rm --no-deps mtveil --config /etc/mtveil/config.json --check-config
docker compose -f deploy/compose.yaml up -d mtveil
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
MTVEIL_BIND=0.0.0.0 MTVEIL_PORT=443 docker compose -f deploy/compose.yaml up -d mtveil
docker compose -f deploy/compose.yaml exec mtveil mtveil link --config /etc/mtveil/config.json --server YOUR_SERVER_IP --port 443
```

Команда `link` намеренно раскрывает секрет в ссылке — выдавайте её только
предназначенным тестировщикам. Для повторных deploy сохраните MTVEIL_BIND/PORT
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
docker compose -f deploy/compose.yaml logs --tail=100 mtveil
docker compose -f deploy/compose.yaml stats --no-stream mtveil
docker compose -f deploy/compose.yaml stop mtveil
docker compose -f deploy/compose.yaml down
```

SIGTERM прекращает приём, затем даёт сессиям drain_timeout_secs (5 с по умолчанию).
Оставшиеся сессии закрываются; клиентам потребуется reconnect. Секрет остаётся
в томе. `down -v` удаляет том и секрет — для обычной остановки его не используйте.
Перед удалением тома обеспечьте защищённую резервную копию секрета.

## Обновление и откат

Перед изменением исходников сохраните image текущей версии под отдельным тегом:

```bash
docker image tag mtveil:0.1.0-alpha.1 mtveil:rollback
```

Сохраните копию config.json. Соберите новую версию, выполните `--check-config`,
затем `up -d mtveil`. Для отката восстановите совместимый config.json и выполните:

```bash
MTVEIL_IMAGE=mtveil:rollback docker compose -f deploy/compose.yaml up -d --no-build mtveil
```

При откате используйте прежние MTVEIL_BIND/PORT. Том секрета не удаляйте.
Обновление перезапускает единственный процесс: zero-downtime здесь не обещается,
replay-cache при перезапуске очищается. Базовые образы закреплены digest'ами;
байт-идентичность сборки и registry publication пока не заявляются.

Пакет проверен на Linux/amd64. Прикладная проверка Telegram DC — отдельная
команда `mtveil-harness probe`, она требует тестового секрета и Python-клиента.
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
   - Перед запуском выполняет `mtveil check-egress --config /etc/mtveil/config.json --dc 2` из сетевого контекста edge-контейнера (отдельно показывает TCP-доступность, проверку токена и связность до Telegram DC).

### Туннели (SharX, WireGuard, AmneziaWG) и безопасность

- Мастер **не настраивает** туннели, маршруты и firewall — поднимите их заранее.
- На `egress` указывайте именно внутренний IP интерфейса туннеля:
  - **SharX:** IP mesh-интерфейса (например, `10.203.0.x`), слушающего на данной ноде.
  - **WireGuard / AmneziaWG:** локальный IP `wg*`/`awg*`-интерфейса (например, `10.250.x.y`).
- Для отказоустойчивости маршруты от `edge` к основному и резервному `egress` должны идти по **независимым** туннелям/путям.
- **Важно:** заголовок `MTV2` только аутентифицирует `edge` (и не должен открываться в публичный интернет); шифрование канала между `edge` и `egress` обеспечивает сам туннель (SharX / WG / AWG).

### Что происходит при сбое egress

- Активные сессии на упавшем `egress` могут оборваться.
- Пользователь на клиенте Telegram видит кратковременное «Подключение…» — менять ссылку не нужно: клиент переподключается на тот же `edge`, а `edge` для новых соединений выбирает живой резервный `egress` (при отказе TCP, записи префикса, таймауте ACK или отрицательном ACK).

### Эксплуатация и откат для мастера (`deploy/wizard`)

```bash
# Статус, логи и диагностика egress
docker compose --env-file deploy/wizard/.env -f deploy/wizard/compose.yaml ps
docker compose --env-file deploy/wizard/.env -f deploy/wizard/compose.yaml logs --tail=100 mtveil
docker compose --env-file deploy/wizard/.env -f deploy/wizard/compose.yaml exec mtveil mtveil check-egress --config /etc/mtveil/config.json --dc 2

# Перезапуск и откат на предыдущий образ (сохраняя state-том с секретом/токеном)
docker compose --env-file deploy/wizard/.env -f deploy/wizard/compose.yaml restart mtveil
MTVEIL_IMAGE=mtveil:rollback docker compose --env-file deploy/wizard/.env -f deploy/wizard/compose.yaml up -d --no-build mtveil
```

Статус `healthy` означает только доступность listener'а внутри контейнера; сквозную работу проверяйте через `check-egress` и реальный клиент Telegram.
