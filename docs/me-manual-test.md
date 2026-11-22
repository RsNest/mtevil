# Ручная проверка режима Middle-End (ME) и `ad_tag` на тестовом VPS

> [!IMPORTANT]
> Выполняйте проверку **только на одноразовом тестовом VPS** (не на production-серверах). Не публикуйте и не сохраняйте в репозиторий реальные секреты прокси, `ad_tag`, IP-адреса и логины.

Эта инструкция предназначена для ручной проверки режима ME в `direct` до выхода мастера настройки (Фаза 4).

---

## 1. Подготовка файлов на тестовом VPS

1. Подготовьте рабочий каталог (например, `~/mtevil-me-test`) с подкаталогами `state` (монтируется `:ro`) и `replay` (монтируется `:rw` для кэша `proxy-secret`/`proxy-multi.conf` и `runtime-stats.json`):

```bash
mkdir -p ~/mtevil-me-test/state ~/mtevil-me-test/replay
```

2. Сгенерируйте 16-байтный (32 hex) клиентский секрет прокси (если тестируете с нуля):

```bash
openssl rand -hex 16 > ~/mtevil-me-test/state/secret
chmod 0600 ~/mtevil-me-test/state/secret
```

3. Создайте `~/mtevil-me-test/config.json`:
   - Если контейнер запускается в **`--network=host`** на VPS с публичным IPv4 на интерфейсе, `public_ipv4` можно оставить `null`.
   - Если контейнер запускается в **Docker `bridge`-сети** или VPS находится за **1:1 NAT (EIP)**, обязательно укажите внешний IPv4 хоста в `"public_ipv4": "<ВАШ_ПУБЛИЧНЫЙ_IPV4>"` (автоопределения внешнего IPv4 в ядре нет; без него KDF Telegram ME не совпадёт).

```json
{
  "role": "direct",
  "listen": "0.0.0.0:24443",
  "secret_file": "/var/lib/mtevil/secret",
  "replay_file": "/var/lib/mtevil-replay/replay.bin",
  "sni": "ya.ru",
  "cover": "ya.ru:443",
  "dc": [
    "1=149.154.175.50:443",
    "2=149.154.167.50:443",
    "3=149.154.175.100:443",
    "4=149.154.167.91:443",
    "5=91.108.56.130:443"
  ],
  "metrics_listen": "127.0.0.1:9108",
  "me": {
    "enabled": true,
    "fallback_to_direct": true,
    "send_client_ip": true,
    "public_ipv4": null,
    "pool_size": 2,
    "refresh_interval_secs": 43200,
    "drain_timeout_secs": 60,
    "ad_tag_file": "/var/lib/mtevil/ad-tag"
  }
}
```

> [!NOTE]
> `me.send_client_ip = true` (по умолчанию) передаёт реальный IPv4 клиента в Telegram ME (как в официальном MTProxy). Для проверки экспериментального режима без передачи IP клиента замените `"send_client_ip": false` (передаётся `0.0.0.0:0`) и перезапустите тест отдельно.

4. Назначьте владельца `10001:10001` на тома:

```bash
sudo chown -R 10001:10001 ~/mtevil-me-test/state ~/mtevil-me-test/replay
```

---

## 2. Регистрация тестового прокси в `@MTProxybot` и установка `ad_tag`

1. Сначала запустите контейнер без `ad-tag` (либо с пустым файлом `ad-tag` с правами `0600`), чтобы прокси был доступен снаружи по публичному `IP:PORT` (например, `443`).
2. Откройте в Telegram бота **`@MTProxybot`** и отправьте команду `/newproxy`.
3. Укажите:
   - публичный `IP:PORT` тестового VPS (в split-схеме `edge → egress` указывается `IP:PORT` узла `edge`);
   - 32-hex клиентский секрет из `~/mtevil-me-test/state/secret` (чистые 16 байт **без** префиксов `ee`/`dd` и без домена SNI).
4. После успешной проверки `@MTProxybot` выдаст 32-hex рекламный тег (`ad_tag`).
5. Запишите `ad_tag` в файл с правами **`0600`** и владельцем `10001:10001` (перезапуск контейнера не требуется — демон перечитывает `ad_tag_file` автоматически каждые 2 с):

```bash
umask 077
printf '%s\n' '<ВАШ_32_HEX_AD_TAG>' > ~/mtevil-me-test/state/ad-tag
chmod 0600 ~/mtevil-me-test/state/ad-tag
sudo chown 10001:10001 ~/mtevil-me-test/state/ad-tag
```

6. Привяжите тестовый канал в `@MTProxybot` (`/myproxies` → выберите прокси → `Edit promotion` / указать канал).

---

## 3. Чек-лист проверки реальным клиентом Telegram

Сформируйте ссылку `https://t.me/proxy?server=<IP>&port=<PORT>&secret=ee<32_HEX_SECRET><HEX_SNI>` и подключитесь в официальном клиенте Telegram (Desktop / iOS / Android):

- [ ] **Авторизация и подключение:** прокси переходит в статус «Подключено», пинг стабилен.
- [ ] **Чаты:** отправка и получение текстовых сообщений в личных чатах и группах.
- [ ] **Медиа (DC `-2` / `-4`):** загрузка и отправка фото, видео, голосового сообщения.
- [ ] **Звонок:** установка голосового звонка (проверка сигналинга через ME).
- [ ] **Спонсорский канал (`ad_tag`):** вверху списка чатов появляется закреплённый спонсорский канал (может потребоваться перезапуск клиента Telegram или 1–2 минуты).
- [ ] **Переключение сети:** переключение Wi-Fi ↔ мобильная сеть (LTE/5G) — клиент автоматически переподключается без зависания.
- [ ] **Экспериментальный `send_client_ip = false` (отдельный прогон):** повторить подключение, отправку сообщений и загрузку медиа при `"send_client_ip": false`, зафиксировать результат.

---

## 4. Сбор диагностики (без секретов и `ad_tag`)

Убедитесь, что в собранных выводах **нет** секретов, `ad_tag` и IP-адресов клиентов:

1. Состояние ME-пула из `runtime-stats.json` (или `mtevilctl status` после Фазы 4):

```bash
cat ~/mtevil-me-test/replay/runtime-stats.json | python3 -m json.tool
```

Ожидаемые поля в блоке `"me"`:
- `"mode": "me"` (или `"me_degraded_fallback_direct"` при деградации);
- `"degraded": false`, `"alive_connections"` равен `"total_slots"`;
- `"ad_tag": "configured"` (значение тега никогда не выводится);
- `"fallback_direct_total": 0`, `"refresh_errors": 0`, `"backpressure_drops": 0`, `"dropped_close_ext": 0`.

2. Метрики Prometheus (localhost-only):

```bash
curl -fsS http://127.0.0.1:9108/metrics | grep '^mtevil_me_'
```

3. Логи контейнера (проверить наличие `me_config_loaded`, `me_ad_tag_reloaded`, `"route":"me"` и отсутствие утечек `ad_tag` / клиентских IP):

```bash
docker logs --tail 50 <имя_контейнера>
```

4. По завершении проверки удалите тестовый контейнер, тестовый прокси в `@MTProxybot` (`/myproxies` → удалить) и каталог `~/mtevil-me-test`.
