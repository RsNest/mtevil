# Воспроизводимые команды аудита маскировки FakeTLS (`mtevil`)

Никакие секреты, ссылки `t.me/proxy`, `ad_tag`, реальные IP клиентов и `.pcap`-файлы в репозиторий не сохраняются. Запускайте аудит только против **собственного одноразового тестового контейнера** на выделенном порту (не на рабочем порту `443`).

## 1. Пассивный профиль `ServerHello` (200 соединений) + эталонные домены

```bash
python3 scripts/dpi-audit/tls_audit.py \
  --target-host 127.0.0.1 \
  --target-port 24470 \
  --sni example.com \
  --secret-hex "<32_HEX_TEST_SECRET>" \
  --n-samples 200 \
  --domains example.com ya.ru vk.com ozon.ru habr.com github.com google.com
```

## 2. Активные пробы, post-handshake idle и IP-ASN проверка

```bash
PYTHONPATH=scripts/dpi-audit python3 scripts/dpi-audit/active_and_traffic_audit.py \
  --target-host 127.0.0.1 \
  --target-port 24470 \
  --sni example.com \
  --secret-hex "<32_HEX_TEST_SECRET>" \
  --vps-public-ip "$(curl -4 -fsS https://api.ipify.org)"
```

## 3. Ручные команды захвата и проверки (`tcpdump` / `tshark` / `openssl` / `curl`)

```bash
# Снять короткий локальный pcap на тестовом порту (в /tmp, не в git!)
sudo tcpdump -i lo -nn -s 0 -w /tmp/mtevil-audit.pcap "tcp port 24470"

# Разобрать ClientHello / ServerHello, типы записей и длины в tshark
tshark -r /tmp/mtevil-audit.pcap -Y "tls.handshake" -T fields \
  -e frame.time_relative -e tcp.stream -e tls.handshake.type \
  -e tls.handshake.ciphersuite -e tls.handshake.extensions_alpn_str

# Проверка NewSessionTicket на эталонном домене
(sleep 0.6; echo Q) | openssl s_client -connect ya.ru:443 -servername ya.ru -tls1_3 -alpn h2,http/1.1 -msg 2>&1 | grep -c NewSessionTicket

# Активная HTTP/2-проба через cover-путь mtevil
curl -v --http2 --resolve example.com:24470:127.0.0.1 https://example.com:24470/
```
