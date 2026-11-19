# Совместимый Direct-прототип (ADR-001)

Бинарник `mtveil`, крейты `proto` (чистые байтовые операции) и `data-plane`
(Tokio I/O). Это тестовый прототип, не production-релиз.

Вход: TLS ClientHello до 4096 байт handshake body, до 16 TLS records.
Исходные TLS records сохраняются отдельно от собранного handshake. Каноническая
форма HMAC: один record `16 03 01 len`, ClientHello с нулями вместо random.
Первые 28 байт random = HMAC-SHA256(secret, canonical CH)[0..28], последние
4 байта XOR digest tail = UNIX timestamp LE. Сравнение constant time.
Проверяются длины вложенных полей, TLS1.3 supported_versions и SNI.

Без секрета, skew, replay, неверный SNI или неподдерживаемый CH: байты точно
форвардируются на настроенный cover без собственного TLS ответа. После первого
байта SH FakeTLS путь необратим; ошибки MTProto приводят к закрытию, не cover.
Первый байт отправленный cover также исключает последующий выбор FakeTLS.

SH: TLS1.3-shaped ServerHello + CCS + random application record, HMAC(secret,
client_random || full flight with zero SH random). Это совместимость FakeTLS,
а НЕ настоящая TLS-криптография и НЕ доказательство браузерного fingerprint.

Внутри application records: 64-byte obfuscated2 init. Из wire[8..40] и secret
получаем SHA256 key, IV wire[40..56]; receive cipher consumes all 64 bytes;
tag dddd, DC id LE i16 из расшифрованного хвоста. Ответный cipher: reversed
wire[8..56], key SHA256(first32 || secret), IV last16. Только padded intermediate.

Direct DC: отдельный случайный obfuscated2 header с тем же transport tag, но
ключи DC без proxy secret. Отдельные AES-256-CTR потоки в каждом направлении.
Прокси не расшифровывает пользовательский MTProto payload, только транспортную
обфускацию. Разрешены только явно заданные DC ID -> SocketAddr, включая media
через абсолютное значение ID; никакого произвольного SOCKS/open-proxy.

CLI: `--listen`, `--secret-file` (32 hex), `--sni`, `--cover host:port`,
`--dc ID=IP:PORT` (повторяемый), `--max-connections` (по умолчанию 128),
`--handshake-timeout-secs` (10), `--idle-timeout-secs` (300).
`--drain-timeout-secs` (5) ограничивает завершение текущих сессий при остановке.
Секрет считывается до accept-loop и не логируется. Буферы фиксированного размера,
один permit на соединение; handshake, connect, read/write и relay имеют deadlines.

Replay-cache: максимум 65536 записей, TTL 300 с. Проверка и вставка под одним
async mutex; очередь expiry позволяет удалять не более 64 протухших записей
на одно обращение вместо полного обхода таблицы. При насыщении живые ключи
не вытесняются; новые CH уходят в cover. Кэш остаётся process-local.

SIGINT и Linux SIGTERM прекращают admission, включая ожидание свободного
permit. Затем действует отдельный drain deadline, оставшиеся задачи отменяются.
Завершённые задачи JoinSet собираются перед новым admission; ограничение
числа живых сессий само по себе не ограничивает накопление завершённых handles.

Регрессии: `cargo test --workspace --locked`. Сетевые тесты используют только
loopback cover/DC: replay-race 8 клиентов, split CH 1..16/17 records, сохранение
исходных cover-байтов, ошибки после SH, crypto offsets, handshake/write/idle
deadlines, release permit и остановку при насыщенном admission.

Малый Linux resource smoke (не нагрузочный benchmark):

```text
python3 crates/harness/stand/smoke/resource_smoke.py --binary target/release/mtveil --out runs/resource-smoke
```

Он создаёт 12 медленных loopback-соединений при лимите 4, фиксирует /proc FD/RSS,
проверяет освобождение всех клиентов и возврат FD к baseline, затем SIGTERM.
Не меняет sysctl/firewall/сервисы и не обращается к Telegram DC. Рост RSS в таком
коротком smoke не используется как доказательство наличия/отсутствия утечки.

Ссылки: https://core.telegram.org/mtproto/mtproto-transports,
https://core.telegram.org/mtproto/description . Собственное ядро не копирует
серверный код telemt/mtg; синтетический клиент уже проверен отдельно против telemt.
