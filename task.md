# mtveil — Architecture Baseline v1.3
## Итоговое архитектурное решение. Обязательно для всего проекта.

> **Статус:** действует. Изменения — только через ADR (`docs/adr/NNN-*.md`).
> **Иерархия:** этот документ → спецификации компонентов → код.
> **Эпистемическое правило:** утверждения считаются гипотезами, пока не измерены.
> Согласованность ревью не является верификацией; арбитр — стенд Phase 0.
> **Железное правило:** код data plane не пишется до завершения Phase 0 и ADR-001.

---

## 0. Как пользоваться документом

1. Инварианты `INV-xx` обязательны. Каждый тест, защищающий инвариант, ссылается на его ID
   в имени/комментарии; каждый PR проверяется на соответствие INV.
2. Решения, меняющие архитектуру, оформляются ADR до кода.
3. Разделы «методики» определяют, что считается доказательством. KPI без методики не принимаются.
4. Реестр свидетельств (§15) фиксирует, что подтверждено, а что требует проверки.
   Код конкурентов не заимствуется до проверки лицензии.

---

## 1. Стратегия: baseline сначала, ядро потом

- **Цель A:** собственный технологический продукт (оправдан Rust-core).
- **Цель B:** быстрый надёжный прокси (оправдан форк/патчи).
- Выбор делается **по данным Phase 0**, а не идеологически.

### Decision gate → ADR-001 (fork vs new core)
Для каждого подтверждённого дефекта конкурентов оцениваем:
severity (S1–S4) · patchability upstream (effort, риск регрессий, вероятность принятия) ·
fork-стоимость поддержки · стратегическая ценность владения ядром.
Один неисправимый S1 может оправдать новое ядро; пять S3 могут не оправдать.
Механический счёт дефицитов запрещён.

**Артефакты Phase 0 (wire-корпус, harness, генератор, методика) обязательны при любом исходе.**
При исходе «форк» этот baseline применяется к форку: инварианты реализационно-независимы.

---

## 2. Scope

### MVP
Data plane (listener · demux · FakeTLS · secure-транспорт · ME-pool · Direct) ·
внешний cover (nginx/Caddy за byte-relay) · control plane (epoch-конфиги, пользователи,
localhost API, /metrics, lifecycle) · egress (direct/socks5/interface/bind + scopes, health,
`me_nat_ip`) · guard (replay, skew, suspects, shadow-ban→cover, canary) · lifecycle
(graceful drain, upgrade с zero accept-pause, watchdog).

### Вне MVP (отдельные спеки/фазы/репозитории)
| Компонент | Статус |
|---|---|
| Companion-рефингерпринтер | отдельный продукт; ядро полностью работает без него |
| Встроенный cover (rustls+ACME+h2/h3) | позже; сначала внешний cover |
| Thread-per-core runtime | только после бенчмарка против multithread Tokio |
| Managed sidecar-супервизор | сначала внешний SOCKS5 + health |
| Cross-server suspect sync, WEB-режим, link-sets | позже |
| MSS-clamp | опция, выключена; против реассемблирующих узлов не работает |

---

## 3. Плоскости и изоляция

```text
DATA PLANE    listener → demux → faketls/transport → ME-pool / Direct
CONTROL PLANE config-epochs · users · API · metrics · lifecycle   (отдельный runtime)
EGRESS PLANE  routing · health · upstreams                        (изолированные пулы)
COVER         внешний nginx/Caddy, свой cgroup/systemd-лимит      (byte-relay из demux)
```

### Правила
- **INV-07 (изоляция):** сбой/перегрузка cover, control API или egress-health не деградирует
  установленные MTProto-сессии. Проверяется chaos-тестами.
- Data plane: multithread Tokio; control plane: отдельный однопоточный runtime;
  blocking-пул bounded (`spawn_blocking`) для DNS/файлов/cert/nft-helper — никогда на data-потоках.
- Data plane: запрещены `std::fs`, `getaddrinfo`, блокирующие локи, синхронные внешние вызовы.
- Fairness: per-connection per-event caps (кадры/байты), round-robin ready-очередь;
  целевой p99 итерации event loop < 1 мс (измеряется).
- **Триггер ADR-002 (выделение control plane в процесс):** если chaos-тест «flood control API +
  шторм blocking-операций» поднимает p99 data plane выше порога (конфиг, напр. +10%) или вызывает
  любое нарушение deadline — control plane выносится в отдельный процесс с локальным IPC.
  Тюнинг приоритетов потоков не считается решением.

---

## 4. Замороженные инварианты

### INV-01 · ProtocolCommitted (необратимая граница протокола)
`ProtocolCommitted(protocol)` наступает при **первом успешном `write()` в клиентский сокет**
байтов выбранного протокола (FakeTLS SH или cover-relay); partial write ≥1 байт = коммит.
`EAGAIN`/очередь без записи = не коммит; очередь можно отбросить и уйти в cover.
Cover-коммит — при первом из: байт клиента форвардирован бэкенду, либо байт бэкенда записан клиенту.
После коммита переход между протоколами запрещён навсегда.
Порядок: `CH → validate → atomic replay check_and_insert → policy → generate SH → queue →
[окно отбрасывания] → first write → COMMITTED`.
**Проверка:** тест порядка write/commit; revoke/overload между генерацией и флашем → cover;
ошибка после коммита → drain/close, не cover.

### INV-02 · Replay: атомарность и персистентность
Таблица в **tmpfs-mmap** (`/run/mtveil/replay.tbl`), разбитая на N шардов (напр. 256).
Каждый шард — **process-shared robust mutex** (не lock-free CAS: проще, переживает смерть
владельца через `EOWNERDEAD` + recovery). `check_and_insert` — одна критическая секция.
Ключ = canonical HMAC (32 Б), TTL 300 с; ленивое протухание + bounded sweep в control plane.
Duplicate → CoverRelay + метрика. Saturated → sweep; если полно → CoverRelay новых CH + метрика
(fail-safe наружу, не тихий приём). Старый/новый процесс при upgrade и рестарт после crash
мапят один файл → кэш сохраняется. Reboot: tmpfs очищается; остаточный риск replay CH <120 с
документируется и принимается. Rotation секрета безопасен по построению (ключ зависит от секрета).
**Проверка:** барьер-тест двух worker'ов с идентичным CH (ровно один Accepted);
кросс-процессный тест при upgrade; тест смерти владельца мьютекса; тест насыщения.

### INV-03 · Прогресс при backpressure
Per-worker emergency reserve (конфиг, напр. 64 КиБ + headroom) только для: флаша уже
зашифрованных outbound-очередей, control-кадров ME (PING/PONG), close/drain (предвыделенные пути).
Новые чтения и ME-dial резерв не используют. Каждое ожидание имеет конечный deadline:
PreAuth/handshake budget wait → handshake_timeout; Ready stall без прогресса →
budget_stall_timeout (напр. 60 с) → graceful close; ME blackhole → eviction deadline;
upgrade drain → drain_deadline. Таймеры и пути закрытия не требуют аллокаций из исчерпанного пула.
ME-first resume. Аргумент прогресса: освобождение ресурсов никогда не требует бюджета из пула,
который может быть исчерпан → каждое приостановленное соединение имеет путь освобождения.
**Проверка:** chaos «все paused + ME blackhole» → ресурсы освобождены за ограниченное время;
метрики reserve_usage, budget_stall_timeout, paused_duration_p99.

### INV-04 · No avoidable abortive close
Замена «Never RST». Поведение по фазам:
| Фаза / класс входа | Поведение |
|---|---|
| PreAuth: браузерный CH без секрета, replay, skew, неверный секрет, чужой SNI | relay в cover |
| PreAuth: мусор / не-TLS / TLS1.2-only / resumption-CH | relay в cover; ответ = поведение реального сервера для этого класса (alert/close допустимы) |
| PreAuth: overload / бюджет / DNS-miss / cover-connect-fail | relay при возможности; иначе bounded graceful close + метрика |
| PostCommit: любой сбой | graceful drain/close; cover запрещён (INV-01) |
| Смерть процесса / FD-exhaustion на accept | вне инварианта; supervisor restart + метрики |
Механика: bounded drain receive-очереди перед close (Linux шлёт RST при close с непрочитанными
данными). App-счётчики = intent; ground truth = kernel/eBPF (§11.4).
**Проверка:** probe-сьют по классам; chaos; сверка intent vs kernel RST.

### INV-05 · Владение ME-сессией и порядок
Клиент привязан ровно к одному writer'у на всю жизнь сессии; перепривязки не существует.
Потеря writer'а → закрытие привязанных клиентов (`me_writer_lost`) + reconnect клиента;
прозрачный failover не обещается. Per-client FIFO сохраняется через mux; outbound — FIFO по
enqueue; частичная запись возобновляется с точного byte-offset, **без повторного шифрования**.
Плановая замена: writer перестаёт принимать новых → дренаж/deadline → закрытие.
Eviction только по совокупности признаков (PONG просрочен + запросы без ответа), не чаще
одного на DC за интервал; последний живой writer DC не выселяется.
**Проверка:** тест потери writer'а, тест partial-write offset, тест FIFO под нагрузкой.

### INV-06 · Config lifecycle: prepare → commit → retire
prepare: валидация, pre-resolve DNS, pre-bind listeners, pre-create upstream health, pre-load
сертов; всё fallible, владельческие токены в `PrepareSet`; ошибка → drop → автооткат внешних ресурсов.
commit: атомарная публикация epoch (`arc-swap`), **после коммита никаких fallible-операций**.
retire: асинхронный дренаж старых ресурсов по deadline; ошибки логируются/ретраятся, не блокируют
commit; reconcile-петля против сирот. Откат возможен только до commit; после — forward-fix
новым epoch. Смена listener: bind new → commit → drain old.
**Проверка:** тест падения на каждой стадии prepare; тест retire-ошибок; тест orphan-reconcile.

### INV-07 · Изоляция плоскостей
См. §3. **Проверка:** chaos-тесты изоляции; триггер ADR-002.

### INV-08 · Секреты
`zeroize` ключей/секретов; constant-time сравнение (`subtle`); секреты никогда в логах;
файлы 0600 root-owned; API раскрывает секрет только при create/rotate/links (one-time);
токены со scopes (admin/read/metrics). **Проверка:** тесты логов/API, fuzz парсеров.

### INV-09 · Разделение верификации
Корректность протокола ≠ поведенческая эквивалентность пробам ≠ статистическое сходство.
Три отдельных семейства тестов (§11). Остаточные детектируемые признаки не заявляются
исправленными: нет session tickets в FakeTLS, «сертификат» одной записью, мессенджерный
поведенческий профиль, фиксированный JA4 стокового клиента.
**Проверка:** ни один KPI не смешивает семейства.

### INV-10 · Честные гарантии
Zero accept-pause + измеряемый дренаж и `forced_close_ratio`; «ноль разрывов» не обещается.
Recovery — только по таксономии §11.2. Память — только по методике §11.3.
**Проверка:** формат отчётов бенчмарка соответствует методике.

---

## 5. State machines (сводно)

### 5.1. Клиентская сессия
```text
Accepted → PreAuth ─┬─(HMAC ok ∧ replay ok ∧ policy ok)→ Authenticated
                    └─(иначе)→ CoverRelay
Authenticated → Obfuscation → Ready → Draining → Closed
CoverRelay → Draining → Closed
ProtocolCommitted фиксируется по INV-01 и необратим.
```

### 5.2. FakeTLS-engine
Split-CH ≤16 записей / ≤4096 Б тело; HMAC по канонической single-record форме; masking получает
оригинальные байты как пришли. HMAC-SHA256 multi-key, constant-time первые 28 Б; timestamp XOR,
окно ±120 с. SH-полёт: одна AppData-запись «сертификата» (ограничение клиента), размер из профиля
(§11C), HMAC покрывает весь полёт. PQ — таблица групп/размеров, не одна константа.
obfuscated2 init 64 Б; ключи SHA-256(nonce||secret), IV из nonce; только secure-тег.
Позиции AES-CTR encrypt/decrypt отслеживаются отдельно.

### 5.3. ME-writer
```text
Dialing → Handshaking → Ready ─┬─(плановая замена)→ Draining → Dead
                               └─(сбой)→ Dead
```
Инварианты владения/порядка/дренажа — INV-05. Handshake ME — отдельные состояния с таймаутами;
ad_tag-политика по official MTProto + верификация векторами.

### 5.4. Direct
Per-client TCP к DC; те же partial-write/drain-семантики; маршрут per-DC конфигом;
ad_tag в Direct не передаётся (документированный трейдофф).

### 5.5. Завершение
`stop reads → flush outbound (bounded) → shutdown(WR) → drain inbound (bounded) → close`.
Дренаж inbound перед close обязателен для avoidance RST; лимиты байт/времени; неизбежные RST считаются.

---

## 6. Resource accounting и профили нагрузки

### 6.1. Память
Userspace: глобальный бюджет буферов пересылки, доля на worker, учёт по capacity;
пол 64 КиБ на активное соединение; отказ бюджета = пауза чтения (с INV-03), не разрыв.
Kernel: per-socket `SO_RCVBUF`/`SO_SNDBUF` caps по профилю; политика `tcp_rmem/wmem`.
Формула: `total ≈ userspace_budget + kernel_socket_buffers + runtime + shared`.
16 ГБ / 50k = 335 КБ всё-включено; 8 ГБ бюджет → 168 КБ userspace + kernel (idle ~10–30 КБ,
active — до caps). «Хватит» — не утверждается, а измеряется.
Admission: `max_connections`, `max_handshakes`, FD-лимит, RSS-watchdog, cgroup `MemoryMax`.
PreAuth-overload → дешёвый CoverRelay; PostAuth-budget → backpressure; accept-then-close churn запрещён по возможности.

### 6.2. Профили (обязательны все)
| Профиль | Параметры | Цель |
|---|---|---|
| idle | 50k сессий, keep-alive | память, FD, CPU idle |
| messaging | 50k, реалистичный редкий обмен | базовая совместимость |
| messaging_hot | 20k активных × 3 msg/s двусторонно, кадры 64–512 Б (~60k msg/s) + 30k idle | очереди, планировщик, кодек, allocation rate |
| mixed media | 10–20% сессий качают медиа | throughput, buffer caps, budget refusals |
| reconnect storm | 5–10k conn/s после сбоя | admission, replay, ME dial rate, recovery |

---

## 7. Failure matrix (сокращённая; полная — `docs/failure-matrix.md`)

| Сбой | PreAuth / PreCommit | PostCommit | Метрика |
|---|---|---|---|
| DNS cover недоступен | cached address → relay; иначе graceful close | нет влияния | cover_dns_fail |
| Cover connect fail | запасная цель → graceful close | нет влияния | cover_connect_fail |
| ME dial fail | — | close сессии, reconnect | me_dial_fail |
| ME blackhole | — | eviction по совокупности | me_slow_evictions |
| Partial write | bounded retry с offset | то же | partial_writes |
| Client FIN/RST | дренаж/закрытие | дренаж/закрытие | close_reasons |
| Budget exhausted | relay в cover | пауза чтения (INV-03) | budget_refusals |
| FD exhaustion | accept fails/backlog | существующие не страдают | accept_failures |
| Revoke пользователя | relay в cover | immediate close / grace drain (политика) | revoked_sessions |
| Clock jump >120с | CH в skew → cover | готовые сессии не страдают | hello_clock_skew |
| Upstream fail | — | новые conn на здоровый маршрут, старые дренируются | upstream_failover |
| OOM/kill | supervisor restart | сессии теряются (честно) | process_restarts |

---

## 8. Configuration lifecycle: per-field политики

| Изменение | Политика |
|---|---|
| Добавление пользователя | новые соединения, без разрывов |
| Лимиты (квоты/rate/IP) | per-field: `new-only` \| `live-apply` |
| Удаление/отключение | `immediate` (default, безопасность) \| `grace-drain` |
| Ротация секрета | старые сессии: `revoke` (default) \| `keep-until-close` |
| tls_domain / SNI-пулы | только новые соединения |
| Upstreams | новые conn на новый маршрут; старые дренируются на старом |
| Listeners | отдельная процедура (§INV-06) |
| DRS/cert-профиль | только новые соединения |
| Cover backend | новые relay-соединения |

Сессия пинит identity-снапшот момента аутентификации; live-параметры читает из текущего epoch.

---

## 9. Lifecycle и upgrade

Zero accept-pause: новый процесс bind через SO_REUSEPORT (или SCM_RIGHTS передача listener),
старый прекращает accept и дренируется с deadline (конфиг, напр. 15 мин).
Долгоживущие Telegram-сессии делают 100% дренаж непрактичным → по deadline forced close **с подсчётом**.
Метрики: `accept_pause_ms`, `drained_sessions`, `forced_closed_sessions`, `forced_close_ratio`.
systemd watchdog + sd-notify readiness; crash-only; деградация в cover при перегрузке.

---

## 10. Security model

| Граница | Модель |
|---|---|
| Клиент | untrusted; все парсеры bounded, fuzz-покрытые |
| Cover backend | local semi-trusted; отдельный процесс/лимиты |
| Upstream/sidecar | untrusted network; local process sandboxed, pinned checksum |
| Control API | localhost + Bearer + scopes; секреты one-time |
| Конфиг/секреты | root-owned 0600; zeroize; никогда в логах |
| Firewall | main process без CAP_NET_ADMIN; nft через узкий локальный helper |

Main process unprivileged: только `CAP_NET_BIND_SERVICE`, seccomp, `ProtectSystem=strict`.
Обновления: SHA-512 + подпись до замены бинарника; pinned deps, reproducible build, SBOM.

---

## 11. Верификация и бенчмарки

### 11.1. Семейства (INV-09)
- **A. Корректность/совместимость:** матрица стоковых клиентов (Android/iOS/Desktop/tdlib,
  версии фиксируются), wire-векторы, pcap-replay; gate на каждый релиз.
- **B. Поведенческая эквивалентность пробам:** классы (браузерный CH без секрета, replay в/вне окна,
  мусор, не-TLS, TLS1.2-only, resumption-CH, молчаливое соединение, пробы под нагрузкой);
  ожидание = поведение эталонного cover; pass-rate по классам.
- **C. Статистическое сходство:** распределения размеров записей/полёта vs эталонный cover
  при сопоставимой нагрузке; KS/EMD с заданными порогами; отсутствие константных размеров;
  тайминги отдельно. Сходство ≠ протокольная неотличимость.
- **D. Остаточные признаки:** перечислены в INV-09, не заявляются исправленными.
- **E. Поведение при отказах:** failure-injection suite против конкурентов — главное конкурентное поле.

### 11.2. Recovery-таксономия
| Метрика | Определение |
|---|---|
| upstream_recovery_time | t0 → первый здоровый egress-маршрут |
| writer_ready_time | t0 → первый ME-writer затронутого DC в Ready |
| service_recovery_time | t0 → первое новое клиентское соединение с полным handshake **и payload** |
| client_recovery_fraction(T) | доля клиентов генератора с живой сессией на t0+T (T=30/60/120 с) |
| session_loss_count / forced_reconnect_count | абсолютные counts |

Сессии на потерянном writer'е не «восстанавливаются» — это новые сессии. Сравнение — только
по этой таксономии, одинаковыми точками замера.

### 11.3. Память/утечки
Совокупно: live object census (sessions/writers/queues/buffers), allocator stats
(allocated/resident/metadata), buffer used vs reserved, cgroup `memory.current/peak`,
RSS slope + CI, heap-профили soak (dhat/bytehound).
Критерий: после снятия нагрузки live objects и allocated возвращаются к baseline ± CI.
Плато RSS не доказывает отсутствие утечек.

### 11.4. RST-атрибуция
App intent-счётчики + kernel `nstat` (`TCPAbortOnData/OnClose/OnMemory/OnTimeout`,
`ListenDrops/Overflows`) + eBPF `tcp:tcp_send_reset` с socket cookie (`SO_COOKIE`) →
корреляция с session id; pcap-ring на стенде. На стенде Phase 0 eBPF обязателен; в продакшене опционален.

### 11.5. Phase 0 exit-критерии (все обязательны)
- [ ] Версии и конфигурации telemt/mtg/mtdd запинены, воспроизводимы.
- [ ] Совместимые wire-тест-векторы получены.
- [ ] Воспроизводимый генератор нагрузки (все профили §6.2).
- [ ] Сетевые и локальные задержки разделены.
- [ ] Сценарии отказов: ME blackhole/loss, DNS, FD, memory, clock jump, upgrade под нагрузкой, revoke под нагрузкой.
- [ ] Сравнительный отчёт: медиана N прогонов + CI, сырые данные опубликованы.
- [ ] ADR-001 (fork vs new core) по рубрике §1.

**Справедливость:** не требовать одинаковой функциональности; сравнение в пределах возможностей
каждой реализации, расхождения семантики документируются. mtg single-secret — ограничение методики.

### 11.6. Benchmark methodology
Одинаковое железо, ядро/sysctl, внешний cover, egress; 4+ профиля; инъекции netem/cgroup/FD;
метрики: RSS/allocator/cgroup, p50/p95/p99 локальной обработки отдельно от RTT, error/reject reasons,
recovery-таксономия, forced_close_ratio, rst_ratio (сверка), probe pass-rate.
Репортинг: медиана N прогонов + CI, сырые данные, воспроизводимость через Compose + netem + генератор.

---

## 12. KPI (с методиками, не декларации)

| Область | Критерий |
|---|---|
| Пробы | 100% ожидаемых ответов для заданных классов корректных проб; мусор/alert — отдельные классы |
| Память | отсутствие статистически значимого неконтролируемого роста по методике §11.3 |
| Upgrade | zero accept-pause + измеряемый дренаж + forced_close_ratio |
| Latency | раздельно local processing p99 и end-to-end при фиксированном RTT |
| Статистика | протокольные проверки (A) + статистические тесты с методикой (C) |
| Детект блокировки | время детекта при заданных точках наблюдения и типах отказа |
| Совместимость | смоук-матрица стоковых клиентов зелёная на каждом релизе |

---

## 13. Roadmap и gates

| Фаза | Содержание | Gate |
|---|---|---|
| 0 | baseline harness + wire-корпус + генератор + методики; бенчмарк конкурентов | exit-критерии §11.5 → **ADR-001** |
| 1 | wire-совместимый прототип (если gate пройден) | векторы + смоук реальных клиентов |
| 2 | MVP: пользователи, ME/Direct, диагностика, внешний cover | матрица клиентов + failure matrix в тестах |
| 3 | надёжный data plane: профили нагрузки, hot-reload по политикам, chaos | INV-тесты + нагрузочные прогоны |
| 4 | production hardening: обновления, sandbox, подписанные релизы | soak + upgrade-тесты |
| later | встроенный cover, thread-per-core (bench-gated), sidecar-супервизор | по данным |
| отдельно | companion | отдельный репо/спека/roadmap |

Оценки (соло + AI): Phase 0 — 3–5 нед; прототип 4–8 нед; MVP 2–4 мес суммарно;
надёжный data plane 3–6 мес; hardening 6–9 мес; companion 9–15+ мес.

---

## 14. Engineering rules

### 14.1. Репозиторий
```text
mtveil/
  docs/adr/                  # ADR-000 (этот baseline), ADR-001 (gate), ...
  docs/specs/                # спеки компонентов, failure-matrix, методики
  crates/
    proto/                   # чистые парсеры/кодеки, без I/O
    data-plane/              # listener/demux/faketls/transport
    me-pool/                 # writer'ы, Direct
    egress/                  # upstreams, health, routing
    control/                 # epoch-конфиги, users, API, metrics
    guard/                   # replay (tmpfs robust-mutex), suspects, canary
    harness/                 # генератор, стенд, eBPF/nstat, отчёты
  tests/vectors/             # wire-векторы
  tests/inv/                 # тесты инвариантов (имена ссылаются на INV-xx)
```

### 14.2. Код
- Rust; парсеры — чистые функции над `&[u8]`, bounded, без unsafe; fuzz-покрытие обязательно.
- Data plane: правила §3 (никаких блокирующих операций).
- Каждый INV-тест ссылается на ID; PR без INV-проверки при затрагивании инварианта не принимается.
- clippy/deny, pinned deps, reproducible static musl build, SBOM, релизы SHA-512 + подпись.

### 14.3. Процесс
Spec → INV-check → тесты → код. Spec-first для всех компонентов.
Изменение инварианта — только ADR + обновление тестов.
Секреты/лицензии: код конкурентов не копируется до проверки лицензии (§15).

---

## 15. Реестр свидетельств

| Утверждение | Уровень | Статус |
|---|---|---|
| mtdd: kFakeCertSize=2878, masking-пути, suspects, upstreams, split-CH, PQ-константы | primary (чтение исходников) | подтверждено |
| mtdd: MIT | primary (README) | подтверждено |
| telemt: Rust+Tokio, режимы, masking, tls_emulation, WEB | secondary (README/docs) | код не аудирован |
| mtg: single-secret | secondary (README форка) | требует проверки по mtg |
| Лицензии telemt/mtg | не верифицированы | **TODO до заимствования кода** |
| Волны DPI-2026 | field reports (teleproxy docs, mtg#547, Habr, tdesktop#30733) | триангулировано, не независимое измерение |

План: аудит исходников по спорным утверждениям; независимый захват трафика где легально;
проверка лицензий. До проверки — только дизайны, не код.

---

## 16. Открытые вопросы (закрываются в Phase 0/1)

1. Источник истины ME-handshake/ad_tag при расхождении implementations.
2. Direct: ограничения медиа по типу аккаунта — зафиксировать тестами.
3. Дефолты kernel buffer caps per profile — только по замерам.
4. Дефолт drain window при upgrade — по распределению длительности сессий.
5. Replay saturation trade-off: доступность vs строгость — политика по данным.
6. Достаточен ли внешний cover для probe-equivalence (гипотеза: да) до встроенного cover.

---

## 17. Немедленный следующий шаг

**Спека Phase 0** (`docs/specs/phase-0.md`): топология стенда (Compose + netem),
eBPF/nstat-атрибуция RST, генератор нагрузки из pcap-производных кадров, формат сырых данных,
шаблон ADR-001. Код data plane не начинается до ADR-001.

Побеждаем не количеством функций, а измеряемым поведением при отказах.
