# Спека Phase 0 — baseline harness, wire-корпус, генератор, методики

> **Статус:** действует. Подчиняется [ADR-000 baseline](../adr/000-architecture-baseline.md).
> **Область:** артефакты Phase 0 обязательны при любом исходе decision gate (ADR-001).
> Код data plane (`crates/data-plane`, протокольные кодеки `crates/proto`) **не пишется** до
> завершения Phase 0 и ADR-001.
> **Верификация:** утверждения считаются гипотезами, пока не измерены (эпистемическое правило ADR-000).

---

## 0. Цели Phase 0

1. Воспроизводимый стенд: топология, конфигурации, версии конкурентов — зафиксированы и пинятся.
2. Wire-корпус: совместимые тест-векторы MTProto-транспортов (FakeTLS, secure, obfuscated2),
   пригодные и для бенчмарка совместимости, и для будущих INV-тестов.
3. Генератор нагрузки, покрывающий все профили ADR-000 §6.2, детерминированный (seed).
4. Атрибуция RST (eBPF/nstat/pcap) — ground truth против app-intent счётчиков (ADR-000 §11.4).
5. Инъекции отказов и recovery-таксономия (ADR-000 §11.2).
6. Сравнительный отчёт telemt / mtg / mtdd: медиана N прогонов + CI, сырые данные.
7. **Gate:** exit-критерии §1 → ADR-001 (fork vs new core) по рубрике §14.

Критерии выхода (все обязательны, чеклист ведётся в §15):

- [ ] Версии и конфигурации telemt/mtg/mtdd запинены, воспроизводимы (`versions.lock`).
- [ ] Совместимые wire-тест-векторы получены и зафиксированы (`tests/vectors/`).
- [ ] Воспроизводимый генератор нагрузки (все профили §6.2).
- [ ] Сетевые и локальные задержки разделены (методика §6).
- [ ] Сценарии отказов реализованы (§9).
- [ ] Сравнительный отчёт: медиана N прогонов + CI, сырые данные опубликованы (§11, §12).
- [ ] ADR-001 по рубрике §14.

---

## 1. Объекты сравнения

| Реализация | Роль | Pinning |
|---|---|---|
| telemt | кандидат A | git ref + build flags + image digest |
| mtg (форк) | кандидат B | git ref + build flags + image digest |
| mtdd | кандидат C | git ref + build flags + image digest |
| эталонный cover (nginx/caddy) | ground truth для family B/C | image digest + config в репо |

Правила:

- Артефакт `harness/config/versions.lock.toml`: для каждого объекта — VCS URL, ref (full sha),
  фикс-патчи (если есть, как diff), build flags, container image + digest, sha256 бинарника.
  Пересборка воспроизводима: `harness stand build` обязан восстанавливать идентичный бинарник
  или падать.
- **Код конкурентов не копируется** до проверки лицензий (ADR-000 §15). Phase 0 использует
  конкурентов как чёрные ящики (запуск, конфигурация, замеры) — заимствования кода не требуются.
- mtg single-secret — задокументированное ограничение методики (ADR-000 §11.5): профили с
  несколькими пользователями для mtg прогоняются с одним секретом; расхождение семантики
  фиксируется в отчёте, не интерполируется.
- **Справедливость:** не требовать одинаковой функциональности; каждая реализация замеряется
  в пределах своих возможностей. Отсутствующая функция (напр. ME-режим, upgrade без
  accept-pause) → строка `N/A (отсутствует)` в отчёте, не штраф и не экстраполяция.

---

## 2. Топология стенда

```text
                    compose-сеть client-net (netem: профиль RTT/loss/jitter)
 +----------------+          +-------------------------------------+
 | generator      |          |              dut-<impl>             |
 | (нагрузка +    | -------> |  telemt | mtg | mtdd               |
 |  probe-suite)  |          |  cgroup: MemoryMax/CPU/DUT-профиль  |
 +----------------+          +------------------+------------------+
                                        | front-net
                     +------------------+------------------+
                     | cover (nginx/caddy, эталонный сайт) |
                     +------------------+------------------+
                                        | egress-net (netem: отдельный профиль)
                     +------------------+------------------+
                     | upstream-farm: fake-DC (TCP echo    |
                     | MTProto-подобный), socks5, DNS      |
                     +-------------------------------------+

 observer (host network): eBPF, nstat-poller, pcap-ring, cgroup-metrics
 chaos    (host/privileged): tc-netem инъекции, fd/mem/clock-инъекции, orchestrator
```

### 2.1. Сервисы Compose

| Сервис | Образ | Сеть | Ограничения |
|---|---|---|---|
| `dut-<impl>` | pinned image реализации | client-net, front-net, egress-net | cgroup `MemoryMax`, `pids-limit`, CPU quota — по DUT-профилю |
| `cover` | nginx pinned | front-net, cover-net | свой cgroup-лимит (ADR-000 §3) |
| `upstream-farm` | harness image (`crates/harness` bin: fake-dc, fake-socks5) | egress-net | фиксированные ответы, лог включений |
| `generator` | harness image (`crates/harness` bin: generator) | client-net | seed-детерминированный |
| `observer` | harness image + eBPF | host network, монтирует cgroupfs | `privileged` только здесь |
| `chaos` | harness image + iproute2, netem | host network | `NET_ADMIN`, применяет tc на veth |

### 2.2. Сети и разделение задержек (ADR-000 §11.5, §11.6)

Каждая compose-сеть — отдельный netem-домен:

| Сеть | Профиль по умолчанию | Назначение |
|---|---|---|
| client-net | RTT 0 / RTT 50 мс / loss 0% / 1% (пер-прогон) | клиентский плечо |
| front-net | без netem | локальный byte-relay (cover в том же сегменте) |
| egress-net | RTT 0 / 100 мс | плечо до upstream/DC |
| cover-net | без netem | cover → реальный мир (в стенде — локальный сайт) |

Правила разделения задержек:

1. **Local processing latency** измеряется в прогоне с `netem = 0` на client-net и egress-net:
   генератор меряет timestamp каждого события (connect, CH sent, first byte back, payload ack) —
   разности без сетевой составляющей.
2. **End-to-end latency** — прогон с нетем-профилем; отчёт всегда указывает профиль.
3. p50/p95/p99 публикуются **отдельно** для local и e2e; смешивание запрещено (ADR-000 §12).
4. Timestamp'ы — `CLOCK_MONOTONIC` на одной машине; wall-clock добавляется в manifest.

### 2.3. Kernel/сисctl окружение

- `harness/stand/sysctl.conf` — фиксируется в manifest каждого прогона: `tcp_rmem/tcp_wmem`,
  `somaxconn`, `tcp_max_syn_backlog`, `tcp_tw_reuse`, fs.file-max, eBPF-лимиты.
- Идентичное железо/ядро — требование ADR-000 §11.6; manifest содержит `uname -a`,
  `/proc/cpuinfo` signature, container runtime version.

---

## 3. Wire-корпус (артефакт `tests/vectors/`)

Назначение: единый набор байтовых векторов для (a) проверки совместимости реализаций,
(b) будущих INV-тестов и кодеков Phase 1+.

### 3.1. Источники

1. **Захват стоковых клиентов** (family A, ADR-000 §11.1): Android/iOS/Desktop/tdlib,
   версии фиксируются в `tests/vectors/clients.lock`. Захват легален там, где проводится;
   трафик анонимизируется (адреса/IP нормализуются, payload MTProto не дешифруется —
   векторы байт-уровневые).
2. **Синтетические векторы**: сгенерированные harness'ом по спецификации протокола
   (контрольные HMAC-цепочки, граничные split-CH 1/16 записей, ≤4096 Б тело — ADR-000 §5.2).
3. **Отрицательные векторы**: мусор, не-TLS, TLS1.2-only, resumption-CH, битые HMAC,
   replay-дубликаты, skew-CH (timestamp ±121 с).

### 3.2. Формат вектора

```json
{
  "id": "faketls-browser-ch-001",
  "class": "browser-ch-no-secret",
  "transport": "faketls",
  "source": "capture|synthetic",
  "client": "android-<ver>|synthetic",
  "records": [{"direction": "c2p", "hex": "...", "split": 3}],
  "expect": {"classified": "cover", "committed": "cover-relay"},
  "notes": "..."
}
```

- `expect` фиксирует ожидаемую классификацию/коммит по ADR-000 INV-01/INV-04 —
  это семейство B (поведенческая эквивалентность), для эталонного cover ожидание = поведение cover.
- Каждый вектор имеет sha256; индекс — `tests/vectors/index.json`.
- Golden-тест harness'а: `harness corpus verify` проверяет структуру, хеши и компактность
  (bounded-парсеры harness'а не должны паниковать ни на одном векторе).

### 3.3. Приёмка корпуса

- [ ] По ≥1 вектору на каждый класс из §10 (probe-suite) и §3.1.
- [ ] Минимум 20 векторов от ≥2 стоковых клиентов на транспорт (FakeTLS).
- [ ] Negative-векторы покрывают все классы INV-04 PreAuth.

---

## 4. Генератор нагрузки (`crates/harness` bin: `generator`)

Требования ADR-000 §6.2: все профили обязательны, воспроизводимость через seed.

### 4.1. Архитектура

- Rust + Tokio, отдельный однопоточный runtime на счётчик/отчётность, data-часть — multithread.
- Сессии — легковесные акторы: connect → handshake (кадры из корпуса) → payload cadence →
  close/reconnect. Кадры и интервалы — из pcap-производных таблиц (§4.3), не из фантазий.
- Детерминизм: один `seed` → идентичная последовательность событий (с точностью до scheduling);
  seed пишется в manifest. RNG — splitmix64-производные, без глобальных источников энтропии.
- Тайминги относительные: события планируется в виртуальной шкале, привязка к real time —
  драйвером с ограниченным drift; drift превышение → метрика `generator_overload` и флаг в отчёте.

### 4.2. Профили (ADR-000 §6.2 — все обязательны)

| Профиль | Параметры | Первичные метрики |
|---|---|---|
| `idle` | 50k сессий keep-alive, без обмена | RSS/FD/CPU idle |
| `messaging` | 50k, реалистично редкий обмен | базовая совместимость |
| `messaging_hot` | 20k × 3 msg/s двусторонне, кадры 64–512 Б (~60k msg/s) + 30k idle | очереди, p99, allocation rate |
| `mixed_media` | 10–20% сессий качают медиа | throughput, budget refusals |
| `reconnect_storm` | 5–10k conn/s после сбоя | admission, replay, dial rate, recovery-таксономия |

Ограничения генератора на `messaging_hot`/`reconnect_storm` (файловые дескрипторы клиента)
решаются эфемерными пространствами: несколько network namespaces генератора либо
несколько контейнеров `generator-shard-N`; манифест фиксирует шарды.

### 4.3. Кадры из pcap

- Вход: pcap-файлы корпуса §3.1 → нормализация в таблицу кадров: `{dir, size, gap_us_prev, flags}`.
- Таблицы публикуются как `tests/vectors/pcap-derived/<profile>.jsonl` + sha256.
- Абсолютные тайминги отбрасываются; сохраняются распределённые интервалы (для C-семейства —
  точные последовательности размеров записей).

### 4.4. Probe-suite режим генератора

Помимо нагрузки, генератор исполняет probe-suite (§10) как отдельный режим `probe`:
последовательность векторов + фикс ответов; используется для family B и для canary-проверки
стенда перед каждым прогоном (`stand preflight`).

---

## 5. Атрибуция RST (ADR-000 §11.4)

Ground truth по RST обязателен на стенде Phase 0 (eBPF), в продакшене — опционален.

### 5.1. Сбор

| Источник | Что даёт | Частота |
|---|---|---|
| eBPF `tcp:tcp_send_reset`, `tcp:tcp_receive_reset` | событие RST с socket cookie, 4-tuple, ts_ns | поток (ringbuf) |
| `nstat` (`/proc/net/netstat`, `netstat -s`) | `TCPAbortOnData/OnClose/OnMemory/OnTimeout`, `ListenDrops/Overflows` | снапшот каждые 1 с, diff |
| pcap AF_PACKET ring (client-net veth, egress-net veth) | сырые пакеты для споров | ring-файлы по 100 МБ, ретеншн 2 ГБ |
| app-intent счётчики DUT | intent замены/закрытия | scrape /metrics каждые 1 с |

### 5.2. Корреляция

- Ключ: `(4-tuple, ts-окно ±50 мс)`; socket cookie: observer берёт из BPF-события; для клиентской
  стороны генератор логирует `SO_COOKIE` своего сокета при connect (getsockopt) — связка
  cookie ↔ session id пишется в `events.jsonl`.
- Отчёт публикует `rst_ratio` = kernel RST (eBPF, отфильтрованные по 4-tuple DUT) / app intent
  close-события, с разбивкой по фазам PreAuth/PostCommit (INV-04). Расхождение > порога —
  красный флаг инварианта и обязательный разбор в отчёте.

---

## 6. Recovery-таксономия (ADR-000 §11.2 — без изменений, точки замера)

- `t0` — момент инъекции, помечается orchestrator'ом в `events.jsonl` (`kind: injection_start`).
- `upstream_recovery_time` — t0 → первый здоровый egress-маршрут (health-событие upstream-farm/DUT).
- `writer_ready_time` — t0 → первый ME-writer затронутого DC в Ready (метрика DUT, где режим есть).
- `service_recovery_time` — t0 → первое новое клиентское соединение с полным handshake **и payload**
  (подтверждение генератора).
- `client_recovery_fraction(T)` — доля клиентов генератора с живой сессией на t0+T (T=30/60/120 с).
- `session_loss_count`, `forced_reconnect_count` — абсолютные counts генератора.

Сессии на потерянном writer'е — новые сессии; таксономия едина для всех реализаций,
точки замера одинаковы.

---

## 7. Память (ADR-000 §11.3)

| Источник | Что собирается | Кем |
|---|---|---|
| live object census | sessions/writers/queues/buffers — если реализация экспортирует; иначе N/A | scrape /metrics |
| allocator stats | allocated/resident/metadata (jemalloc/tokio-метрики где доступны) | scrape |
| cgroup | `memory.current`, `memory.peak`, `pids.current` | observer |
| RSS slope | регрессия по минутным точкам + 95% CI | report |
| heap-профили | dhat/bytehound — только для собственного кода (Phase 1+); для конкурентов N/A | — |

Критерий утечки: после снятия нагрузки live objects и allocated возвращаются к baseline ± CI;
плато RSS не доказывает отсутствие утечек. soak-прогоны: idle 24 ч, messaging 8 ч (внутри Phase 0
— минимум 1 ч smoke; полные soak — Phase 3, здесь только методика апробируется).

---

## 8. Формат сырых данных

Единый layout, публично публикуемый вместе с отчётом:

```text
runs/<run_id>/
  manifest.json           # полный контекст (ниже)
  raw/
    events.jsonl.gz       # единая timeline всех источников (observer нормализует)
    nstat/<svc>.jsonl.gz  # снапшоты nstat
    pcap/                 # ring-фрагменты, только для прогонов с включённым pcap
    ebpf/                 # сырые ringbuf-дампы
    metrics/              # scrape-слепки /metrics всех сервисов
    cgroup/<svc>.jsonl    # memory.current/peak, pids
  logs/
    dut.log.gz, cover.log.gz, generator.log.gz, chaos.log.gz
  report/
    summary.json          # агрегаты: p50/p95/p99 local/e2e, counts, recovery
    families.json         # A/B/C результаты раздельно (INV-09: не смешивать)
    rst_audit.json        # intent vs kernel (§5.2)
    verdict.json          # PASS/FAIL чеклиста прогона
```

`manifest.json` (минимум):

```json
{
  "run_id": "2026-11-17T…-<slug>",
  "dut": "telemt|mtg|mtdd|cover-ref",
  "versions_lock_sha256": "…",
  "profile": "idle|messaging|messaging_hot|mixed_media|reconnect_storm|probe",
  "netem": {"client": "rtt0-loss0", "egress": "rtt100"},
  "seed": 123456789,
  "sysctl_sha256": "…",
  "host": {"kernel": "…", "cpu": "…", "runtime": "…"},
  "injections": [{"t0_offset_ms": 300000, "kind": "me_blackhole", "target": "dut"}],
  "files": {"<relpath>": {"sha256": "…", "bytes": 123}}
}
```

Правила: `events.jsonl` — единственная хронология (`{ts_ns, source, kind, session?, attrs}`);
каждый файл в manifest хешируется; отчёт без сырых данных не принимается (ADR-000 §11.6).

---

## 9. Инъекции отказов (ADR-000 §11.5, §7; полная матрица — [failure-matrix.md](failure-matrix.md))

| # | Сценарий | Механика инъекции | Измеряемое |
|---|---|---|---|
| F1 | ME blackhole | iptables DROP на egress-плечо DUT→DC, пакеты идут, ACK нет | eviction deadline, INV-03 |
| F2 | ME loss (RST) | та же цель, RST/FIN вместо DROP | writer_lost, reconnect storm |
| F3 | DNS fail/timeout | локальный DNS upstream-farm: REFUSED / silent drop | cover_dns_fail, поведение PreAuth |
| F4 | FD exhaustion | ulimit -n DUT до исчерпания в controlled темпе | accept_failures, изоляция старых сессий |
| F5 | Memory pressure | cgroup MemoryMax DUT ступенчато вниз | budget_refusals, graceful vs OOM |
| F6 | Clock jump | libfaketime/clock-offset в DUT-контейнере ±121 с | hello_clock_skew → cover |
| F7 | Upgrade под нагрузкой | новый бинарник тем же способом, каким реализация умеет (если умеет) | accept_pause_ms, forced_close_ratio |
| F8 | Revoke под нагрузкой | удаление/ротация пользователя через API/конфиг реализации | revoked_sessions, INV-06/§8 |
| F9 | Cover failure | стоп/перегрузка cover | INV-07: MTProto-сессии не деградируют |
| F10 | Egress partition | netem loss 100% на egress-net | upstream failover, дренаж старых |

Каждая инъекция: `(t0, kind, params)` в manifest; orchestrator гарантирует идентичные тайминги
между повторами прогона. Реализация без соответствующей функции → `N/A (отсутствует)` + документация.

---

## 10. Probe-suite классы (family B, ADR-000 §11.1 B)

Ожидание для каждого класса = поведение эталонного cover при том же входе; pass-rate по классам.

| Класс | Вход | Позитивное ожидание |
|---|---|---|
| P01 browser-ch-no-secret | валидный браузерный CH без секрета | поведение = cover (SH/обмен) |
| P02 replay-in-window | дубликат валидного CH в окне 300 с | cover + метрика replay (INV-02) |
| P03 replay-out-window | дубликат за окном | как новый вход |
| P04 garbage | не-TLS байты | поведение cover на мусор (alert/close) |
| P05 not-tls | TLS1.0/кастомный бинарный протокол | то же |
| P06 tls12-only | CH с max=TLS1.2 | поведение cover |
| P07 resumption-ch | CH с pre-shared/resumption индикатором | поведение cover (INV-09: нет session tickets в FakeTLS) |
| P08 silent | connect без данных, hold | тайм-аут как у cover, без RST до deadline (INV-04) |
| P09 valid-probe | валидный CH с секретом | полный handshake (positive control) |
| P10 skew | валидный CH, timestamp ±121 с | cover, метрика hello_clock_skew |
| P11 probes-under-load | P01–P10 в фоне messaging_hot | те же ответы при перегрузке |

Каждый класс = wire-векторы §3 + автоматическая сверка ответа с эталонным cover-прогоном
(пара прогонов: cover-ref и DUT, сравнение нормализованных ответов).

---

## 11. Методика прогонов (ADR-000 §11.6)

1. Один и тот же хост, kernel/sysctl, внешний cover, egress — во всех прогонах серии.
2. Preflight: `stand preflight` — probe P09 на DUT + health всех сервисов; fail → прогон не стартует.
3. Warmup T_w (профиль-зависимый, по умолчанию 60 с) — не включается в отчётные окна.
4. Измеряемое окно T_m (по умолчанию 300 с; reconnect_storm — 120 с после t0 инъекции).
5. Cooldown: снимок leaked-ресурсов (§7) до остановки сервисов.
6. N ≥ 5 прогонов на (DUT × профиль × инъекция-набор); отчёт — медиана + 95% CI (bootstrap,
   10k ресемплов), сырые данные каждого прогона сохраняются.
7. Порядок прогонов рандомизирован по seed'у для развязки с дрейфом окружения; дрейф-контроль:
   повтор эталонного микробенчмарка (cover-ref) до/после серии, расхождение >5% → серия аннулируется.
8. Один инъекционный фактор за прогон (кроме явно заявленных комбо-прогонов), чтобы атрибуция
   была однозначной.

---

## 12. Отчёт (шаблон `harness/report/template.md`)

Обязательные разделы (формат соответствует ADR-000 INV-10):

1. Идентификация: manifest-ссылки, versions.lock, host, дата.
2. Матрица прогонов: DUT × профиль × инъекция × N, статусы preflight.
3. Latency: local/e2e p50/p95/p99 раздельно, с CI.
4. Память: §7 источники, RSS slope + CI, census-таблица.
5. RST-аудит: intent vs kernel, rst_ratio, расхождения с разбором.
6. Recovery: таксономия §6 по каждому сценарию F1–F10.
7. Families: A (совместимость), B (probe pass-rate по классам), C (KS/EMD против cover-ref) —
   раздельно, без смешивания (INV-09).
8. Честные гарантии: drained/forced_close_ratio, accept_pause_ms (INV-10).
9. Ограничения и N/A: отсутствующие функции, ограничения методики (mtg single-secret).
10. Выводы для ADR-001: сырой материал по рубрике §14, без оценки — оценки в ADR.

---

## 13. Открытые вопросы Phase 0 → 1 (из ADR-000 §16)

1. Источник истины ME-handshake/ad_tag при расхождении реализаций — закрыть векторами корпуса.
2. Direct: ограничения медиа по типу аккаунта — зафиксировать тестами (нужны легальные акки).
3. Дефолты kernel buffer caps per profile — только по замерам стенда.
4. Дефолт drain window при upgrade — по распределению длительности сессий (из корпуса).
5. Replay saturation trade-off — политика по данным насыщения (INV-02 тест).
6. Достаточность внешнего cover для probe-equivalence (гипотеза: да) — проверка family B.

---

## 14. Рубрика ADR-001 (шаблон решения — `docs/adr/001-*.md`)

Для каждого подтверждённого дефекта конкурентов (источник: прогонов отчёты §12, п. 7/9,
и аудит исходников по ADR-000 §15):

| Поле | Что фиксируется |
|---|---|
| id | DEF-NNN, ссылка на run_id/строки исходников |
| описание | дефект и наблюдаемое поведение |
| severity | S1 (критично)…S4 (косметика), с обоснованием |
| evidence | run_id, класс пробы, kernel-корреляция — не «мнение ревью» |
| patchability | effort, риск регрессий, вероятность принятия upstream |
| fork-стоимость | стоимость поддержки форка этого дефекта/области |
| стратегическая ценность | что даёт владение ядром для этой области |

Взвешивание — **нарратив, не механический счёт** (ADR-000 §1: «один неисправимый S1 может
оправдать новое ядро; пять S3 могут не оправдать»). Структура решения:

1. Контекст: подтверждённые дефекты (таблица) + подтверждённые достоинства.
2. Варианты: fork (+патчи) / new core / interim-fork → core.
3. Анализ по рубрике выше.
4. Решение и последствия: риски, план, триггеры ревизии ADR.

---

## 15. Чеклист выхода (живой)

Ведётся здесь; пометка + ссылка на run_id/commit обязательна.

- [ ] `versions.lock.toml` воспроизводим (пересборка даёт идентичные sha256).
- [ ] Wire-корпус принят (§3.3), в `tests/vectors/` с индексом.
- [ ] Генератор: все 5 профилей §4.2 прогнаны smoke-режимом на cover-ref.
- [ ] Разделение задержек: два прогон-профиля (netem0/e2e) с раздельными метриками.
- [ ] F1–F10 реализованы и отработаны хотя бы по одному прогону на каждую реализацию.
- [ ] Отчёт по §12 сгенерирован из сырых данных, N ≥ 5 на ячейку сравнения.
- [ ] ADR-001 написан по рубрике §14 и принят.

---

## 16. Порядок работ (внутри Phase 0)

1. versions.lock + сборочный пайп образов конкурентов (§1).
2. Стенд: compose + netem-домены + observer (§2), preflight.
3. Wire-корпус: захват/нормализация/приёмка (§3).
4. Генератор: профили + pcap-таблицы + probe-режим (§4).
5. RST-атрибуция: eBPF + корреляция + сверка (§5).
6. Инъекции F1–F10 (§9) + recovery-инструментация (§6).
7. Прогоны по §11 → отчёт §12 → рубрика §14 → **ADR-001**.
