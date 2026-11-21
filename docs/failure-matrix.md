# Failure matrix — mtevil

> **Статус:** действует. Сокращённая версия — ADR-000 §7. Каждая строка должна иметь
> покрывающий тест в `tests/inv/` (имя ссылается на INV-xx) или строку `N/A (отсутствует)`
> в отчёте Phase 0 для реализаций без соответствующей функции.
> Механика инъекций — [specs/phase-0.md §9](specs/phase-0.md).

Идентификаторы `F-NN` — канонические ссылки для тестов и отчётов. Инъекционные сценарии
Phase 0 (F1–F10 в phase-0.md §9) — подмножество; столбец «Инъекция» ссылается на них.

## 1. Матрица

| ID | Сбой | Фаза | Ожидаемое поведение | Метрика | INV | Инъекция |
|---|---|---|---|---|---|---|
| F-01 | DNS cover недоступен | PreAuth/PreCommit | cached address → relay; кэша нет → bounded graceful close | cover_dns_fail | INV-04 | F3 |
| F-02 | DNS timeout (не отказ) | PreAuth/PreCommit | то же, с тайм-аутом ≤ configured deadline | cover_dns_fail, dns_deadline_exceeded | INV-03, INV-04 | F3 |
| F-03 | Cover connect fail (основная цель) | PreAuth/PreCommit | запасная цель → relay; нет запасной → graceful close | cover_connect_fail | INV-04 | F9 |
| F-04 | Cover перегрузка/сбой процесса | PreAuth + установленные сессии | новые PreAuth деградируют по INV-04; MTProto-сессии **не страдают** | cover_overload_degrades, mtproto_sessions_survive | INV-07 | F9 |
| F-05 | ME dial fail | PostCommit | close сессии + reconnect клиента; новых bind на мёртвого writer нет | me_dial_fail | INV-05 | F2 |
| F-06 | ME blackhole (падение, без RST) | PostCommit | eviction по совокупности признаков в deadline; сессии закрыты `me_writer_lost` | me_slow_evictions, budget_stall_timeout | INV-03, INV-05 | F1 |
| F-07 | ME writer loss (RST/FIN) | PostCommit | немедленное `me_writer_lost` → закрытие привязанных клиентов | me_writer_lost | INV-05 | F2 |
| F-08 | ME плановая замена writer'а | PostCommit | старый не принимает новых → дренаж/deadline → закрытие | me_drain_forced_close | INV-05 | F2 |
| F-09 | Partial write в клиентский сокет | обе | bounded retry с точного byte-offset, без повторного шифрования | partial_writes | INV-05 | N/A (нагрузка) |
| F-10 | Client FIN | обе | graceful: stop reads → flush → shutdown(WR) → drain inbound (bounded) → close | close_reasons | INV-04, §5.5 | N/A (нагрузка) |
| F-11 | Client RST | обе | очистка ресурсов сессии; в kernel это не app-RST | close_reasons | INV-04 | N/A (нагрузка) |
| F-12 | Budget exhausted (userspace) | PreAuth | relay в cover (дешёвый путь) | budget_refusals | INV-03 | F5 |
| F-13 | Budget exhausted | PostCommit | пауза чтения (backpressure), не разрыв; emergency reserve на служебные пути | budget_refusals, reserve_usage, paused_duration_p99 | INV-03 | F5 |
| F-14 | Emergency reserve exhausted | PostCommit | пути освобождения не требуют бюджета; graceful close по deadline | budget_stall_timeout | INV-03 | F5+F1 |
| F-15 | FD exhaustion на accept / бюджет FD | PreAuth | На старте `effective_max = min(max_connections, (nofile - 128) / 2)` (fail-fast `< 16`); на accept backoff 10 мс..1 с (`EMFILE`/`ENFILE`/`ENOBUFS`/`ENOMEM`), транзиентные `ECONNABORTED`/`ECONNRESET` игнорируются; установленные сессии не страдают | accept_errors{kind}, effective_max_connections | §6.1 | F4 |
| F-16 | Memory pressure (cgroup) | обе | admission-отказы на PreAuth (→cover); PostCommit — backpressure; OOM — вне инварианта | budget_refusals, process_restarts | INV-03, §6.1 | F5 |
| F-17 | Revoke пользователя | PostCommit | `immediate` (default): close; `grace-drain`: дренаж по deadline | revoked_sessions | §8 | F8 |
| F-18 | Ротация секрета | обе | default `revoke`: старые сессии закрыты; `keep-until-close` — опция | secret_rotations | §8 | F8 |
| F-19 | Clock jump >120 с | PreAuth | CH в skew → cover; готовые сессии не страдают | hello_clock_skew | §5.2 | F6 |
| F-20 | Replay-таблица saturated | PreAuth | sweep; полно → CoverRelay новых CH (fail-safe наружу) | replay_saturated_relays | INV-02 | нагрузка |
| F-21 | Replay: смерть владельца мьютекса | PreAuth | robust mutex `EOWNERDEAD` → recovery → ровно один Accepted из двух CH | replay_owner_died_recoveries | INV-02 | тест барьером |
| F-22 | Replay-файл потерян (reboot/crash) | PreAuth | честный рестарт с пустой таблицей; остаточный риск <120 с задокументирован | replay_table_reinit | INV-02 | рестарт стенда |
| F-23 | Upstream fail | PostCommit | новые conn на здоровый маршрут (circuit breaker с экспоненциальным backoff `egress_cooldown_base_ms`..`egress_cooldown_max_ms` ×2 ±20% jitter, сброс на успехе); старые дренируются по deadline | upstream_failover | §7 | F10 |
| F-24 | Egress partition (loss 100%) / все в cooldown | PostCommit | как F-23 + fail-open проба + фоновый монитор (`30 с` / `5 с` при деградации, ротация DC `2, 4, -2, -4`) ставит и снимает cooldown без жертвы живым клиентом | upstream_recovery_time, service_recovery_time | §11.2 | F10 |
| F-25 | Config prepare fail на любой стадии | control | drop PrepareSet → автооткат внешних ресурсов; commit не случается | config_prepare_failures | INV-06 | тест-фолт |
| F-26 | Config retire error | control | лог/ретрай, commit не блокируется; reconcile против сирот | config_retire_errors, config_orphans | INV-06 | тест-фолт |
| F-27 | Control API flood + blocking-шторм | control vs data | p99 data plane в пределах +10% или ADR-002 триггер | api_flood_p99_delta | INV-07, §3 | нагрузка |
| F-28 | Cover backend replacement | PreAuth | новые relay-соединения на новый бэкенд; старые доживают | cover_backend_swaps | §8 | нагрузка |
| F-29 | Upgrade процесса под нагрузкой | обе | zero accept-pause (REUSEPORT/SCM_RIGHTS); drain по deadline; forced close **с подсчётом** | accept_pause_ms, drained_sessions, forced_close_ratio | §9, INV-10 | F7 |
| F-30 | Watchdog kill (OOM/kill -9) | обе | supervisor restart; сессии теряются честно | process_restarts | INV-10 | chaos |
| F-31 | Guard: подозрительный источник (suspect) | PreAuth | shadow-ban → cover; canary-валидация исключений | suspects_shadow_banned | guard | нагрузка |
| F-32 | Half-close (client SHUT_WR) | PostCommit | дожитие в drain-семантике §5.5, без преждевременного close | close_reasons | INV-04 | N/A (probe) |
| F-33 | TCP zero window клиента | PostCommit | backpressure по outbound, deadline → graceful close | budget_stall_timeout | INV-03 | netem |
| F-34 | Reordering/dup на пути | обе | корректность FIFO per-client сохраняется | fifo_violations (должно быть 0) | INV-05 | netem |
| F-35 | Lie-пакеты/пробинг под нагрузкой | PreAuth | те же ответы P01–P11, что и без нагрузки | probe_pass_rate_under_load | INV-04, §10 | P11 |

## 2. Правила применения

1. Каждый тест `tests/inv/` ссылается на ID из этой матрицы и на INV-xx в имени.
2. Фаза «PreAuth/PreCommit» vs «PostCommit» определяется по INV-01 (первая запись байта
   протокола в клиентский сокет = коммит).
3. «Bounded» всегда означает: и байт-лимит, и время-лимит; оба параметра — конфиг.
4. Строки, недостижимые для конкретной реализации в Phase 0, в сравнительном отчёте
   помечаются `N/A (отсутствует)` — расхождение семантики документируется (ADR-000 §11.5).
5. Изменение строки матрицы — через ADR, если меняет инвариант; иначе — PR с обновлением
   покрывающих тестов.
