#!/bin/bash
# Infrastructure smoke — phase-0.md §16 этап 2. НЕ бенчмарк, не заявляет
# нагрузочные профили, совместимость, INV или завершённость сравнения.
#
# Infrastructure smoke: 1 session per probe, seed 0; actual duration is recorded.
# CPU: generator-stub/DUT/observer делят host CPU — contention возможен
# (записывается vmstat в env).
set -eu
set -o pipefail
SMOKE_START=$(date +%s)
cleanup() {
    docker compose -f crates/harness/stand/compose.yaml stop rst-observer nstat-observer >/dev/null 2>&1 || true
    if [ -n "${BPF_LOG_PID:-}" ]; then kill "$BPF_LOG_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT
cd "$(dirname "$0")/../../../.."   # → корень репо (smoke → stand → harness → crates → root)

export PATH="$HOME/.cargo/bin:$PATH"
HARNESS=target/release/mtveil-harness
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-infra-smoke"
RUN_DIR="runs/${RUN_ID}"
STAND=crates/harness/stand

echo "=== [1/8] run dir: ${RUN_DIR} (симлинк runs/current)"
mkdir -p "${RUN_DIR}/raw/nstat" "${RUN_DIR}/raw/ebpf" "${RUN_DIR}/raw/events" "${RUN_DIR}/logs" "${RUN_DIR}/report" "${RUN_DIR}/env"
# Цель симлинка — имя соседа внутри runs/ (не "runs/<id>": иначе симлинк висячий
# и внутри observer-контейнера /runs/current не резолвится).
rm -f runs/current && ln -sfn "${RUN_ID}" runs/current

echo "=== [2/8] stand up (pinned DUT telemt)"
"${HARNESS}" stand up --allow-unpinned 2>&1 | tee "${RUN_DIR}/logs/harness-up.log"
docker compose -f "${STAND}/compose.yaml" logs --no-log-prefix cover > "${RUN_DIR}/logs/cover.log" 2>&1 || true

echo "=== [3/8] ожидание DUT (telemt инициализирует DC-connectivity ~40 c до bind:443)"
# ВАЖНО: проверка ВНУТРИ контейнера DUT — docker-proxy на published-порту
# принимает TCP даже когда бэкенд не слушает (обнаружено 2026-11-17: refused
# из client-stub при 'успешном' host-чеке).
DUT_WAIT_START=$(date +%s)
for i in $(seq 1 60); do
    if docker exec mtveil-dut-telemt bash -c 'exec 3<>/dev/tcp/127.0.0.1/443' 2>/dev/null; then break; fi
    sleep 2
done
DUT_WAIT_S=$(( $(date +%s) - DUT_WAIT_START ))
echo "dut_startup_wait_s=${DUT_WAIT_S} (метод: docker-exec /dev/tcp, не host-port)" | tee "${RUN_DIR}/env/dut-startup-wait.txt"
if ! docker exec mtveil-dut-telemt bash -c 'exec 3<>/dev/tcp/127.0.0.1/443' 2>/dev/null; then
    echo "FAIL: DUT не начал слушать 443 внутри контейнера за 120 c — лог: docker logs mtveil-dut-telemt"
    exit 1
fi

echo "=== [3b/8] start rst-observer capture (bpftrace → raw/ebpf/reset.log)"
# rst-observer пишет в stdout контейнера; направляем в файл через docker logs -f
docker logs --since 0s -f mtveil-rst-observer > "${RUN_DIR}/raw/ebpf/reset.log" 2>&1 &
BPF_LOG_PID=$!
sleep 3   # attach bpftrace

echo "=== [4/8] client-stub пробы (controlled RST, closed port, garbage)"
# --entrypoint обязателен: compose run не переопределяет entrypoint контейнера
docker compose -f "${STAND}/compose.yaml" --profile tools run --rm --entrypoint python3 client-stub \
    /client/probe.py mtveil-dut-telemt 443 9999 \
    > "${RUN_DIR}/raw/events/probe-stub.jsonl" 2>&1
cat "${RUN_DIR}/raw/events/probe-stub.jsonl"

echo "=== [5/8] DUT-netns HTTP fetch до cover (дельты nstat в netns DUT)"
DUT_PID=$(pgrep -f '/usr/local/bin/telemt' | head -1)
echo "dut pid: ${DUT_PID}" | tee "${RUN_DIR}/env/dut-pid.txt"
docker exec mtveil-nstat-observer sh -c \
    "nsenter -t ${DUT_PID} -n curl -sS -m 5 -o /dev/null -w 'http_code=%{http_code}\n' http://mtveil-cover:80/" \
    2>&1 | tee -a "${RUN_DIR}/raw/events/dut-netns-curl.log"
docker exec mtveil-nstat-observer sh -c \
    "nsenter -t ${DUT_PID} -n curl -sS -m 5 http://mtveil-upstream-farm:80/" \
    2>&1 | tee -a "${RUN_DIR}/raw/events/dut-netns-curl.log"

echo "=== [6/8] vmstat (CPU contention evidence)"
vmstat 1 5 > "${RUN_DIR}/env/vmstat.txt" 2>&1 || true
cat /proc/loadavg > "${RUN_DIR}/env/loadavg-end.txt"

echo "=== live preflight (exit 2 explicitly means P09 is still unimplemented)"
set +e
"${HARNESS}" stand preflight --dut telemt --allow-unimplemented 2>&1 | tee "${RUN_DIR}/logs/preflight.log"
PF=${PIPESTATUS[0]}
set -e
if [ "$PF" -ne 0 ] && [ "$PF" -ne 2 ]; then
    echo "FAIL: infrastructure preflight exit=$PF"
    exit 1
fi
cp crates/harness/config/versions.lock.toml "${RUN_DIR}/env/versions.lock.snapshot.toml"
sysctl net.ipv4.tcp_rmem net.ipv4.tcp_wmem net.core.somaxconn > "${RUN_DIR}/env/sysctl.txt"
echo "=== [7/8] остановка сбора, съём буферизованных логов, gzip улик"
sleep 2   # дать nstat-observer доснять дельты
# Порядок важен: сначала СТОП контейнера (bpftrace флэшит блок-буфер stdout
# при выходе — docker logs -f не увидит события до завершения процесса),
# потом снимаем ПОЛНЫЙ лог контейнера.
docker compose -f "${STAND}/compose.yaml" stop rst-observer nstat-observer > /dev/null 2>&1 || true
kill "${BPF_LOG_PID}" 2>/dev/null || true
docker logs mtveil-rst-observer > "${RUN_DIR}/raw/ebpf/reset.log" 2>&1 || true
docker logs mtveil-nstat-observer > "${RUN_DIR}/logs/nstat-observer.log" 2>&1 || true
docker compose -f "${STAND}/compose.yaml" logs dut-telemt > "${RUN_DIR}/logs/dut.log" 2>&1 || true
gzip -f "${RUN_DIR}/raw/nstat/dut.jsonl" "${RUN_DIR}"/logs/*.log
cp "${RUN_DIR}/raw/events/probe-stub.jsonl" "${RUN_DIR}/raw/events.jsonl.tmp"
gzip -f "${RUN_DIR}/raw/events.jsonl.tmp" && mv "${RUN_DIR}/raw/events.jsonl.tmp.gz" "${RUN_DIR}/raw/events.jsonl.gz"

echo "=== [8/8] report summary + seal + lint"
cat > "${RUN_DIR}/report/summary.json" <<EOF
{
  "status": "infrastructure-smoke",
  "claims": {
    "load_profiles": false,
    "protocol_compatibility": false,
    "inv_tests": false,
    "benchmark": false
  },
  "probes": ["controlled-rst", "closed-port-no-socket", "garbage-http"],
  "duration_s": $(( $(date +%s) - SMOKE_START )),
  "preflight_exit": ${PF},
  "note": "scaffold observability validation only"
}
EOF
sha_vl="$(sha256sum crates/harness/config/versions.lock.toml | cut -d' ' -f1)"
"${HARNESS}" report seal \
    --run-dir "${RUN_DIR}" --dut telemt --profile probe --seed 0 \
    --versions-lock-sha256 "${sha_vl}" --sysctl-sha256 "$(sha256sum "${RUN_DIR}/env/sysctl.txt" | cut -d' ' -f1)" \
    --netem-client zero --netem-egress zero
"${HARNESS}" report lint --run-dir "${RUN_DIR}"


echo ""
echo "SMOKE COMPLETE: ${RUN_DIR}"
echo "Ключевые улики:"
echo "  - raw/ebpf/reset.log        (tracepoint события SEND/RECV_RESET)"
echo "  - raw/nstat/dut.jsonl.gz    (per-netns счётчики DUT)"
echo "  - raw/events/probe-stub.jsonl (пробы клиента)"
echo "  - logs/dut.log.gz, env/     (cpu allocation, digests)"
