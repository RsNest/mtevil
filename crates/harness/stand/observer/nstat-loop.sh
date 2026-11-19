#!/bin/sh
# Минимальный nstat-observer: снапшоты TCP-счётчиков из network namespace DUT.
# Спека: phase-0.md §5.2; per-netns kernel counters — корректная изоляция от host.
#
# Ограничения scaffold (честно):
# - интервал жёстко 2 с (спека требует 1 с; полный observer — этап 5 §16);
# - пишет plain JSONL; gzip на seal (harness report seal);
# - nstat с -z выдаёт дельты с прошлого вызова этого же процесса — наблюдатель
#   держит состояние в памяти, что и даёт per-interval дельты.

set -eu
RUN_DIR="${RUN_DIR:-/runs/current}"
DUT_CONTAINER="${DUT_CONTAINER:-mtveil-dut-telemt}"
OUT="${RUN_DIR}/raw/nstat/dut.jsonl"
mkdir -p "$(dirname "$OUT")"

echo "{\"note\":\"nstat-observer start, interval=2s, source=netns-of-${DUT_CONTAINER}\",\"ts\":\"$(date -u +%FT%TZ)\"}" >> "$OUT"

# PID процесса telemt в host-pid namespace (контейнерobserver имеет pid:host).
PID=""
for i in $(seq 1 60); do
    PID=$(pgrep -f '/usr/local/bin/telemt' | head -1 || true)
    if [ -n "$PID" ]; then break; fi
    sleep 1
done
if [ -z "$PID" ]; then
    echo "{\"error\":\"dut process not found\"}" >> "$OUT"
    sleep 3600
    exit 1
fi

NETNS_INUM=$(nsenter -t "$PID" -n sh -c 'readlink /proc/self/ns/net' 2>/dev/null || echo unknown)
echo "{\"note\":\"dut pid=${PID} netns=${NETNS_INUM}\",\"ts\":\"$(date -u +%FT%TZ)\"}" >> "$OUT"

# Счётчики, релевантные RST-аудиту (phase-0.md §5.1) + ListenDrops/Overflows.
PATTERN='TcpExtTCPAbortOn(Data|Close|Memory|Timeout)|TcpExtListen(Drops|Overflows)|TcpActiveOpens|TcpPassiveOpens|TcpExtTCPTimeouts'

while :; do
    ts=$(date -u +%FT%TZ)
    # Дельты с прошлого опроса в netns DUT; формат: "CounterName  value".
    nsenter -t "$PID" -n nstat -z 2>/dev/null | grep -E "$PATTERN" | while read -r name value rest; do
        [ "$value" = "0" ] && continue
        printf '{"ts":"%s","netns":"%s","counter":"%s","delta":%s}\n' "$ts" "$NETNS_INUM" "$name" "$value" >> "$OUT"
    done
    sleep 2
done
