# rst-observer: bpftrace из пакетной базы Ubuntu (официальный bpftrace/bpftrace
# недоступен на docker hub и ghcr — проверено 2026-11-17, см. compose.yaml).
# ВАЖНО: версия bpftrace должна понимать BTF/tracepoint-форматы host-ядра
# (7.0 на тестовой VM): 24.04 не знал полей state/reason нового формата — падал
# attach. ubuntu:26.04 соответствует поколению ядра стенда.
# Base-образ пинится digest'ом после первого pull (env прогона).
FROM ubuntu:26.04
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends bpftrace && rm -rf /var/lib/apt/lists/*
COPY rst-observer/reset.bt /reset.bt
ENTRYPOINT ["/usr/bin/bpftrace", "-B", "line", "/reset.bt"]
