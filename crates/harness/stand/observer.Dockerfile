# Минимальный nstat-observer: alpine + iproute2 (nstat) + util-linux (nsenter) + curl.
# Базовый образ пинится digest'ом после первого pull (запись в env прогона).
FROM alpine:3.21
RUN apk add --no-cache iproute2 util-linux curl jq
COPY observer/nstat-loop.sh /observer/nstat-loop.sh
RUN chmod +x /observer/nstat-loop.sh
ENTRYPOINT ["/bin/sh", "/observer/nstat-loop.sh"]
