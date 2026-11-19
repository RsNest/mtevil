# Build from the committed dependency lock. Image tags alone do not prove bit reproducibility.
FROM rust:1.100.0-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY tests/vectors/prototype ./tests/vectors/prototype
RUN cargo build --release --locked -p mtveil-data-plane

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
LABEL org.opencontainers.image.title="mtveil" \
      org.opencontainers.image.version="0.1.0-alpha.1" \
      org.opencontainers.image.description="Experimental MTProto Direct proxy"
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates openssl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 mtveil \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin mtveil \
    && mkdir -p /var/lib/mtveil /etc/mtveil \
    && chown 10001:10001 /var/lib/mtveil
COPY --from=build /src/target/release/mtveil /usr/local/bin/mtveil
USER 10001:10001
EXPOSE 24443
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/mtveil"]
CMD ["--config", "/etc/mtveil/config.json"]
