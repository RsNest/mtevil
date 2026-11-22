# Build from the committed dependency lock. Image tags alone do not prove bit reproducibility.
FROM rust:1.100.0-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY tests/vectors/prototype ./tests/vectors/prototype
COPY tests/inv ./tests/inv
ARG MTEVIL_VERSION=0.1.0-dev
ENV MTEVIL_BUILD_VERSION=${MTEVIL_VERSION}
RUN cargo build --release --locked -p mtevil-data-plane

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
ARG MTEVIL_VERSION=0.1.0-dev
ARG MTEVIL_REVISION=unknown
LABEL org.opencontainers.image.title="mtevil" \
      org.opencontainers.image.version="${MTEVIL_VERSION}" \
      org.opencontainers.image.revision="${MTEVIL_REVISION}" \
      org.opencontainers.image.description="Experimental MTProto Direct proxy"
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates openssl curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 mtevil \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin mtevil \
    && mkdir -p /var/lib/mtevil /var/lib/mtevil-replay /etc/mtevil \
    && chown 10001:10001 /var/lib/mtevil /var/lib/mtevil-replay \
    && chmod 0700 /var/lib/mtevil-replay
COPY --from=build /src/target/release/mtevil /usr/local/bin/mtevil
USER 10001:10001
EXPOSE 24443
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/mtevil"]
CMD ["--config", "/etc/mtevil/config.json"]
