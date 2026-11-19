# Сборка DUT telemt из pinned коммита (versions.lock candidates.telemt).
# ВАЖНО (честность pinning'а):
# - TELEMT_REF — полный sha из versions.lock; сборка воспроизводима по дереву исходников,
#   но build_reproducible=false: байт-идентичность бинарника между сборками не доказана
#   (Cargo.lock версионируется в репо telemt, но toolchain rust:1-bookworm плавает —
#   перед claim'ом reproducibility pin digest'а rust-образа и cargo --locked обязательны).
# - Базовые образы пинятся digest'ом после первого pull (записывается в env прогона).

FROM rust:1-bookworm AS build
ARG TELEMT_REF=dac7aeeeda55951cf03a229ee9357e2af558d45e
WORKDIR /src
RUN git clone https://github.com/telemt/telemt . \
    && git checkout --detach "${TELEMT_REF}" \
    && git rev-parse HEAD > /src/pinned-commit.txt \
    && cargo build --release

FROM debian:bookworm-slim
ARG TELEMT_REF=dac7aeeeda55951cf03a229ee9357e2af558d45e
LABEL mtevil.dut="telemt" mtevil.ref="${TELEMT_REF}"
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/telemt /usr/local/bin/telemt
COPY --from=build /src/pinned-commit.txt /etc/telemt/pinned-commit.txt
COPY dut-telemt.toml /etc/telemt/telemt.toml
EXPOSE 443
ENTRYPOINT ["/usr/local/bin/telemt"]
