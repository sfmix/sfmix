# Build context is the looking-glass/ workspace root, so all member crates are
# visible to cargo. Invoke with:  docker build -f lg-neighborhood-watch/Dockerfile .
FROM rust:1-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release -p lg-neighborhood-watch

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 10185 neighwatch
COPY --from=builder /build/target/release/lg-neighborhood-watch /usr/local/bin/lg-neighborhood-watch
# Grant raw-socket capability to the binary so it can capture (AF_PACKET) and
# solicit (raw ICMP) while running unprivileged. The container must still be run
# with --cap-add NET_RAW so the capability is in the bounding set.
RUN setcap cap_net_raw+ep /usr/local/bin/lg-neighborhood-watch
USER neighwatch
ENTRYPOINT ["/usr/local/bin/lg-neighborhood-watch"]
