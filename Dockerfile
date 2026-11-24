# Multi-stage zero-dependency Rust musl build (< 10 MB final image, non-root)
FROM rust:1.83-alpine AS builder
WORKDIR /src
COPY Cargo.toml ./
COPY assets/logo.png ./assets/logo.png
COPY assets/devices ./assets/devices
COPY src ./src
RUN cargo test && \
    cargo build --release && \
    strip target/release/thread2mqtt

FROM alpine:3.21
RUN adduser -D -u 1000 thread2mqtt
USER 1000:1000
WORKDIR /app
COPY --from=builder /src/target/release/thread2mqtt /usr/local/bin/thread2mqtt
EXPOSE 8099
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8099/health >/dev/null 2>&1 || exit 1
ENTRYPOINT ["/usr/local/bin/thread2mqtt"]
