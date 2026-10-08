# hdtp-gateway slim image (SPEC §12.3): one static binary on distroless, non-root,
# state on /data. Supervised stdio integrations need runtimes — use the -full image
# (Dockerfile.full) or mount your own.
# The limits sidecar (cmd/hdtp-limitd, SPEC §5.7), a static binary beside the node's. Its crates are
# `make limitd-vendor`'s, received as the named context `limitdvendor` (the Makefile's
# --build-context, compose.yaml's additional_contexts), so this build fetches nothing and holds no
# credential. Alpine's Rust links against musl, so the
# binary is static and runs on distroless's static base.
FROM rust:1.92-alpine AS limitd
COPY --from=limitdvendor . /vendor
WORKDIR /src
COPY cmd/hdtp-limitd ./
RUN sed 's#^directory = .*#directory = "/vendor/crates"#' /vendor/config.toml > .cargo/config.toml \
 && cargo build --release --locked --offline

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
# go.mod replaces frp with this directory (scripts/frp-patch.sh), so it is there before the download.
COPY third_party/frp ./third_party/frp
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=0.1.0-dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /hdtp-gateway ./cmd/hdtp-gateway
RUN mkdir /data-skel

FROM gcr.io/distroless/static-debian12:nonroot
# /usr/local/bin is on distroless's PATH, so the documented
# `docker compose exec hdtp-gateway hdtp-gateway <cmd>` resolves. Copied to
# BOTH paths: the entrypoint and every doc that says /hdtp-gateway keep working.
COPY --from=build /hdtp-gateway /hdtp-gateway
COPY --from=build /hdtp-gateway /usr/local/bin/hdtp-gateway
# The limits sidecar and its shipped configuration: the same image runs it as a process of its own
# (`--entrypoint /hdtp-limitd`, compose.yaml's `limitd`), socket /data/limits.sock, which is the
# node's default limits_socket under /data.
COPY --from=limitd /src/target/release/hdtp-limitd /hdtp-limitd
COPY deploy/limitd/limits.json /etc/hdtp-limitd/limits.json
# named volumes inherit the image's ownership of the mount point on first use;
# distroless has no shell, so seed /data with the right owner at build time
COPY --from=build --chown=nonroot:nonroot /data-skel /data
ENV HDTP_DATA_DIR=/data
VOLUME /data
EXPOSE 8080 8443
USER nonroot
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD ["/hdtp-gateway", "healthcheck"]
ENTRYPOINT ["/hdtp-gateway"]
CMD ["serve"]
