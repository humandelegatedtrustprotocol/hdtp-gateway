# pact-gateway slim image (SPEC §12.3): one static binary on distroless, non-root,
# state on /data. Supervised stdio integrations need runtimes — use the -full image
# (Dockerfile.full) or mount your own.
FROM golang:1.26-alpine AS build
WORKDIR /src
# The node requires the PRIVATE module github.com/pact-cloud/pact-identity/go by version, and
# no credential enters this build. `make identity-proxy` fetches that one module on the host
# (over SSH) into .build/identity-proxy, laid out as a Go module proxy, and the build receives
# it as the named context `identityproxy` (the Makefile's --build-context, compose.yaml's
# additional_contexts). The go command asks that proxy first and the public one for everything
# else; go.sum still verifies what it serves. GONOSUMDB, not GOPRIVATE: GOPRIVATE would also
# skip the proxy list and fetch the module from GitHub directly, which needs the credential.
COPY --from=identityproxy . /identity-proxy
ENV GOPROXY=file:///identity-proxy,https://proxy.golang.org GONOSUMDB=github.com/pact-cloud/*
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=0.1.0-dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /pact-gateway ./cmd/pact-gateway
RUN mkdir /data-skel

FROM gcr.io/distroless/static-debian12:nonroot
# /usr/local/bin is on distroless's PATH, so the documented
# `docker compose exec pact-gateway pact-gateway <cmd>` resolves. Copied to
# BOTH paths: the entrypoint and every doc that says /pact-gateway keep working.
COPY --from=build /pact-gateway /pact-gateway
COPY --from=build /pact-gateway /usr/local/bin/pact-gateway
# named volumes inherit the image's ownership of the mount point on first use;
# distroless has no shell, so seed /data with the right owner at build time
COPY --from=build --chown=nonroot:nonroot /data-skel /data
ENV PACT_DATA_DIR=/data
VOLUME /data
EXPOSE 8080 8443
USER nonroot
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD ["/pact-gateway", "healthcheck"]
ENTRYPOINT ["/pact-gateway"]
CMD ["serve"]
