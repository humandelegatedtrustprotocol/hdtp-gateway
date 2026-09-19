BINARY := pact-gateway
VERSION ?= 0.1.0-dev

.PHONY: sqlc sqlc-check distclean hooks all analyze vulncheck staticcheck gosec fuzz web dist sbom build check fmt vet dependents test clean harness harness-preflight harness-live harness-image harness-image-caldav harness-shaper screenshots harness-pr harness-nightly harness-kernel

# all is the full local pre-flight, in the one order that is correct.
#
# `web` comes FIRST because the bundle-contract tests read the embedded
# web/dist: running check before it greenlights whatever bundle happened to be
# committed, not the one your sources produce. `sbom` comes LAST because `dist`
# starts by deleting the directory sbom writes into.
#
# What it does NOT do, so a green run is not mistaken for more than it is: the
# scenario harness (separate module, needs Docker — `make harness`, or
# `harness-pr` / `harness-nightly` for the live tiers) and the container images
# (`harness-image`).
all: web check analyze build dist sbom
	@echo
	@echo "all: portal rebuilt, gate green, analysis clean, artifacts in dist/"

# analyze runs exactly what CI runs, so what fails there fails here first.
# The versions are pinned HERE and the workflow calls these targets — one list,
# not two to drift apart.
analyze: vulncheck staticcheck gosec

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...

staticcheck:
	go run honnef.co/go/tools/cmd/staticcheck@2025.1.1 ./...

# G101 fires on generated sqlc SQL text, G104 on Close(), and G304 on file paths
# the OWNER supplies on the command line. The rules that matter — G402 TLS
# posture, G203 escaping, G115 conversions, G204 subprocess — stay on, and the
# handful of by-design hits carry #nosec with a reason.
gosec:
	go run github.com/securego/gosec/v2/cmd/gosec@v2.22.9 \
		-quiet -exclude-dir=harness -exclude=G101,G104,G304 ./...

# Every parser that meets untrusted input, 30s each. Deliberately not part of
# `all`: two minutes of wall clock that finds nothing on most runs. CI runs it
# on every push, and TestEveryFuzzTargetRunsInCI fails the build if a target is
# added and this list is not.
fuzz:
	go test ./internal/contacts/ -run '^FuzzVCardParse$$'    -fuzz '^FuzzVCardParse$$'    -fuzztime 30s
	go test ./internal/public/   -run '^FuzzSealedPayload$$' -fuzz '^FuzzSealedPayload$$' -fuzztime 30s
	go test ./internal/cli/      -run '^FuzzInviteOffer$$'   -fuzz '^FuzzInviteOffer$$'   -fuzztime 30s
	go test ./internal/core/     -run '^FuzzRedact$$'        -fuzz '^FuzzRedact$$'      -fuzztime 30s

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BINARY) ./cmd/pact-gateway

# PLATFORMS is what a release ships. CGO is off and -trimpath is set for every
# one, so the binary depends on no host libc and embeds no build paths — which is
# what lets a third party rebuild a tag and compare checksums.
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

# dist builds every platform and writes SHA256SUMS. The release workflow runs this
# exact target rather than its own build commands, so what CI ships is what a
# maintainer can reproduce locally.
dist:
	@rm -rf dist && mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; out=dist/$(BINARY)_$(VERSION)_$${os}_$${arch}; \
		echo "building $$out"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath \
			-ldflags "-s -w -X main.version=$(VERSION)" -o $$out ./cmd/pact-gateway || exit 1; \
	done
	@cd dist && shasum -a 256 * > SHA256SUMS && cat SHA256SUMS

# hooks points git at the versioned hooks in githooks/ — the path is relative to
# the repository root, one level up from this module. One setting, and the
# hooks travel with the repository instead of living in an untracked .git/hooks
# that every clone starts without.
hooks:
	git config core.hooksPath pact-gateway/githooks
	@echo "hooks installed: $$(git config core.hooksPath)"
	@echo "pre-push runs the harness — the tier CI cannot run (no Chrome on a runner)."

# web rebuilds the embedded portal SPA. Its OUTPUT (web/dist) is committed, so
# plain `go build` and the release workflow need no Node toolchain; run this
# after changing anything under web/src and commit what it writes.
web:
	cd web && npm ci && npm run build

# sbom emits CycloneDX for the shipped binary's dependency graph. Pinned, not
# @latest: a supply-chain document produced by an unpinned tool is worth less.
sbom:
	@mkdir -p dist
	go run github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.9.0 \
		app -json -licenses=false -main cmd/pact-gateway -output dist/sbom.cdx.json .
	@echo "wrote dist/sbom.cdx.json"

# check covers the PRODUCT only. The harness is a separate module (harness/go.mod),
# so `go vet ./...` and `go test ./...` here do not see it — which is the point:
# its CDP and orchestration dependencies stay out of the shipped artifact's
# dependency and vulnerability surface. Run `make harness` for that module.
check: fmt vet dependents test

# SQLC pins the generator. It is pinned HERE and nowhere else: `sqlc` is not
# installed on any machine that builds this, and the version matters more than
# usual because v1.30.0 slices statements out of the query files by a RUNE offset
# while reading BYTES — one em dash in a comment silently corrupts every statement
# after it (see TestQuerySourcesAreASCII, and F8 in
# pact-cloud/docs/release/findings-2026-09-18-rig.md). v1.27.0 and below do not
# build on a current macOS SDK at all (strchrnul, pg_query_go v5).
SQLC := go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.30.0

# `make sqlc` after any change to migrations/ or queries/. The generated code is
# committed, so a change that skips this leaves the store reading a schema that
# does not exist.
sqlc:
	$(SQLC) generate
	@gofmt -l internal/core/store/sqlitedb internal/core/store/pgdb | (! grep .) \
		|| { echo "sqlc output is not gofmt-clean"; exit 1; }
	@echo "sqlc: internal/core/store/{sqlitedb,pgdb} regenerated"

# sqlc-check fails when the committed generated code does not match what the
# current sources produce. NOT part of `check`: it builds sqlc from source, which
# is minutes, and `check` runs on every commit. CI and `make all` are where it
# belongs, and it is named here rather than left implicit because the drift it
# catches is exactly what went unnoticed for weeks.
sqlc-check:
	@tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
		cp -R internal/core/store/sqlitedb internal/core/store/pgdb "$$tmp/"; \
		$(SQLC) generate; \
		if diff -r "$$tmp/sqlitedb" internal/core/store/sqlitedb >/dev/null \
		&& diff -r "$$tmp/pgdb" internal/core/store/pgdb >/dev/null; then \
			echo "sqlc-check: generated code matches its sources"; \
		else \
			echo "sqlc-check: generated code is STALE - run make sqlc and commit the result"; \
			diff -r "$$tmp/sqlitedb" internal/core/store/sqlitedb | head -20; \
			diff -r "$$tmp/pgdb" internal/core/store/pgdb | head -20; \
			exit 1; \
		fi

fmt:
	@d=$$(gofmt -l .); if [ -n "$$d" ]; then echo "gofmt needed:"; echo "$$d"; exit 1; fi

vet:
	go vet ./...

# The cloud's Go conformance battery imports this module's `internal/` packages, so moving an
# API here breaks it THERE. It is a separate module in a separate repository and runs only from
# `scripts/conformance.sh` against a deployed node, so nothing compiled it: on 2026-09-19 it
# stopped compiling twice in one day — `Keypair.Protocol` removed, then `Call`'s signature — and
# neither was noticed until an unrelated `go vet` happened to run over it. The repository that
# moves the API is the one whose gate has to object, so this vets it whenever the sibling is on
# disk. CI checks out no sibling; there it says it skipped rather than passing quietly.
#
# The scenario harness (./harness) is the same shape and closer to home: a separate module in THIS
# repository that imports `internal/`, built by the pre-push hook and by nothing else. The same two
# removals broke it the same day, and the fix above — made for the cloud's battery — walked past it.
# It is always on disk, so it is always vetted.
CLOUD_BATTERY := ../pact-cloud/gateway/conformance
dependents:
	@echo "go vet ./harness/..."
	@(cd harness && go vet ./...) || { \
		echo "the scenario harness no longer compiles against this module:"; \
		echo "  it is a separate Go module that imports internal/, and until 2026-09-19 only the"; \
		echo "  pre-push hook built it — so it broke in B3c and was found at the first push."; exit 1; }
	@if [ -d "$(CLOUD_BATTERY)" ]; then \
		echo "go vet $(CLOUD_BATTERY)"; \
		(cd "$(CLOUD_BATTERY)" && go vet ./...) || { \
			echo "the cloud's conformance battery no longer compiles against this module:"; \
			echo "  fix it in $(CLOUD_BATTERY) in the same change that moved the API"; exit 1; }; \
	else \
		echo "!! dependents: $(CLOUD_BATTERY) is not on disk, so the cloud's conformance battery"; \
		echo "   was NOT compiled against this change. It imports internal/ packages of this module."; \
	fi

# ./... reaches into web/node_modules, which vendors a Go package of its own
# (flatted). Naming the module's real trees keeps the run to this repository's
# code and stops a dependency's test failures from reading as ours.
test:
	go test -race ./cmd/... ./internal/...

# The scenario harness (docs/harness-design.md). Separate module, separate command,
# deliberately not part of `check`.
harness:
	cd harness && go vet ./... && go test -race ./...

# The node image the harness stands topologies up from: the shipped artifact,
# built from the repo's own Dockerfile.
harness-image:
	docker build --build-context pactidentity=../pact-identity/go -t pact-gateway:harness .

# The calendar scenario (S4) needs the -FULL image — node and uv, so a supervised
# stdio child can run in-container (SPEC §12.3) — with the upstream MCP server
# already installed. Installed at build time rather than fetched by `npx` at run
# time so the scenario does not depend on reaching a package registry mid-test,
# and so what it exercises is a pinned version.
harness-image-caldav:
	docker build --build-context pactidentity=../pact-identity/go -f Dockerfile.full -t pact-gateway:harness-full .
	printf 'FROM pact-gateway:harness-full\nUSER root\nRUN npm install -g caldav-mcp@0.10.0 && chown -R 65532:65532 /usr/local/lib/node_modules\nUSER 65532:65532\n' \
	  | docker build -t pact-gateway:harness-caldav -

# The shaper image: iproute2 preinstalled. It must ship tc rather than install it,
# because the shaper runs inside the target's network namespace and cannot reach a
# package repo through a partition it just created.
harness-shaper:
	printf 'FROM alpine:3.20\nRUN apk add --no-cache iproute2\n' | docker build -t pact-harness-shaper:1 -

# An aarch64 Linux kernel for the VM topology (S8). Extracted from Alpine's arm64
# image so no download or host toolchain is needed. Export PACT_HARNESS_KERNEL to
# the printed path to enable the VM tests.
KERNEL_DIR ?= .harness-kernel
harness-kernel:
	@mkdir -p $(KERNEL_DIR)
	@docker run --rm --platform linux/arm64 -v "$(PWD)/$(KERNEL_DIR):/out" alpine:3.20 \
	  sh -c 'apk add --no-cache linux-virt >/dev/null 2>&1 && cp /boot/vmlinuz-virt /out/'
	@echo "export PACT_HARNESS_KERNEL=$(PWD)/$(KERNEL_DIR)/vmlinuz-virt"

# ---- run tiers (docs/harness-design.md §6) --------------------------------
# The tiers exist because the full matrix is slow enough that people stop reading
# the result. What each tier DROPS is named, so a green run is never mistaken for
# more coverage than it is.

# PR tier: everything hermetic, plus the two live suites that carry the most
# signal per second. Does NOT run: resilience (S7), long-horizon time (S8),
# CalDAV booking (S4), portal screenshots (S11), or topologies T3-T6.
harness-pr: harness
	cd harness && PACT_HARNESS_LIVE=1 go test ./... -run 'TestPairing|TestAdversarial|TestLive' -count=1

# Nightly tier: every live suite, including the slow ones.
harness-nightly: harness harness-image harness-image-caldav harness-shaper
	cd harness && PACT_HARNESS_LIVE=1 go test ./... -count=1 -timeout 40m

# Live fabric tests: these create real Docker networks and containers. Opt-in,
# because they need a daemon and take minutes rather than seconds.
harness-live:
	cd harness && PACT_HARNESS_LIVE=1 go test ./... -run TestLive -count=1 -v

# Report whether this host can run each fabric (container, vm).
harness-preflight:
	cd harness && go run ./cmd/harness preflight

# The README's screenshots are REAL: captured from a running node by the portal
# scenario, not drawn. Regenerate them when the portal changes, so the pictures
# cannot quietly stop matching the product.
screenshots: harness-image
	@tmp=$$(mktemp -d) && cd harness && \
	  PACT_HARNESS_LIVE=1 PACT_HARNESS_ARTIFACTS=$$tmp go test ./scenario/ \
	    -run TestEveryPortalPageRenders -count=1 >/dev/null && \
	  for n in dashboard card audit; do cp $$tmp/$$n-light.png ../docs/images/$$n.png; done && \
	  echo "docs/images updated from a live node"

# clean removes what a build PRODUCES. `dist/` was the omission that mattered:
# `make dist` writes four platform binaries plus an SBOM there and nothing ever
# took them away, so a repository that had cut a few releases carried ~200 MB of
# stale artifacts that no target would remove.
clean:
	rm -f $(BINARY)
	rm -rf dist

# distclean also drops what a build DOWNLOADS or extracts: the SPA's node
# modules and the harness's guest kernel. Both are regenerable — `make web` and
# `make harness-kernel` — and both are large enough to be worth reclaiming when
# you are done with a machine.
distclean: clean
	rm -rf web/node_modules .harness-kernel
	@echo "removed dist/, the binary, web/node_modules and .harness-kernel"
	@echo "regenerate with: make web · make harness-kernel · make build"
