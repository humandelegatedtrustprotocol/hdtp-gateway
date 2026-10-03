BINARY := hdtp-gateway
VERSION ?= 0.1.0-dev

.PHONY: limitd limitd-check limitd-vendor harness-hdtp-cli scale identity-proxy identity-bump sqlc sqlc-check distclean hooks all analyze vulncheck staticcheck gosec deadcode fuzz web dist sbom build check fmt vet dependents test test-js clean harness harness-preflight harness-live harness-image harness-image-caldav harness-shaper screenshots harness-pr harness-nightly harness-kernel

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

# analyze is what the pre-push hook runs (githooks/pre-push). The versions are
# pinned HERE and the hook calls these targets — one list, not two to drift apart.
analyze: vulncheck staticcheck gosec deadcode

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

# Whole-program reachability from the shipped binary (review N-15). The report goes to a file, not
# a pipe: make runs /bin/sh, where a pipeline's status is its last command's, so a deadcode that
# failed to build would hand the checker nothing and pass. The checker holds the report to the
# Reachability table in docs/conformance.md.
deadcode:
	@report=$$(mktemp) && \
	go run golang.org/x/tools/cmd/deadcode@v0.49.0 \
		-f '{{range .Funcs}}{{$$.Path}} {{.Name}}{{"\n"}}{{end}}' \
		-filter '^github.com/humandelegatedtrustprotocol/hdtp-gateway/(cmd|internal)/' ./... > "$$report" && \
	HDTP_DEADCODE_REPORT="$$report" go test ./internal/integrationtest \
		-run '^TestDeadcodeFindsOnlyWhatTheTableExcuses$$' -count=1 -v; \
	status=$$?; rm -f "$$report"; exit $$status

# The node at the size it grows to, run by the pre-push hook. Two measurements, each of which is
# skipped in an ordinary `go test` because it takes a minute or needs a big file:
#   - the store's scale benchmarks (internal/core/store/scale_test.go), over a seeded database of
#     a million messages and a million audit rows in a scratch file. Before this target nothing
#     ran them: they were a comment with a command in it;
#   - an import of 40,000 threads against one of 10,000 (internal/portable/scale_test.go), which
#     fails when reading, or writing, four times the threads costs more than six times as long.
#     hdtp-identity v0.3.0's quadratic threads.csv reader measured 10.8x and 17.7x here.
# The status is carried by hand: make 3.81 ignores .SHELLFLAGS, so a pipeline or a later command
# would otherwise decide whether this failed.
scale:
	@dir=$$(mktemp -d); \
	HDTP_SCALE_DB="$$dir/scale.db" go test ./internal/core/store/ -run '^$$' -bench '^BenchmarkScale' -benchtime 3x -count=1; \
	status=$$?; rm -rf "$$dir"; test $$status -eq 0 || exit $$status; \
	HDTP_EXPORT_SCALE=40000 go test ./internal/portable/ -run '^TestAnImportGrowsLinearlyWithItsThreads$$' -count=1 -v -timeout 20m

# Every parser that meets untrusted input, 30s each. Deliberately not part of
# `all`: two minutes of wall clock that finds nothing on most runs. The pre-push
# hook runs it on every push, and TestEveryFuzzTargetRunsUnderMakeFuzz fails the
# build if a target is added and this list is not.
fuzz:
	go test ./internal/contacts/ -run '^FuzzVCardParse$$'    -fuzz '^FuzzVCardParse$$'    -fuzztime 30s
	go test ./internal/public/   -run '^FuzzSealedEnvelope$$' -fuzz '^FuzzSealedEnvelope$$' -fuzztime 30s
	go test ./internal/cli/      -run '^FuzzInviteOffer$$'   -fuzz '^FuzzInviteOffer$$'   -fuzztime 30s
	go test ./internal/core/     -run '^FuzzRedact$$'        -fuzz '^FuzzRedact$$'      -fuzztime 30s

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BINARY) ./cmd/hdtp-gateway

# PLATFORMS is what a release ships. CGO is off and -trimpath is set for every
# one, so the binary depends on no host libc and embeds no build paths — which is
# what lets a third party rebuild a tag and compare checksums.
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

# dist builds every platform and writes SHA256SUMS. A release is cut locally from
# this exact target (RELEASING.md), so what ships is what anyone with read access to
# this repository and the identity module can rebuild. It fetches nothing private
# itself: set GOPRIVATE and the SSH insteadOf first (CONTRIBUTING.md).
dist:
	@rm -rf dist && mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; out=dist/$(BINARY)_$(VERSION)_$${os}_$${arch}; \
		echo "building $$out"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath \
			-ldflags "-s -w -X main.version=$(VERSION)" -o $$out ./cmd/hdtp-gateway || exit 1; \
	done
	@cd dist && shasum -a 256 * > SHA256SUMS && cat SHA256SUMS

# hooks points git at the versioned hooks in githooks/. The path is relative, so
# it resolves against each worktree's top level and every worktree runs its own
# copy. One setting, and the hooks travel with the repository instead of living in
# an untracked .git/hooks that every clone starts without.
hooks:
	git config core.hooksPath githooks
	@echo "hooks installed: $$(git config core.hooksPath)"
	@echo "pre-commit styles staged Go; pre-push runs the whole gate (this repository has no CI)."

# web rebuilds the embedded portal SPA. Its OUTPUT (web/dist) is committed, so
# plain `go build` and `make dist` need no Node toolchain; run this
# after changing anything under web/src and commit what it writes.
web:
	cd web && npm ci && npm run build

# sbom emits CycloneDX for the shipped binary's dependency graph. Pinned, not
# @latest: a supply-chain document produced by an unpinned tool is worth less.
sbom:
	@mkdir -p dist
	go run github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.9.0 \
		app -json -licenses=false -main cmd/hdtp-gateway -output dist/sbom.cdx.json .
	@echo "wrote dist/sbom.cdx.json"

# check covers the PRODUCT only. The harness is a separate module (harness/go.mod),
# so `go vet ./...` and `go test ./...` here do not see it — which is the point:
# its CDP and orchestration dependencies stay out of the shipped artifact's
# dependency and vulnerability surface. Run `make harness` for that module.
check: fmt vet dependents limitd-check test test-js

# The limits sidecar (cmd/hdtp-limitd, SPEC §5.7): HDTP §12's budgets, decided by hdtp-identity's
# pact-limits crate, required by version (its Cargo.toml). Rust, so cargo. The crate is private and
# fetched over SSH with this machine's agent (cmd/hdtp-limitd/.cargo/config.toml), locally only;
# the image builds read it from `limitd-vendor` instead, with no credential inside Docker.
LIMITD := cmd/hdtp-limitd
LIMITD_VENDOR := .build/limitd-vendor
limitd:
	cargo build --release --locked --manifest-path $(LIMITD)/Cargo.toml

# The sidecar's gate: its style, its lints as errors, its tests. The style is also applied to
# staged Rust at commit (githooks/pre-commit), so this step has nothing to find.
limitd-check:
	cargo fmt --manifest-path $(LIMITD)/Cargo.toml -- --check
	cargo clippy --release --locked --all-targets --manifest-path $(LIMITD)/Cargo.toml -- -D warnings
	cargo test --release --locked --manifest-path $(LIMITD)/Cargo.toml

# The sidecar's crates laid out for an offline build ($(LIMITD_VENDOR), gitignored and dockerignored
# like the identity proxy), which the image builds read as the named context `limitdvendor`.
limitd-vendor:
	rm -rf $(LIMITD_VENDOR) && mkdir -p $(LIMITD_VENDOR)
	cargo vendor --locked --manifest-path $(LIMITD)/Cargo.toml $(LIMITD_VENDOR)/crates > $(LIMITD_VENDOR)/config.toml
	@echo "limitd-vendor: $(LIMITD_VENDOR)"

# SQLC pins the generator. It is pinned HERE and nowhere else: `sqlc` is not
# installed on any machine that builds this, and the version matters more than
# usual because v1.30.0 slices statements out of the query files by a RUNE offset
# while reading BYTES — one em dash in a comment silently corrupts every statement
# after it (see TestQuerySourcesAreASCII, and F8 in
# batondeck/docs/release/findings-2026-09-18-rig.md). v1.27.0 and below do not
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
# is minutes. The pre-push hook runs it, and it is a target of its own rather than
# left implicit because the drift it catches is exactly what went unnoticed for weeks.
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
# disk. A clone without the sibling says it skipped rather than passing quietly.
#
# The battery requires this module by a pinned version, so vetting it as it stands would judge the
# pin, not the tree being gated. So it is built through a go.work made for the one run, in a
# temporary directory OUTSIDE the repository: it uses the battery's checkout and REPLACES this
# module with this tree. A replace, not a `use`: with `use` the go command still fetches the go.mod
# of the version the battery pins, which for an unpushed commit does not exist. It is the only
# workspace any gate builds (the pre-push hook runs everything else with GOWORK=off, so it proves
# the committed go.mod and go.sum).
#
# The scenario harness (./harness) is the same shape and closer to home: a separate module in THIS
# repository that imports `internal/`, built by the pre-push hook and by nothing else. The same two
# removals broke it the same day, and the fix above — made for the cloud's battery — walked past it.
# It is always on disk, so it is always vetted.
CLOUD_BATTERY := ../batondeck/gateway/conformance
dependents:
	@echo "go vet ./harness/..."
	@(cd harness && go vet ./...) || { \
		echo "the scenario harness no longer compiles against this module:"; \
		echo "  it is a separate Go module that imports internal/, and until 2026-09-19 only the"; \
		echo "  pre-push hook built it — so it broke in B3c and was found at the first push."; exit 1; }
	@if [ -d "$(CLOUD_BATTERY)" ]; then \
		battery="$$(cd "$(CLOUD_BATTERY)" && pwd)"; ws="$$(mktemp -d)"; \
		trap 'rm -rf "$$ws"' EXIT; \
		(cd "$$ws" && GOWORK= go work init "$$battery" && \
			GOWORK= go work edit -replace="$$(GOWORK=off go -C "$(CURDIR)" list -m)=$(CURDIR)") || exit 1; \
		echo "go vet $(CLOUD_BATTERY) (go.work: this tree + the battery)"; \
		(cd "$$battery" && GOWORK="$$ws/go.work" go vet ./...) || { \
			echo "the cloud's conformance battery no longer compiles against this tree:"; \
			echo "  fix it in $(CLOUD_BATTERY) in the same change that moved the API"; exit 1; }; \
		echo "go test -run TestTheBatteryCanSealEveryShapeItSends $(CLOUD_BATTERY)"; \
		(cd "$$battery" && GOWORK="$$ws/go.work" go test -count=1 -run 'TestTheBatteryCanSealEveryShapeItSends' ./...) || { \
			echo "the cloud's conformance battery cannot seal a call it sends: compiling was never the"; \
			echo "  same as working, and the rest of that package only runs against a deployment"; exit 1; }; \
	else \
		echo "!! dependents: $(CLOUD_BATTERY) is not on disk, so the cloud's conformance battery"; \
		echo "   was NOT compiled against this change. It imports internal/ packages of this module."; \
	fi

# ./... reaches into web/node_modules, which vendors a Go package of its own
# (flatted). Naming the module's real trees keeps the run to this repository's
# code and stops a dependency's test failures from reading as ours.
# The node's tests run the real limits sidecar (internal/limits/limitstest), so it is built first.
test: limitd
	go test -race ./cmd/... ./internal/...

# The portal's page scripts that no Go test can execute: wallet_return.js reads the web wallet's
# answer out of the fragment and POSTs it (internalui/wallet_pages.go). `node --test` runs them
# against a stubbed browser, with no package installed; the Node it needs is the one `make web`
# already requires, and a machine without it fails here rather than skipping. The same run takes the
# SPA's pure modules as they ship (web/test: the audit page's names, the overview's numbers), their
# types stripped by Node itself. Then the brand, which is
# JavaScript for the same reason: web/tools/kit.mjs check holds the vendored hdtp-web-kit (web/kit/,
# web/public/{brand,fonts}) to its release manifest and the portal's palette to the kit, contrast included.
test-js:
	@command -v node >/dev/null || { echo "test-js: node is not installed; it is what make web needs too"; exit 1; }
	node --test internal/internalui/*_test.mjs web/test/*_test.mjs
	node web/tools/kit.mjs check

# The scenario harness (docs/harness-design.md). Separate module, separate command,
# deliberately not part of `check`.
# The multi-process scenario (harness/multiprocess) runs the limits sidecar, so the hermetic tier builds it
# first: a fresh checkout has no target/ and the test refuses to run without the binary.
harness: limitd
	cd harness && go vet ./... && go test -race ./...

# ---- the identity module ---------------------------------------------------
# The node requires github.com/pact-cloud/pact-identity/go BY VERSION (go.mod, no replace). The
# repository is private and fetched over SSH, locally only: GOPRIVATE keeps it off the public
# proxy and checksum database, and the insteadOf, set for the one process through GIT_CONFIG_*
# (never in anybody's git config), makes the go command's git use SSH instead of HTTPS.
# GOWORK=off: these targets are about the version go.mod names, not a workspace's checkout.
IDENTITY_MODULE := github.com/pact-cloud/pact-identity/go
PRIVATE_FETCH := GOWORK=off GOPRIVATE='github.com/humandelegatedtrustprotocol/*' GIT_CONFIG_COUNT=1 \
	GIT_CONFIG_KEY_0=url.git@github.com:.insteadOf GIT_CONFIG_VALUE_0=https://github.com/
IDENTITY_PROXY := .build/identity-proxy

# identity-proxy fetches the version go.mod requires on the host and lays it out as a Go module
# proxy in $(IDENTITY_PROXY) (gitignored and dockerignored), which the image builds read as the
# named context `identityproxy`: the image builds with no credential inside Docker.
identity-proxy:
	@set -e; \
	v=$$($(PRIVATE_FETCH) go list -m -f '{{.Version}}' $(IDENTITY_MODULE)); \
	test -n "$$v" || { echo "identity-proxy: go.mod requires no version of $(IDENTITY_MODULE)"; exit 1; }; \
	$(PRIVATE_FETCH) go mod download $(IDENTITY_MODULE)@$$v; \
	src="$$(go env GOMODCACHE)/cache/download/$(IDENTITY_MODULE)/@v"; \
	dst="$(IDENTITY_PROXY)/$(IDENTITY_MODULE)/@v"; \
	rm -rf "$(IDENTITY_PROXY)"; mkdir -p "$$dst"; \
	cp "$$src/$$v.info" "$$src/$$v.mod" "$$src/$$v.zip" "$$dst/"; \
	echo "$$v" > "$$dst/list"; \
	echo "identity-proxy: $(IDENTITY_MODULE)@$$v in $(IDENTITY_PROXY)"

# identity-bump moves the node and the harness to another release of the identity module and
# runs the gate on the result: `make identity-bump VERSION=0.3.0` (or v0.3.0). The Go tag is
# go/vX.Y.Z because the module lives in go/; `go get` takes the module's own version, vX.Y.Z.
identity-bump:
	@test "$(origin VERSION)" = "command line" || { echo "usage: make identity-bump VERSION=x.y.z"; exit 1; }
	@set -e; v=v$(patsubst v%,%,$(VERSION)); \
	$(PRIVATE_FETCH) go get $(IDENTITY_MODULE)@$$v; \
	$(PRIVATE_FETCH) go mod tidy; \
	cd harness; \
	$(PRIVATE_FETCH) go get $(IDENTITY_MODULE)@$$v; \
	$(PRIVATE_FETCH) go mod tidy; \
	echo "identity-bump: node and harness require $(IDENTITY_MODULE) $$v"
	$(PRIVATE_FETCH) $(MAKE) check

# The node image the harness stands topologies up from: the shipped artifact,
# built from the repo's own Dockerfile. HARNESS_IMAGE is its tag, exported to the harness as
# HDTP_HARNESS_IMAGE (harness/images): two worktrees on one machine each take a tag of their own
# (`make harness-nightly HARNESS_IMAGE=hdtp-gateway:harness-mine`), or each tests whichever binary
# the other built last.
HARNESS_IMAGE ?= hdtp-gateway:harness
export HDTP_HARNESS_IMAGE := $(HARNESS_IMAGE)
harness-image: identity-proxy limitd-vendor
	docker build --build-context identityproxy=$(IDENTITY_PROXY) --build-context limitdvendor=$(LIMITD_VENDOR) -t $(HARNESS_IMAGE) .

# The live batteries that are DATA in the sibling repositories, run against a node by the nightly
# tier: hdtp-identity's intrusion battery through its `hdtp` CLI (S18), the cloud's Go conformance
# battery (S19), and the cloud's local cloud with the real wallet page (S20; it also needs the WorkOS
# test pair in the environment, which this Makefile does not read from any file). Each is a Need (harness/registry); the tier promises it when the
# sibling is checked out beside this repository, and says NOT PROMISED, with how to provide it,
# when it is not. Override either with HDTP_CLI or HDTP_CLOUD_BATTERY in the environment.
HDTP_IDENTITY ?= $(CURDIR)/../hdtp-identity
HDTP_CLI_BIN := $(HDTP_IDENTITY)/target/release/pact
harness-hdtp-cli:
	@if [ -n "$$HDTP_CLI" ]; then echo "harness-hdtp-cli: HDTP_CLI=$$HDTP_CLI"; \
	elif [ -f "$(HDTP_IDENTITY)/Cargo.toml" ]; then \
		cargo build --release -q -p pact --manifest-path "$(HDTP_IDENTITY)/Cargo.toml" || exit 1; \
		echo "harness-hdtp-cli: $(HDTP_CLI_BIN)"; \
	else echo "!! harness-hdtp-cli: no hdtp-identity checkout at $(HDTP_IDENTITY): S18 will be NOT PROMISED"; fi
# The environment a live tier runs under: the two siblings' paths when they are on disk.
LIVE_ENV = HDTP_CLI="$${HDTP_CLI:-$$(test -x '$(HDTP_CLI_BIN)' && echo '$(HDTP_CLI_BIN)')}" \
	HDTP_CLOUD_BATTERY="$${HDTP_CLOUD_BATTERY:-$$(test -f '$(abspath $(CLOUD_BATTERY))/go.mod' && echo '$(abspath $(CLOUD_BATTERY))')}" \
	HDTP_LOCAL_CLOUD="$${HDTP_LOCAL_CLOUD:-$$(test -f '$(abspath $(CLOUD_BATTERY))/../e2e/local-run.mjs' && echo '$(abspath $(CLOUD_BATTERY)/..)')}"

# The calendar scenario (S4) needs the -FULL image — node and uv, so a supervised
# stdio child can run in-container (SPEC §12.3) — with the upstream MCP server
# already installed. Installed at build time rather than fetched by `npx` at run
# time so the scenario does not depend on reaching a package registry mid-test,
# and so what it exercises is a pinned version.
# Its tags follow HARNESS_IMAGE's reason: HARNESS_FULL_IMAGE and HARNESS_CALDAV_IMAGE (exported to
# the harness as HDTP_HARNESS_CALDAV_IMAGE), so S4 runs the binary of the tree under test.
HARNESS_FULL_IMAGE ?= hdtp-gateway:harness-full
HARNESS_CALDAV_IMAGE ?= hdtp-gateway:harness-caldav
export HDTP_HARNESS_CALDAV_IMAGE := $(HARNESS_CALDAV_IMAGE)
harness-image-caldav: identity-proxy limitd-vendor
	docker build --build-context identityproxy=$(IDENTITY_PROXY) --build-context limitdvendor=$(LIMITD_VENDOR) -f Dockerfile.full -t $(HARNESS_FULL_IMAGE) .
	printf 'FROM $(HARNESS_FULL_IMAGE)\nUSER root\nRUN npm install -g caldav-mcp@0.10.0 && chown -R 65532:65532 /usr/local/lib/node_modules\nUSER 65532:65532\n' \
	  | docker build -t $(HARNESS_CALDAV_IMAGE) -

# The shaper image: iproute2 preinstalled. It must ship tc rather than install it,
# because the shaper runs inside the target's network namespace and cannot reach a
# package repo through a partition it just created. The recipe is
# harness/images.ShaperDockerfile, the one the fabric also builds on demand.
harness-shaper:
	cd harness && go run ./cmd/harness shaper

# An aarch64 Linux kernel for the VM topology (S8): Alpine's linux-virt package,
# installed into the pinned arm64 Alpine image (so it needs the package mirror once)
# and copied out; no host toolchain. Export HDTP_HARNESS_KERNEL to the printed path
# to enable the VM scenario. $(CURDIR), not $(PWD): `make -C hdtp-gateway` leaves
# PWD at the caller's directory, and the kernel landed outside the repository.
KERNEL_DIR ?= .harness-kernel
harness-kernel:
	@mkdir -p $(KERNEL_DIR)
	@docker run --rm --platform linux/arm64 -v "$(CURDIR)/$(KERNEL_DIR):/out" alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc \
	  sh -c 'apk add --no-cache linux-virt >/dev/null 2>&1 && cp /boot/vmlinuz-virt /out/'
	@echo "export HDTP_HARNESS_KERNEL=$(CURDIR)/$(KERNEL_DIR)/vmlinuz-virt"

# ---- run tiers (docs/harness-design.md §6) --------------------------------
# A tier is a set of scenarios read from the registry (harness/registry: each
# scenario's Spec, in its own test), never a regular expression over test names.
# `harness run` prints what the tier PROMISES before it starts, runs `go test -v`
# on exactly those tests, and fails the tier if a promised scenario did not PASS
# — a skip included. What a tier does not promise is printed with what it needs.
# Each tier builds what it promises, so its promise is one it can keep.

# Fabric tier: the fabric proving itself against real containers (F1-F5).
harness-live: harness-image
	cd harness && go run ./cmd/harness run -tier fabric

# PR tier: the fabric tier plus pairing (S2) and the adversarial probes (S9).
harness-pr: harness harness-image
	cd harness && go run ./cmd/harness run -tier pr

# Nightly tier: every scenario. It promises S8 only when HDTP_HARNESS_KERNEL is
# set and T7 only when HDTP_CF_DOMAIN is set, and says so when they are not.
harness-nightly: harness harness-image harness-image-caldav harness-shaper harness-hdtp-cli
	cd harness && $(LIVE_ENV) go run ./cmd/harness run -tier nightly

# Report whether this host can run each fabric (container, vm).
harness-preflight:
	cd harness && go run ./cmd/harness preflight

# The README's screenshots are REAL: captured from a running node by the portal
# scenario, not drawn. Regenerate them when the portal changes, so the pictures
# cannot quietly stop matching the product.
screenshots: harness-image
	@tmp=$$(mktemp -d) && cd harness && \
	  { HDTP_HARNESS_ARTIFACTS=$$tmp go run ./cmd/harness run -id S11 >$$tmp/run.log || \
	    { tail -40 $$tmp/run.log; exit 1; }; } && \
	  for n in dashboard card audit; do cp $$tmp/$$n-light.png ../docs/images/$$n.png; done && \
	  echo "docs/images updated from a live node"

# clean removes what a build PRODUCES. `dist/` was the omission that mattered:
# `make dist` writes four platform binaries plus an SBOM there and nothing ever
# took them away, so a repository that had cut a few releases carried ~200 MB of
# stale artifacts that no target would remove.
clean:
	rm -f $(BINARY)
	rm -rf dist .build

# distclean also drops what a build DOWNLOADS or extracts: the SPA's node
# modules and the harness's guest kernel. Both are regenerable — `make web` and
# `make harness-kernel` — and both are large enough to be worth reclaiming when
# you are done with a machine.
distclean: clean
	rm -rf web/node_modules .harness-kernel
	@echo "removed dist/, the binary, web/node_modules and .harness-kernel"
	@echo "regenerate with: make web · make harness-kernel · make build"
