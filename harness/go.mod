// The scenario harness is a SEPARATE module on purpose (docs/harness-design.md §2).
//
// It drives a real browser over CDP and orchestrates containers and VMs, which means
// dependencies that must never reach the shipped artifact. A build tag would keep them
// out of the binary but not out of the root go.mod, go.sum, or govulncheck's surface.
// A separate module keeps them out of all four, and Go excludes nested modules from the
// parent's ./... automatically — so `make check` never compiles this.
module github.com/pact-cloud/pact-gateway/harness

go 1.26.6

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/chromedp/sysutil v1.1.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/emersion/go-vcard v0.1.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.3 // indirect
	github.com/go-json-experiment/json v0.0.0-20260623181947-01eb4420fa68 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/webauthn v0.18.1 // indirect
	github.com/go-webauthn/x v0.3.1 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/gobwas/ws v1.4.0 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/jsonschema-go v0.4.3 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/mfridman/interpolate v0.0.2 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/pressly/goose/v3 v3.28.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/sethvargo/go-retry v0.4.0 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/oauth2 v0.37.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	modernc.org/libc v1.75.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)

require (
	github.com/chromedp/cdproto v0.0.0-20260804232424-e85f50dbfd32
	github.com/chromedp/chromedp v0.16.0
	github.com/jackc/pgx/v5 v5.11.0
	github.com/modelcontextprotocol/go-sdk v1.8.0
	github.com/pact-cloud/pact-gateway v0.0.0
	github.com/pact-cloud/pact-identity/go v0.3.6
	modernc.org/sqlite v1.57.0
)

replace github.com/pact-cloud/pact-gateway => ..
