package scenario

// The images every scenario runs. Off-the-shelf and pinned where the upstream
// offers a tag worth pinning; nothing here is a stand-in written by us.
const (
	// nodeImage is the product, built by `make harness-image`.
	nodeImage = "pact-gateway:harness"
	// caldavImage is the -full image plus a pinned caldav-mcp, built by
	// `make harness-image-caldav`.
	caldavImage = "pact-gateway:harness-caldav"

	pebbleImage   = "ghcr.io/letsencrypt/pebble:latest"
	corednsImage  = "coredns/coredns:latest"
	radicaleImage = "tomsquest/docker-radicale:latest"
	alpineImage   = "alpine:3.20"
	curlImage     = "curlimages/curl:latest"
	socatImage    = "alpine/socat"
)
