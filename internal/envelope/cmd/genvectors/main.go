// Command genvectors regenerates the committed sealed-envelope test vectors:
//
//	go run ./internal/envelope/cmd/genvectors > internal/envelope/testdata/vectors.json
//
// Deterministic by construction (see envelope.GenerateVectors); a diff in the
// output means the envelope implementation changed behavior.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/tech-sumit/pact-gateway/internal/envelope"
)

func main() {
	vs, err := envelope.GenerateVectors()
	if err != nil {
		fmt.Fprintln(os.Stderr, "genvectors:", err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(vs); err != nil {
		fmt.Fprintln(os.Stderr, "genvectors:", err)
		os.Exit(1)
	}
}
