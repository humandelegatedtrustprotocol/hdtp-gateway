package conformance

import _ "embed"

// keptWasContactCases is the one list both hosts run by name (testdata/kept_was_contact.json).
//
//go:embed testdata/kept_was_contact.json
var keptWasContactCases []byte
