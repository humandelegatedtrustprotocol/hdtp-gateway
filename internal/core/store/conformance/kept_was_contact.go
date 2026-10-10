package conformance

import _ "embed"

// keptWasContactCases is the one list of these cases (testdata/kept_was_contact.json), run here by
// name; BatonDeck's cloud/1004 is to run the same list once it lands.
//
//go:embed testdata/kept_was_contact.json
var keptWasContactCases []byte
