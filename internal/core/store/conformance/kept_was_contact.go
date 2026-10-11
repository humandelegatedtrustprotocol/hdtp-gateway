package conformance

import _ "embed"

// keptWasContactCases is the one list of these cases (testdata/kept_was_contact.json), run here by
// name. BatonDeck runs the same list by the same names against its cloud/1004 trigger, from a byte
// copy its check-harvested.mjs holds to this file at the node commit it last harvested.
//
//go:embed testdata/kept_was_contact.json
var keptWasContactCases []byte
