package core

// errorCodes are HDTP §12's refusal codes, the table at the head of the specification's "Errors,
// limits, conformance" section. TestErrorCodesAreTheSpecsTable holds this list to that table.
var errorCodes = map[string]bool{
	"unknown_contact":     true,
	"pending_approval":    true,
	"permission_denied":   true,
	"invite_invalid":      true,
	"blocked_or_unknown":  true,
	"too_large":           true,
	"rate_limited":        true,
	"unavailable":         true,
	"bad_request":         true,
	"seal_required":       true,
	"identity_required":   true,
	"envelope_invalid":    true,
	"seal_not_accepted":   true,
	"certificate_renewed": true,
	"chain_required":      true,
}

// PeerRefused is what this node says of a peer's refusal that carries no §12 code.
const PeerRefused = "refused"

// PeerCode is the code of a peer's refusal as this node repeats it: the code itself when it is
// one of §12's, PeerRefused for any other non-empty string, and "" for none. A peer chooses the
// string; anything that is not a protocol code would be its words put in front of the owner.
func PeerCode(code string) string {
	switch {
	case code == "":
		return ""
	case errorCodes[code]:
		return code
	}
	return PeerRefused
}
