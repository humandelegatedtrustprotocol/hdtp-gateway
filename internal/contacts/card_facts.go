package contacts

// CardFacts is a served card and what an owner reads it by: the address and the root its certificate
// names, read through the intake a peer's card passes (ValidateInbound), so they cannot say what the
// card does not, and the host key it is served under. Both doors to the owner's own card answer it,
// under these names (the cloud's, /v1/identities/{slug}/card): the portal's GET /api/card and the
// owner MCP's export_card.
type CardFacts struct {
	Card     string `json:"card"`
	Endpoint string `json:"endpoint"`
	Root     string `json:"root_fingerprint"`
	Kid      string `json:"kid"`
}

// FactsOf reads a card this node serves, with the key it serves it under.
func FactsOf(card, kid string) (CardFacts, error) {
	c, err := ValidateInbound(card)
	if err != nil {
		return CardFacts{}, err
	}
	return CardFacts{Card: card, Endpoint: c.Endpoint, Root: c.Key, Kid: kid}, nil
}
