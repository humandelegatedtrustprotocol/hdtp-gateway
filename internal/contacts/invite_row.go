package contacts

import "github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"

// InviteRow is one invite as every owner door answers it: the portal's `GET /api/invites` and the
// owner MCP's `list_invites` (Building rule 1; #225). It is the cloud's `/v1` Invite
// (`batondeck/gateway/src/api/v1/routes/shared.ts`) with two differences, held by a test
// (`TestTheInviteRowIsTheCloudsLessItsLinkAndWithItsGrant`): no `url`, because this node keeps only
// the token's hash (SPEC §11) and so has no link to answer after the mint; and `permissions`, the
// grant a redemption gives, because an invite here can carry a grant of its own where the cloud's
// carries a preset only. The token's hash and the account stay in the store.
type InviteRow struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	Preset      string   `json:"preset"`
	Uses        int64    `json:"uses"`
	MaxUses     int64    `json:"max_uses"`
	AutoAccept  bool     `json:"auto_accept"`
	Permissions []string `json:"permissions"`
	ExpiresAt   int64    `json:"expires_at"`
	// RevokedAt is when the invite was revoked, null while it is not: the cloud's column.
	RevokedAt *int64 `json:"revoked_at"`
}

// InviteRows projects stored invites to the rows the doors answer, in the store's order. A list
// with none is empty, never null, and so is an invite's grant.
func InviteRows(list []store.Invite) []InviteRow {
	out := make([]InviteRow, 0, len(list))
	for _, inv := range list {
		row := InviteRow{ID: inv.ID, Label: inv.Label, Preset: inv.Preset, Uses: inv.Uses, MaxUses: inv.MaxUses,
			AutoAccept: inv.AutoAccept, Permissions: inv.Permissions, ExpiresAt: inv.ExpiresAt}
		if row.Permissions == nil {
			row.Permissions = []string{}
		}
		if inv.RevokedAt != 0 {
			at := inv.RevokedAt
			row.RevokedAt = &at
		}
		out = append(out, row)
	}
	return out
}
