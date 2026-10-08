# internal/internalui/auth

Owner authentication for the node: WebAuthn passkeys with cookie sessions for the portal
(`Service`), and named bearer tokens for the owner MCP (`TokenService`). The package decides who
the owner is; it does not decide what the owner may touch (that is the memberships check in
`internal/internalui` and the Cedar policy in `internal/core/policy`).

Callers, found by grep across the repository:

- `internal/internalui` (`auth_pages.go`, `origin.go`, `owners_pages.go`, `audit_pages.go`) drives
  the ceremonies and the session gate with `Service`, and lists, mints and revokes tokens with
  `TokenService`.
- `internal/internalui/ownermcp` takes `Identity` and `PasskeyInfo`, and `ErrLastPasskey`.
- `internal/cli` builds both services (`serve_admin.go`), validates the bearer on every owner-MCP
  request (`compose.go`, `ownerIdentity`, `requireOwnerToken`), checks the configured host with
  `ValidRelyingPartyID` (`cli.go`), and exposes passkey and token operations on the admin socket.

It calls the store (`internal/core/store`: credentials, owners, sessions, tokens) and
`internal/identity` (`AdoptOrphanAccounts`, on the first owner's creation), and uses
`go-webauthn` for the ceremonies.

## What it holds

Passkeys and sessions (`passkeys.go`):

- `Service`, `New(store)`: the ceremony table and the session operations.
- `RelyingParty{ID, Origin}`: the pair a ceremony runs under, supplied per ceremony by the caller
  (the portal resolves it from the request with `internalui.OriginPolicy`). It is stashed with
  the challenge so both halves of a ceremony use the same pair.
- `ValidRelyingPartyID(host)`: the library's own verdict on a hostname, so a configuration refused
  here is one whose ceremonies would be refused.
- `BeginRegistration` / `FinishRegistration`: register a tagged passkey; the first one creates the
  owner.
- `BeginLogin` / `FinishLogin`: a discoverable-credential login over every registered passkey;
  `FinishLogin` returns a session token.
- `MintSession`: issue a session for an owner who has just proven a credential (the portal calls
  it at the end of setup).
- `SessionOwner`, `Logout`: resolve and end a session.
- `ListPasskeys` and `PasskeyInfo`: passkey metadata across owners.
- `RemovePasskey`, `ErrLastPasskey`, `ErrNoSuchPasskey`: removal that cannot leave zero.

Bearer tokens (`tokens.go`):

- `TokenService{Store, Now}`: `Create`, `Validate`, `Revoke`, `List`.
- `Identity{OwnerID, AccountID}`: what a validated token acts as; `AccountID == ""` means every
  account the owner administers.
- `TokenInfo`: a token's metadata as `List` returns it.

## Flows, as the code has them

Constants: a session lives 12 hours (`sessionTTL`, `passkeys.go`). The portal sets the session
cookie to expire after the same 12 hours with its own literal (`internalui/auth_pages.go`,
`setSession`); the two are separate numbers. A token (`TokenService`) has no expiry: only
revocation ends it. A ceremony has no expiry either (see below).

First passkey. `BeginRegistration(rp, ownerID "", name)` picks the WebAuthn user handle before the
authenticator records it: the first existing owner's id if one exists, else a fresh random id. It
stashes the challenge, the relying party and the handle under a random ceremony id and returns the
options and that id. `FinishRegistration` takes the ceremony out of the table (single use, whether
the call succeeds or not), and for `ownerID == ""` enters a mutex, re-reads the owner list, and
either joins the existing owner or creates the owner under the handle the authenticator already
holds. If an owner has appeared under a different id since `Begin`, it refuses with "another
registration completed first; start again". On creating the first owner it calls
`identity.AdoptOrphanAccounts` so accounts provisioned before the first passkey become
administered by that owner. It then verifies the attestation and stores the credential with the
given tag (`"passkey"` when the tag is empty), and returns the owner id.

Later passkeys. The portal's registration route always calls `Begin`/`Finish` with `ownerID == ""`,
so a second passkey joins the existing owner (the recovery wizard does this). Calling them with a
non-empty owner id is done only by this package's tests in this repository.

Login. `BeginLogin` refuses with "auth: no passkeys registered" when there are none, and returns
an error naming the credential when a stored row will not decode (it is never skipped).
`FinishLogin` takes the ceremony, lets the library find the owner by the user handle the
authenticator replays, and mints a session: 24 random bytes hex-encoded, stored with an issue and
an expiry time.

Sessions. `SessionOwner` answers the owner id, or `""` for an empty, unknown or expired token.
`Logout` removes the row and discards the store's error.

Removal. `RemovePasskey` asks the store to delete the credential only while another passkey
remains (`RemoveCredentialIfNotLast`, one statement). When nothing was removed it lists passkeys
to say why: `ErrLastPasskey` if the id exists, `ErrNoSuchPasskey` if it does not.

Tokens. `Create(ownerID, label, accountID)` refuses an empty label ("auth: token label
required"); it generates 24 random bytes, forms `hdtp_` plus 48 hex characters, stores only the
SHA-256, and returns the plaintext once with the token's id. `Validate` requires the `hdtp_`
prefix, looks the token up by the hash of what was presented, and refuses an unknown or revoked
one; it returns the owner and the account narrowing. `Revoke` stamps the row; the SQLite store
refuses a missing or already revoked id. `List` returns metadata only and includes revoked
tokens.

## What it refuses, and how

These are Go errors; the HTTP statuses are chosen by the callers (the portal answers 401 "not
accepted" for a failed login and 400 for a refused registration; the owner MCP answers 401 for any
bad token, without saying which way).

| Operation | Refusal |
|---|---|
| `BeginRegistration`, `BeginLogin` | the relying party is refused by the library (`auth: relying party <id>/<origin>: ...`) |
| `BeginLogin` | `auth: no passkeys registered`; `auth: stored passkey <id> will not decode: ...` |
| `FinishRegistration`, `FinishLogin` | `auth: unknown or reused ceremony`; the library's verification error, wrapped as `auth: ...` |
| `FinishRegistration` | `auth: another registration completed first; start again` |
| `RemovePasskey` | `ErrLastPasskey`, `ErrNoSuchPasskey` |
| `TokenService.Create` | `auth: token label required` |
| `TokenService.Validate` | `auth: not an hdtp token`, `auth: unknown token`, `auth: token revoked` |

## Invariants

- The first passkey decides who owns the node, and only one owner can win a race to be first:
  creation of the first owner is serialized by `firstMu` and re-checks the owner list inside the
  lock. Held by `TestConcurrentFirstRegistrationYieldsOneOwner`.
- The WebAuthn user handle is the owner id from `BeginRegistration` on, so the credential can log
  in later. Held by `TestRegisterLoginSessionLifecycle` (register, then log in).
- A ceremony id is single use. Held by `TestCeremonyIDsAreSingleUse`.
- Registration asks for a discoverable (resident) credential, because login is discoverable. Held
  by `TestRegistrationAsksForTheDiscoverableCredentialThatLoginNeeds`.
- A stored credential that will not decode is an error that names it, not an absence. Held by
  `TestAStoredCredentialThatWillNotDecodeIsAnErrorAndNotAnAbsence`.
- A passkey stored by the previous library version still signs its owner in. Held by
  `TestAPasskeyStoredByThePreviousLibraryStillSignsItsOwnerIn`.
- A configuration the config check accepts is exactly one whose ceremonies are accepted. Held by
  `TestTheConfigCheckAndTheCeremonyAgreeAboutARelyingParty`.
- Removing a passkey can never leave zero, and the check and the delete are one store statement,
  so two racing removals cannot both pass. The statement lives in the store
  (`RemoveCredentialIfNotLast`); this package maps its answer to `ErrLastPasskey` or
  `ErrNoSuchPasskey`.
- Only the SHA-256 of a token is stored; the plaintext exists only in `Create`'s return. Held by
  `TestTokenListNeverLeaksSecrets` (the listing carries neither the plaintext nor its hex part)
  and `TestTokenLifecycle`.
- Validation looks a token up by its hash, so there is no comparison of secrets to time.
- Revocation takes effect on the next `Validate`, and a second revocation is refused. Held by
  `TestTokenLifecycle`.
- A token narrowed to an account keeps its narrowing. Held by `TestTokenScopingAndUnknowns`.
- A session expires at its stored expiry and `Logout` ends it at once. Held by
  `TestRegisterLoginSessionLifecycle` (it moves the clock 13 hours past a 12-hour session).

## Held by

`passkeys_test.go`: `TestRegisterLoginSessionLifecycle`, `TestMultipleTaggedPasskeysAndRemoval`,
`TestCeremonyIDsAreSingleUse`, `TestConcurrentFirstRegistrationYieldsOneOwner`,
`TestTheConfigCheckAndTheCeremonyAgreeAboutARelyingParty`,
`TestAPasskeyStoredByThePreviousLibraryStillSignsItsOwnerIn` (reads
`testdata/passkey-webauthn-0.17.4.json`),
`TestAStoredCredentialThatWillNotDecodeIsAnErrorAndNotAnAbsence`,
`TestRegistrationAsksForTheDiscoverableCredentialThatLoginNeeds`.
`tokens_test.go`: `TestTokenLifecycle`, `TestTokenScopingAndUnknowns`,
`TestTokenListNeverLeaksSecrets`.

The portal-level flows built on this package (login, wizard gate, recovery token, spoofed Host) are
held in `internal/internalui` by `TestPortalRegistrationAndLoginCeremony`,
`TestLoopbackStillDemandsALoginAndHostIsNotTrusted`, `TestALockedOutOwnerCanRecoverWithAMintedToken`
and `TestAPasskeyCanLogInAgainAfterSigningOut`.

No test in this repository calls `RemovePasskey` with the last remaining passkey or with an unknown
id: `TestMultipleTaggedPasskeysAndRemoval` removes one of two. The last-passkey refusal rests on
the store statement and the mapping above, not on a test of `ErrLastPasskey`.

## What it does not do

- It does not hold the setup tokens that open the wizard, and does not decide whether the wizard
  is open: that is `internalui.SetupTokens` and the gate in `internalui/server.go`.
- It does not set cookies or write HTTP responses. It returns tokens and ownership; the portal sets
  and clears the session cookie.
- It does not resolve the relying party from a request. The caller passes it, and the Host
  allow-list is `internalui.OriginPolicy`.
- It does not expire ceremonies. They sit in memory until `Finish` takes them or the process ends.
- It does not expire bearer tokens, and has no scope finer than owner or owner plus one account;
  what a token may do is decided per tool in `ownermcp`.
- It does not authorize account access. `Identity.AccountID == ""` means "no narrowing", not "all
  accounts": the owner's admin memberships still apply.
- It does not register passkeys over the owner MCP; nothing in the owner MCP calls
  `BeginRegistration`.
