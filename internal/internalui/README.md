# internal/internalui

The node's owner-facing HTTP surface (SPEC §8): the JSON API and POST endpoints behind the
embedded React portal (`web/`), the passkey ceremonies and the session gate in front of them, the
setup wizard's gate, and the few pages the node renders itself (the web-wallet pages, the OAuth
"authorization received" page, the public invite landing).

`internal/cli` builds it. `compose.go` (`internalHandler`) creates one `*ServeMux`, registers each
page group with its `Mount*` function, hands `HandlerWithAuth` that mux, and serves the result on
the internal listener with `Serve`; `serve.go` builds `AuthDeps` and `WalletDeps` and calls
`SetCookieTag`. `internal/cli` also mounts `/healthz` (`Health`) and the owner MCP (`/owner/mcp`)
on the same mux, outside `HandlerWithAuth`: neither goes through this package's session, CSRF or
account layers. The package calls the store, `internal/contacts`, `internal/messaging`,
`internal/integrations`, `internal/identity`, `internal/core` (settings), and its sub-packages
`internalui/auth` (passkeys, sessions, tokens) and `internalui/ownermcp` (the agent surface; this
package does not import it).

Sub-package READMEs: [auth](auth/README.md), [ownermcp](ownermcp/README.md).

## What it holds

Composition and the gate (`server.go`, `auth_pages.go`, `account_resolve.go`, `origin.go`,
`spa.go`):

- `HandlerWithAuth(store, setup, authDeps, mounts...)`: the handler. Outermost to innermost:
  security headers, session gate (when `authDeps` is non-nil), CSRF, account resolution, the mux.
- `SetupTokens`, `NewSetupTokens`, with `Mint`, `MintRecovery`, `Valid`, `ValidRecovery`,
  `Consume`: the tokens that open the first-run wizard.
- `AuthDeps`, `MountAuthPages`, `SessionMiddleware`, `OwnerFrom`, `SetCookieTag`: the ceremonies,
  the session gate, the signed-in owner from the request context, and the per-node cookie suffix.
- `OriginPolicy`: which relying party a ceremony runs under, from the request's Host.
- `LoadTLS`, `Serve`, `Health`: the listener plumbing.

Page groups, each a `*Deps` struct and a `Mount*` function:

| Group | Deps / Mount | Concern |
|---|---|---|
| session | `SessionAPIDeps` / `MountSessionAPI` | who is here, the node's setup state, the owner's identities |
| dashboard | `DashboardDeps` (`DashboardPosture`) / `MountDashboard` | posture and per-identity counts |
| contacts | `ContactsDeps` (`ContactTool`, `Invalidator`) / `MountContactPages` | list, switchboard, lifecycle, calls to a contact |
| requests, invites, card | `ManageDeps` / `MountManagePages` | approvals, address decisions, invites, card |
| inbox, events | `InboxDeps` / `MountInboxPages` | threads, the server-sent event stream |
| conversations | `MessagesDeps` (`ConversationsPage`, `UnreadCap`) / `MountMessagePages` | the conversation view, read markers, sending |
| media | `MediaDeps` / `MountMediaPages` | stored media, deliberate fetch of a contact-supplied URL |
| integrations | `IntegrationsDeps` / `MountIntegrationPages` | add, connect (OAuth), exposure, reconfirm |
| identity | `IdentityDeps` / `MountIdentityPages` | identities and certificate state, create |
| web wallet | `WalletDeps`, `WalletInstalled` / `MountWalletPages` | signing request to a web wallet and its answer |
| settings | `SettingsDeps` (`PairInput`, `PairResult`, `AccountChoice`, `StorageRow`, `AdapterSetting`, `MaxQuotaGiB`, `MaxRetentionDaysForm`, `MaxRequestExpiryDays`) / `MountSettingsPages` | reachability, security knobs, storage, presets, ingress pairing, probe |
| owners | `OwnersDeps` / `MountOwnerPages` | passkeys and bearer tokens |
| audit | `AuditDeps` / `MountAuditPages` | the owner-visible audit trail |
| invite landing | `LandingDeps` / `LandingHandler` | the public `/i/{token}` page (served on the public listener by the node, not this mux) |

## Route table

"Session" means a signed-in owner (the session cookie resolves to an owner) and, for every method
but GET, HEAD and OPTIONS, a CSRF token. A request that names an `account` (in the query, or in a
urlencoded form body) for an account the owner does not administer is answered 404 and audited, on
every session route below. A multipart body is not read by that check (see "What it does not do").
When the node has exactly one account and the owner administers it, a request that names none is
given it; with several accounts nothing is filled in. No route below takes a bearer token: the
token surface is the owner MCP.

Open (no session needed):

| Method, path | What it does |
|---|---|
| `GET /api/session` | `signed_in`, `needs_setup` (zero passkeys), `accounts` (the identities the owner administers; empty without a session), `cookie_tag`. 500 `{"error":"store"}`. |
| `GET /setup` | The SPA shell through the wizard gate (below). |
| `POST /setup/begin`, `POST /setup/finish?ceremony=&tag=` | Register a passkey. Gated by `AuthDeps.SetupAllowed` (404 "setup is closed"). `finish` also signs the new owner in and burns the setup token. |
| `POST /login/begin`, `POST /login/finish?ceremony=` | Passkey login. |
| `GET /wallet/return`, `GET /wallet/return.js` | Where a web wallet navigates back to; holds no data. |
| `GET /assets/*`, `/fonts/*`, `/brand/*` | The SPA's static shell; not audited when unauthenticated. |
| `GET /`, any other unmatched GET | The SPA shell (`no-store`), or a file at the root of the embedded build; an unmatched `/api/...` is 404 `{"error":"not_found"}`. |

Session (JSON reads, then mutations). Five GET routes in this table, `GET /media/{hash}`,
`GET /card.vcf`, `GET /events`, `GET /integrations/{id}/authorize` and `GET /oauth/callback`, are
also reachable with no session; see the last items of "What it does not do".

| Method, path | What it does |
|---|---|
| `POST /logout` | Ends the session, clears the cookie, 303 to `/login`. |
| `GET /api/dashboard` | Posture and, per administered identity, active contacts, pending (requests plus addresses) and certificate. 401 `identity_required` with no owner; 500 `store`. |
| `GET /api/contacts`, `GET /api/contacts/{fpr}` | List with labels (never raw peer names); one contact's switchboard. 404 for an unknown contact. |
| `GET /api/contacts/{fpr}/tools`, `POST /contacts/{fpr}/call` | List a contact's tools; call one (`tool`, `args` as a JSON object). 503 / 400 when `ListTools` / `Call` is nil; 413 over 64 KiB of args; 502 when the call fails. Calls are audited `call_contact`. |
| `POST /contacts/add` | Redeem an invite link or ask with a card. Registered only when `AddContact` is set. 303 to `/contacts` with `added` or `err`. |
| `POST /contacts/{fpr}/remove`, `/block`, `/unblock` | Lifecycle through `contacts.Owner`; 303 to `/contacts` with a notice or `err`. |
| `POST /contacts/{fpr}/permissions`, `/petname`, `/trust` | Save the switchboard (only permissions the account offers persist); set the local name (400 "name too long"); set `messages_only` or `may_instruct` (400 "bad trust flag"). A store failure on permissions, petname or trust is 404. |
| `POST /contacts/{fpr}/refresh` | Refresh that one contact's card; JSON `outcome` and `why`; 404 when `RefreshContact` is nil or fails. |
| `GET /api/requests` | Contacts in `pending_in` (with the invite that admitted them and any address claim) and contacts waiting at a new address. |
| `POST /requests/{fpr}/approve`, `/reject` | Decide a request; 303 to `/requests`. Refusals: 404 unknown contact, 409 wrong state, 400 bad request, 402 contact cap, 500. |
| `POST /requests/addresses/{root}/approve`, `/reject` | Decide a contact waiting at a new address; same refusals. |
| `GET /api/invites`, `POST /invites/create`, `POST /invites/{id}/revoke` | Invites (`max_uses` defaults to 1; the new token travels once, in the redirect to `/invites?new=`; 400 "create failed"); revoke is 404 only for a missing or spent invite, 500 otherwise. |
| `GET /api/card`, `GET /card.vcf` | The account's card with its signature, root and endpoint; the vCard as a download. 404 `no_card` when it has no leaf yet; 500 `card_unavailable`. |
| `GET /api/inbox`, `GET /api/threads/{id}`, `POST /threads/{id}/send` | Threads with unread counts; one thread (opening it marks it read through its newest message); send (origin fixed to the portal). 502 "recorded, but delivery failed". |
| `GET /events` | Server-sent events for the account, from the message bus; sends `: connected`, then `event: <kind>` frames. |
| `GET /api/conversations`, `POST /messages/read`, `POST /messages/send`, `POST /messages/send_media` | The conversation view; mark read through a message (400, 404, 500 as JSON); send text (errors come back in the redirect's `err`); send a file (multipart, 5 MiB; 413, 400, 503, 502). |
| `GET /media/{hash}`, `POST /media/fetch` | Serve stored bytes as an attachment; deliberately fetch a contact-supplied URL (503 when `Fetch` is nil; a refusal is 200 with `{"error":...}`). `/media/{hash}`: 400 without `account` or hash, 404 without a blob row for the account, 410 when the bytes are gone. |
| `GET /api/integrations`, `POST /integrations/create`, `/{id}/remove`, `/{id}/credential`, `/{id}/oauth-client` | List; add (400 from `checkIntegration`, 409 when the insert fails, e.g. a duplicate slug); remove (403 for another account's); store a sealed static credential or OAuth client (503 when unconfigured, 400 on failure). |
| `POST /integrations/{id}/connect`, `GET /integrations/{id}/authorize`, `GET /oauth/callback` | Start the dial in the node's background group; hand the browser to the authorization server; receive its answer (400 when nothing is pending). |
| `POST /integrations/{id}/refresh`, `GET`/`POST /integrations/{id}/exposure`, `POST /integrations/{id}/reconfirm` | Refresh the catalogue; read and publish the exposure set (400 without the acknowledgment when write-capable tools are chosen; 409 without a catalogue snapshot); reconfirm stale entries. |
| `GET /api/identity`, `POST /identity/create` | Identities and their certificate state; create one (503 when `Create` is nil; a missing field or a failed create is a 200 with `error` set). |
| `GET /identity/{slug}/wallet`, `POST /identity/{slug}/wallet/start`, `POST /identity/{slug}/wallet/install`, `GET /wallet/submit.js` | Web-wallet signing request (below). Registered only when `IdentityDeps.Wallet` is set. |
| `GET /api/settings`, `POST /settings` | The knobs the deployment lets the owner change; save (a locked knob is never accepted; a bad value is rendered back with the error). |
| `POST /settings/adapter`, `/settings/storage`, `/settings/presets`, `/settings/presets/{name}/delete`, `/settings/pair`, `/settings/unpair`, `/settings/probe` | Adapter credentials (keyed `tunnel.<adapter>.<name>` or `integration.<slug>.<name>`), storage policy, presets, ingress pairing, reachability probe. The last six are registered only when their `SettingsDeps` field is set. |
| `GET /api/owners`, `POST /owners/passkeys/{id}/remove`, `POST /owners/tokens/create`, `POST /owners/tokens/{id}/revoke` | Passkeys and tokens. A new token's plaintext appears once, in `new_token` of that answer. |
| `GET /api/audit` | The trail, newest first, for the identities the session's owner administers. `actor`, `account`, `limit` (default 500, at most 5000). 401 with no owner; 404 for an account not administered; `names` maps the ids rows mention to names. |

The wizard gate (`GET /setup`, and `SetupAllowed` for the ceremonies): with a passkey present it is
404 unless the query carries a valid recovery token; with none, it passes from a loopback remote
address or with a valid setup token, and otherwise answers 403 "setup requires loopback or a
one-time setup token". Rendering the page never burns a token; `SetupDone` does, after a passkey
exists.

Responses the session gate gives an unauthenticated request outside the open set: 401
`{"error":"identity_required"}` under `/api/`, 401 "sign in first" for any other method than GET
and HEAD, and, for GET and HEAD, it passes the request on (see "What it does not do").

Web wallet: `GET .../wallet` shows what would be asked and of which wallet, and changes nothing
(signed out: 303 to `/login?next=`; not administered: 404; 409 with no public URL, with a portal
address a wallet will not answer, or for an identity with no root). `POST .../wallet/start` mints
the request and answers a page whose form posts it to the wallet; 409 if one is already pending
unless the form carries `replace=1`. `POST .../wallet/install` answers JSON; a refusal is
`{"error","code"}`: 404 `not_found`, 400 `malformed`, 409 `answered` / `no_request` /
`not_this_request`, 400 `wrong_root` / `wrong_key` / `not_newer` / `chain`, 500 `failed`. The
request's lifetime is 8 minutes (`walletRequestLifetime`).

## What it refuses, and how

- Session gate (`SessionMiddleware`): see above; every refusal under `/api/` or of a mutating
  method is audited as `portal_request` / `identity_required`.
- CSRF (`csrfMiddleware`): a state change needs the double-submit token (`X-HDTP-Csrf` header, or
  the form field `csrf`) equal to the CSRF cookie, 403 "csrf token missing or wrong"; and a
  browser must say the request is same-origin (`Sec-Fetch-Site` same-origin or none, or, with no
  Fetch Metadata, an `Origin` equal to the portal's), 403 "cross-site request refused". Both are
  audited (`portal_request`, outcome `csrf` or `cross_site`).
- Account scope (`accountMiddleware`): 404, never 403, for an account the owner does not
  administer; audited `portal_request` / `refused`. A request with no session is passed on
  untouched.
- Relying party (`OriginPolicy.RelyingParty`): the Host must be the configured `InternalHost`, or
  `localhost`; `127.0.0.1` and `[::1]` are refused because an IP address cannot be a relying-party
  id. Refusals answer 400 and are audited `refused_origin`.
- Security headers on every response: `Content-Security-Policy` (`portalCSP`: `'self'` only,
  `frame-ancestors 'none'`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`. The wallet start page alone widens `form-action` to the wallet's
  origin and sends `strict-origin-when-cross-origin`; `/media/{hash}` sets its own stricter CSP.
- Cookies: session `hdtp_session[_<tag>]` (HttpOnly, SameSite=Strict, `Secure` when the surface is
  served over TLS, 12 hours); CSRF `hdtp_csrf[_<tag>]` (readable by the page's script,
  SameSite=Strict).
- Invite landing (`LandingHandler`): unknown, revoked, expired and exhausted tokens are the same
  404, so the page is not an oracle for invite state; 503 "unavailable" when the card, the account
  or (for the JSON view) the chain cannot be produced.
- TLS (`LoadTLS`): neither file set is plain HTTP; one without the other, or a pair that does not
  load, is an error naming the paths and the minimum version is TLS 1.2.

## Invariants

- Every state change passes the CSRF check, and every `/api/` route and every method other than
  GET and HEAD needs a session. Held in the real composition by `internal/cli`'s
  `TestEveryMutatingPortalRouteRefusesAForgedRequest`, and here by
  `TestCSRFCookieOnGETAndEnforcedOnPOST` and `TestLoopbackStillDemandsALoginAndHostIsNotTrusted`.
- A signed-in owner cannot name an account they do not administer in the query or a urlencoded
  form (not in a multipart body: see below): `TestPortalRefusesAnAccountTheOwnerDoesNotAdminister`,
  `TestAnExplicitAccountIsNeverOverridden`, `TestSeveralAccountsAreNeverGuessedBetween`; in the
  real composition `internal/cli`'s `TestAnotherOwnersAccountIsNotFoundAndTheRefusalAudited`.
- An unauthenticated `/api/session` names no identity: `TestSessionEndpointDoesNotEnumerateIdentities`.
- The audit read is scoped by the session's owner, not by what the client sends:
  `TestAuditPageScopesByTheSessionOwner`.
- The wizard is closed once a passkey exists, except to a recovery token, and a recovery token
  adds a passkey without removing any: `TestWizardGoneOncePasskeyExists`,
  `TestALockedOutOwnerCanRecoverWithAMintedToken`; rendering it burns no token:
  `TestSetupTokenSurvivesRenderingTheWizard`; a non-loopback caller needs a token:
  `TestWizardNonLoopbackNeedsToken`.
- A spoofed Host is not used as the relying party, and the refusal is audited:
  `TestLoopbackStillDemandsALoginAndHostIsNotTrusted`.
- Two nodes on one host do not share cookie names: `TestTwoNodesOnOneHostDoNotShareCookieNames`.
- A peer-chosen contact name is never shown alone when it collides with another, including by
  cross-script look-alikes; the look-alike table is held to a shared fixture:
  `TestCollidingNamesCarryTheirFingerprint`, `TestNoListRendersAPeerChosenNameAlone`,
  `TestLookAlikeNamesCollideToo`, `TestTheLookAlikeTableIsTheFixtures`,
  `TestContactLabelsAnswerTheSharedCases`.
- A stored media file is served only to the account whose blob row names it, always as an
  attachment: `TestOwnerCanReadStoredMediaButNotAnotherAccounts`.
- A contact's file is fetched only when the owner asks: `TestMediaFetchIsOwnerInitiatedAndReportsRefusal`.
- Write-capable tools are exposed only with a recorded acknowledgment:
  `TestExposingDestructiveToolNeedsRecordedAck`.
- An invite's state is not observable from the landing page: `TestLandingNoOracle404`.
- Every wallet install refusal answers its code and is worded on the return page:
  `TestEachInstallRefusalAnswersItsCode`, `TestEveryWalletRefusalIsWordedOnTheReturnPage`.
- The portal's loopback rule for a wallet's redirect is the wallet's:
  `TestThePortalsLoopbackRuleIsTheWallets`.
- The portal and the owner MCP stay one authority: `TestEveryAgentCapabilityHasAPortalAffordance`,
  `TestEveryContactAndInviteDecisionAPersonMakesAnAgentCanMake`, `TestSpecNamesEveryOwnerToolOnce`,
  and every mutating portal route is reachable from the UI: `TestEveryPortalRouteIsReachableFromTheUI`.
- Server-rendered pages carry the brand palette of `web/src/brand.css`:
  `TestServerPagesCarryTheBrandPalette`.

## Held by

Test files in this directory, by concern: `server_test.go` (healthz, wizard gate, CSRF),
`auth_pages_test.go` (ceremonies, recovery, static shell not audited), `logout_test.go`,
`account_scope_test.go`, `account_resolve_test.go`, `security_headers_test.go`, `tls_test.go`,
`dashboard_test.go`, `contacts_pages_test.go`, `manage_pages_test.go`, `manage_lifecycle_test.go`,
`manage_address_test.go`, `manage_claim_test.go`, `add_contact_test.go`, `invite_url_test.go`,
`invite_landing_test.go`, `inbox_pages_test.go`, `conversations_unread_test.go`,
`conversation_times_test.go`, `presence_test.go`, `media_pages_test.go`, `media_send_test.go`,
`integrations_pages_test.go`, `integration_hygiene_test.go`, `integration_slug_test.go`,
`identity_pages_test.go`, `wallet_return_test.go` (with `wallet_return_test.mjs`),
`wallet_review_test.go`, `wallet_buttons_test.go`, `wallet_repeat_test.go`, `audit_pages_test.go`,
`displayname_test.go`, `labels_fixture_test.go` (reads `testdata/contact_labels.json`),
`style_test.go`, `chrome_test.go`, `route_ui_test.go`, `parity_test.go`, `contactcap_test.go`,
`revoke_failure_test.go`, `thread_topic_divergence_test.go`. In `internal/cli`, `doors_test.go`
holds the portal as composed.

## What it does not do

- It does not authenticate by itself: `SessionMiddleware` is installed only when `HandlerWithAuth`
  is given an `AuthDeps`, and a nil one (tests) leaves it off. `serve` always passes one.
- The session gate does not refuse an unauthenticated GET or HEAD outside `/api/`: it passes it on
  to the handler. That serves the SPA shell, and it is also how `/media/{hash}`, `/card.vcf`,
  `/events`, `/integrations/{id}/authorize` and `/oauth/callback` are reached with no session
  (`/oauth/callback` is not in the open set). Such a request runs with no owner, and the account
  middleware neither resolves nor refuses an account for it. Measured with a scratch test (not
  kept) on `HandlerWithAuth` with a non-nil `AuthDeps`: an unauthenticated
  `GET /media/{hash}?account=<id>` answered 200 with the stored bytes for an account the caller
  had no session for, and an unauthenticated `GET /events?account=<id>` answered 200 and opened
  the event stream for that account. What stands in the way is that the caller must know the blob
  hash (for media) and the account id.
- The account check does not cover a multipart body. `accountMiddleware` reads `account` only from
  the query and a urlencoded form, and `POST /messages/send_media` takes `account` from its
  multipart body. Measured with the same scratch test: a signed-in owner who administers account A
  posted a multipart `account=<B, which they do not administer>` and `SendMedia` was called for B
  (200); the same request naming B in the query was 404.
- It does not trust loopback as identity: a loopback portal still demands a login
  (`TestLoopbackStillDemandsALoginAndHostIsNotTrusted`).
- It does not hold the portal's UI. The pages are the SPA's (`web/`); the server-rendered pages
  here are only the wallet pages, the OAuth "authorization received" page and the invite landing.
- It does not hold the agent surface (`ownermcp`) or the passkey and token logic (`auth`).
- `DashboardDeps.Setup` and `DashboardDeps.SignedIn` are set by the wiring and not read by the
  dashboard handler.
- Several handlers redirect to SPA paths (`/contacts`, `/requests`, `/messages`, `/invites`,
  `/integrations`, `/identity`) with notices in the query: the redirect target is the SPA's route,
  not a server-rendered page.
