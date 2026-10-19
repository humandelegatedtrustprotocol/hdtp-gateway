# services/webhooks

The node's outbound webhooks: where an account's events are posted, the signing secret each endpoint is shown once, and the log of what was posted. It is BatonDeck's `gateway/src/webhooks/` ported one file for one (`sign.ts` → `sign.go`, `seal.ts` → `seal.go`, `endpoints.ts` → `endpoints.go`, the record and the targets of `deliver.ts` → `deliver.go`, `publish.ts` and the attempt of `deliver.ts` → `dispatch.go`), with the cloud's names, constants, refusal codes, envelope and signature grammar. It runs on the node's store, keyring and change log (`docs/release/webhooks-2026-10-18.md`, items W1 to W3). It calls the store, `internal/messaging` (the change row as an event, the delivery statuses, `FeedCalls`) and `internal/refusal`. The retention pass (`internal/services/retention`) deletes its delivery rows after 30 days and clears a replaced secret once it is no longer accepted.

`serve` builds one `Service` and hands it to the dispatcher and to the portal's Webhooks page (`internal/internalui/webhooks_pages.go`), the one door that registers, rotates, pauses, resumes and removes an endpoint and reads its log (ruling A). The owner MCP and the CLI have none.

## What it holds

- `Service` (`New(st, kr, audit)`): `Create`, `List`, `Rotate`, `SetStatus`, `Remove`, `ListDeliveries`, `RecordAttempt`, `SecretsFor`. It is the one implementation under every door: the portal (ruling A) and the dispatcher.
  - `Create(accountID, url, events)` answers the `EndpointView` and the `whsec_` secret. The secret is in that answer and nowhere else. The URL is stored trimmed, the filter without repeats, the times in unix milliseconds. An account has at most `EndpointLimit` (100) endpoints. The count and the insert are one transaction that locks the account first (`LockAccount`), so the cap holds under concurrent creates on either engine (`TestTheCapHoldsUnderConcurrentCreates`). The account's first endpoint starts the dispatcher's cursor at the newest change (`StartWebhookCursorAt`), so the dispatcher does not claim the log written before it one change at a time.
  - `List` returns the account's endpoints, newest first, at most `EndpointLimit` (the cloud's limit).
  - `Rotate` mints a new secret, shown once. The one it replaces stays accepted for `RotationWindow` (24 h). A rotation during a rotation drops the oldest of three. A paused endpoint rotates.
  - `SetStatus("paused" | "active")`: resuming clears the failure run.
  - `Remove` deletes the endpoint. Its delivery rows stay and keep naming it until the retention pass takes them at 30 days.
  - `ListDeliveries(accountID, endpointID, limit)`: newest first. 50 rows when limit is 0, refused outside 1 to 200 (the cloud's `limitQuery(200, 50)`). The endpoint is looked up first.
  - `RecordAttempt` writes one attempt's row and the endpoint's health in one transaction (`store.Atomically`). A success clears the run. A failure counts one, and the `FailureLimit`-th (20) in a row parks the endpoint. A failure marked `Stopped` (the attempt ended because the process was stopping) is logged and not counted. The excerpt is cut to `ExcerptBytes` (500) bytes of whole UTF-8 characters.
  - `SecretsFor(endpoint, now)` returns the current secret, then the replaced one while it is accepted. When only the replaced one will not open, it signs with the current one alone and reports `previousLost`.
- Views: `EndpointView` (`id, url, events, status, consecutive_failures, rotating_until, created_at, updated_at`, as the cloud's, with no secret, sealed or otherwise) and `DeliveryView` (`id, endpoint_id, event_id, event_type, status, http_status, latency_ms, response_excerpt, created_at`).
- Signing (`sign.go`): `SignatureHeader` `X-HDTP-Signature`, `EventIDHeader`, `EventTypeHeader`, `DeliveryHeader`, `ToleranceSeconds` (300), `SignedPayload` (`<t>.<body>`), `Signature` (`t=<s>,v1=<hmac>[,v1=<hmac>]`, HMAC-SHA256 keyed by the secret's bytes, new secret first), `NewSigningSecret` (`whsec_` + 43 base64url characters).
- Sealing (`seal.go`): the secret is sealed with the node's keyring (`Sealer`, which `core.Keyring` satisfies). The additional data is `webhook-secret:<account>:<endpoint>`. It does not name the column, because a rotation moves the current blob to `previous_sealed` in one statement.
- Events (`events.go`): `EventEnvelope` and `EnvelopeBody` (`{id, type, created_at, identity?, data}`, created_at in milliseconds); `EnvelopeOf(change, accountID)`, the envelope a change row is delivered as, with id `evt_<change id>` and `identity` the account's id (every owner MCP tool takes the account id; the cloud sends the slug, below); `Subscribable()`. One table maps a bus kind to a cloud name, and `Subscribable` is read from it:

  | Name | The change row | Data |
  |---|---|---|
  | `message.received` | `message`, inbound, text | `thread_id, message_id, from` |
  | `message.delivered` | `delivery`, delivered | `thread_id, message_id` |
  | `message.failed` | `delivery`, failed | `thread_id, message_id` |
  | `media.received` | `message`, inbound, media | `thread_id, message_id, from` |
  | `request.pending` | `pending` | `request_id, fingerprint` |
  | `request.answered` | `answered` | `request_id` |
  | `ask.answered` | `ask`, answered (the owner answered an ask, `internal/services/asks`) | `ask_id, thread_id` |
  | `ask.expired` | `ask`, expired unanswered | `ask_id, thread_id` |
  | `call.made` | `call` naming a tool of `messaging.FeedCalls` | `fingerprint, capability` |

- The receiver's verifier (`verify_test.go`): `ParseSignatureHeader` and `VerifySignature` (the window, then a constant-time compare). The node never verifies a signature, so the verifier is not in the binary. `sign_test.go` holds it, and `TestADeliveryIsSignedWithTheHeadersAReceiverNeedsAndLogged` verifies with it the delivery a receiver got.
- `TargetsFor(endpoints, event)` returns the active endpoints whose filter is empty or names the event, registered no later than the event, in whole seconds (the change log keeps seconds). `NewDeliveryID` mints `whd_` + 32 hex characters; endpoint ids are `whe_` + 32 hex characters.

## The dispatcher (`dispatch.go`)

`NewDispatcher(svc, bus, leading, version, log)` and `Run(ctx)`, started by `serve` (`internal/cli/serve.go`):

- It is woken by every event the bus delivers, with `messaging.PollInterval` (250 ms) as the floor, and then reads only while `leading` says this process holds the `LeaseName` lease, `webhooks` (SPEC §11.1).
- A pass (`Pass`) reads every account with an endpoint, active or paused, and pages its change log 500 rows at a time from its `webhook_cursor`.
- For each change, the cursor is claimed BEFORE the change is posted: `ClaimWebhookCursor` moves it from the id it was read at, and a claim another process got first ends the account's pass. A process that stops mid-post does not post the change again, so a change is posted at most once (ruling C), and of two processes on one store only the one whose claim moved the cursor posts it.
- A change a webhook carries (`EnvelopeOf`) is posted to `TargetsFor` the account's endpoints, one after another. Each endpoint is read again first: one removed or paused since the list is sent nothing.
- The attempt: one `POST`, `Content-Type: application/json`, the signature at the attempt's second over the current secret and the replaced one while it is accepted, `X-HDTP-Event-Id`, `X-HDTP-Event-Type`, `X-HDTP-Delivery` (the delivery row's id), and `User-Agent: hdtp-gateway-webhooks/<version>`. `Timeout` (10 s) covers the answer too. A redirect is not followed: the 3xx is the answer, and a failure. At most `ExcerptBytes` of the answer are read, the character the limit cut in two is dropped, and the rest is never read. A non-2xx, a timeout, a refused connection, a DNS failure and a TLS failure are all failures; the excerpt tells them apart and never holds the URL.
- Every attempt is recorded by `RecordAttempt`. Nothing the dispatcher does can fail the change it posts. A failure is swallowed and leaves one line on `serve`'s stderr, `webhooks: <stage> [account:<id>] [event_type:<type>]`, never the error's text: `webhook_accounts_unreadable`, `webhook_cursor_unreadable`, `webhook_changes_unreadable`, `webhook_cursor_unwritable`, `webhook_endpoints_unreadable`, `webhook_secret_unreadable`, `webhook_previous_secret_unreadable` (a warning: the delivery went ahead with the current secret), `webhook_delivery_record_failed`, `webhook_publish_failed`. A failure at an endpoint stops the event's later endpoints; the cursor has already moved past it. No line is written once the process is shutting down, but an attempt in flight when it stops is still recorded, within 5 s (`recordTimeout`), as a failure that does not count toward the pause (`TestAPostInFlightWhenTheProcessStopsIsStillLogged`).

## What it refuses, and how

- `Create`:
  - an account the store does not hold is `refusal.NotFound("unknown account")`;
  - `CheckEndpointURL`'s `url_too_long` (over `MaxURLBytes`, 2,048 bytes, once trimmed; the node's own code), `not_a_url` (not an absolute http or https URL with a host) and `has_credentials` (a user or password in it), and `CheckEvents`'s `unknown_event` (a name the node does not emit, the cloud's names it does not emit included), are each `refusal.BadRequest` in the cloud's words (the node's own for `url_too_long`), joined to `Refused{Code, Detail}`. One `webhook_create account:<id> bad_request` row is written and nothing is stored;
  - an account that has `EndpointLimit` endpoints is `refusal.Conflict`, saying so. One `webhook_create account:<id> endpoint_cap` row is written and nothing is stored.
- `List` of an unknown account is `not_found`, never an empty list.
- `Rotate`, `SetStatus`, `Remove` and `ListDeliveries`: an endpoint that does not exist, and another account's, are both `refusal.NotFound(refusal.NotFoundDetail)`. The other account's endpoint is left as it was. The three writes audit the refusal (`not_found`) under the caller's account and the id asked for. A second `Remove` is `not_found`.
- `SetStatus` with a status other than `active` or `paused` is `bad_request`, audited as `webhook_status account:<id> webhook:<id> bad_request`; `ListDeliveries` with a limit outside 1 to 200 is `bad_request`.
- A store or keyring failure is returned as it is, with no audit row.

## Audit

One row per change, written here (Building rule 7), in the node's snake_case:

- `webhook_create account:<id> webhook:<id> host:<host>` (`ok`, or `account:<id>` with `bad_request`, or `endpoint_cap` for the refused 101st, as `contact_initiate`'s `contact_cap`). The row names the host and never the address, because a receiver may put a token in the path or the query and an audit row is never edited afterwards;
- `webhook_rotate`, `webhook_pause`, `webhook_resume`, `webhook_delete`, each with `account:<id> webhook:<id>` (`ok` or `not_found`);
- `webhook_status account:<id> webhook:<id> bad_request`, a status that is neither.

Deliveries are not audited: the delivery log is their record, as in the cloud.

## Divergences from the cloud

- **URLs (ruling A):** the node takes `http`, IP literals, loopback, LAN and inward names (`localhost`, `.local`, `.internal`). The cloud refuses them as `not_https`, `literal_address` and `private_name`. A scheme other than http or https is `not_a_url` here, where the cloud says `not_https`.
- **Headers:** `X-HDTP-*` where the cloud has `X-BatonDeck-*`. The grammar is the same.
- **The envelope's `identity`:** the account's id, where the cloud sends the identity's slug (`identity.ts`, the event it hands to `enqueueEvent`). Every owner MCP tool of the node takes an account id, so a slug would make a receiver look the account up first. Held by `TestTheEnvelopesIdentityIsTheAccountIDWhereTheCloudSendsTheSlug`.
- **Delivery rows:** no `attempt` (always 1 in the cloud), no `next_attempt_at` and no `payload_json` (always null there). There is never a second attempt, so the columns would be dead.
- **No queue:** the cloud enqueues each event and its consumer posts it. The node reads its change log from a cursor per account, claimed before each post, under a lease. A change the log no longer holds (it keeps a week, SPEC §7.8) is never posted.
- **Redirects:** not followed, where the cloud's `fetch` is told `redirect: "manual"` and its guard refuses the address a redirect names. The owner named one address (ruling A), and a redirect would post the signed event to one the owner did not name.
- **Bounds:** at most 100 endpoints per account and a URL of at most 2,048 bytes. The cloud lists 100, and its checks refuse neither.
- **Doors:** the portal only (ruling A). The cloud has its portal, `/v1` and six owner MCP actions (`webhooks`, `webhook_deliveries`, `create_webhook`, `rotate_webhook_secret`, `set_webhook_status`, `delete_webhook`, in `src/mcp/owner/actions.ts`), which list, create, rotate, pause, resume and remove endpoints and read their log. Held by `TestNoOwnerMCPToolTouchesAWebhook` (`internal/internalui/ownermcp`) and `TestNoCommandTouchesAWebhook` (`internal/cli`).
- **Audit names:** snake_case with the node's resource string, where the cloud has `webhook.created` with JSON details.
- **Events:** only the nine names above. `ask.answered` and `ask.expired` are the node's alone: the cloud has no owner asks. An ask put or withdrawn, and a notice posted, are the agent's own acts and are not sent. `contact.*`, `booking.*`, `integration.attention` and `identity.*` are not emitted, because the change row does not say which of them happened (`events.go` says why for each). `request.pending`, `request.answered` and `call.made` carry a subset of the cloud's data.

## Held by

- `sign_test.go` (with the verifier of `verify_test.go`): the timestamp is inside what is signed, with a pinned HMAC vector that `openssl` and Node's `crypto` agree on; the tolerance window both ways; a changed body, a wrong secret and malformed headers are refused; a rotation signs with both secrets, the new one first; a secret is `whsec_` plus 43 characters, and 20 are distinct.
- `endpoints_test.go`:
  - `TestAURLIsAnHTTPOrHTTPSURLWithAHostAndNoCredentials`, and `TestTheNodeTakesTheAddressesTheCloudRefuses` (ruling A, over every URL the cloud's test refuses);
  - `TestEachRefusalSaysItsOwnReasonInTheCloudsWords`;
  - `TestAnEndpointIsRegisteredFiltersOnEmittedEventsAndIsShownItsSecretOnce` (no secret in the serialised list, the stored secret sealed, the view's fields, the audit row);
  - `TestRotatingKeepsTheOldSecretAcceptedForADay`, `TestAPausedEndpointRotates`, `TestAnEndpointPausesResumesWithACleanSlateAndIsRemoved`;
  - `TestEveryCallRefusesAMissingAnotherAccountsAndAMalformedTarget` (Building rule 3, with the owner's own calls as the control);
  - `TestTheListIsNewestFirstAndBounded`, `TestTheEndpointPastTheLimitIsAConflict` (with another account's and a freed slot as the controls), and `TestTheCapHoldsUnderConcurrentCreates` (two processes on one store race for the last slot, five rounds, on SQLite and on PostgreSQL when `HDTP_TEST_POSTGRES_DSN` is set);
  - `TestTheFirstEndpointStartsTheCursorAtTheNewestChange` (and a second endpoint leaves the cursor where it is).
- `events_test.go`:
  - `TestAFilterTakesExactlyTheEventsTheNodeSends`;
  - `TestEveryChangeRowTheNodeWritesIsDeliveredAsItsNameOrNotAtAll` (rows the messaging service writes, and rows in the shape their publishers write, through `EnvelopeOf`; every offered name is delivered once);
  - `TestTheBodyCarriesIdsAndMetadataAndNeverContent`.
- `deliver_test.go`: targets by status, filter and registration time; a failure recorded as final; a run of 20 parks the endpoint, and a success clears the run without resuming it; the row and the health in one transaction or neither (`TestAnAttemptIsRecordedWithItsHealthOrNotAtAll`, with a store whose count fails); a removed endpoint's attempt is still logged; the excerpt's bound in bytes.
- `seal_test.go`: the current and the replaced secret open during the window and only the current one after it; a blob does not open on another account's row or another endpoint's; a replaced secret that will not open leaves the current one signing.
- `dispatch_test.go`, against `httptest` receivers:
  - `TestADeliveryIsSignedWithTheHeadersAReceiverNeedsAndLogged` (the cloud's "signs what it sends");
  - `TestANon2xxAndARefusedConnectionAreFailuresToldApartByTheExcerpt` (the cloud's "a non-2xx and a thrown fetch"; no token from the URL in the excerpt);
  - `TestAnEndlessAnswerIsCutWithoutReadingTheRest`, `TestAnExcerptDropsTheCharacterTheLimitCutInTwo`, `TestAnAnswerThatIsNotTextIsStillLogged`;
  - `TestARedirectIsNotFollowed`, `TestAnAttemptHasTenSecondsAndThenHasFailed`;
  - `TestAnEndpointGetsWhatItWantsFromItsRegistrationOnAndNothingWhilePaused`, `TestAnEndpointRemovedOrPausedMidBatchReceivesNothingAfter`;
  - `TestAFailureTheDispatcherSwallowsLeavesOneLineNamingItsStage`;
  - `TestTwoDispatchersOnOneStorePostEachChangeOnce` (the lease, and the claim with no lease), on two stores over one database.
- The store's side is the conformance suite's `webhooks` (`internal/core/store/conformance/conformance_webhooks.go`). The retention pass's two writes are held by `TestThePassTakesOldWebhookDeliveriesAndExpiredReplacedSecrets` (`internal/services/retention`) and the suite's `RetentionTakesOldDeliveriesAndExpiredReplacedSecrets`. The tests here run on SQLite, and those that open stores through `sharedStores` (the two dispatchers, the answer that is not text) on PostgreSQL too when `HDTP_TEST_POSTGRES_DSN` is set.

The portal's routes over this service, with their refusals, are held by `internal/internalui/webhooks_pages_test.go`. Not held here: the parity of the names, the envelope and the header grammar with the cloud's, by a test reading the sibling `batondeck` (W4).

## What it does not do

It does not retry, back off, keep a dead letter, put content in a payload, follow a redirect, or resume a parked endpoint by itself.
