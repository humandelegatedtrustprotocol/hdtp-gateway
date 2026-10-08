# messaging

Threads, messages, media blobs, retention and the node's event bus. `Service` and `MediaService`
write rows to `internal/core/store`; `Sweeper` deletes them by age; `Bus` tells waiting readers that
something changed. Callers: `internal/node` (sending, the retry sweep, publishing delivery events),
`internal/public` (inbound `send_message` and `send_media`), the owner surfaces `internal/internalui`,
`internal/internalui/ownermcp` and `internal/cli`, `internal/integrations` (publishes attention and
invalidate events), `internal/portable` (archives chats), and `internal/services/settings` and
`internal/services/retention` (the retention window and the sweep). The package calls only the store; it
has no path to the wire (service.go, comment in `record`), so an outbound row is written here and sent
by the node.

## What it holds

Messages (service.go):

- `Service.Record(ctx, account, contact, dir, Input)` stores one message with idempotency and returns
  a `Result` (thread id and the row's status). `Service.Thread` lists a thread's messages in order.
- `Origin` (`OriginPortal`, `OriginMCP`, `OriginPeer`, `OriginStored`) is the surface a message came
  from; it decides the sender label (`Origin.Sender`, `Input.Label`). `Sender` is `SenderAgent` or
  `SenderHuman`. `Direction` is `DirIn` or `DirOut`.

Media (media.go):

- `MediaService.ReceiveInline` (inbound), `SendInline` (the owner's outbound), `ReceiveURL` (records a
  url without fetching) and `Fetch` (the explicit owner act that retrieves a url).
- `BlobDir`: content-addressed files under `Root/<first two hex>/<sha256>`, mode 0700 directories and
  0600 files; `Put`, `Get`, `Remove`. `MediaMeta` is the JSON body of a kind=media message.
- `IsPrivateAddr`: the SPEC 7.5 refused ranges (loopback, private, link-local, unspecified, CGNAT
  100.64.0.0/10), exported so the outbound leg applies the same rule. Constants `MaxMediaBytes`
  (5 MiB) and `DefaultQuotaBytes` (10 GiB).

Retention (retention.go): `Sweeper.Sweep(ctx, account, window)` returning a `SweepResult`;
`RetentionStore`, `BlobRemover`.

Events (bus.go): `NewBus`, `Bus.Subscribe`, `SubscribeSized`, `Publish`, `Run`; `Event`, `EventKind`
with eleven kinds (message, request, pending, delivery, call, attention, answered, relayed, invalidate,
account, settings); `EventOf` (a change-log row as an event); `FeedCalls` (the tools whose success is
published as an `EventCall`); `ChangeLog`; `PollInterval` (250 ms).

### States

A thread has no status: it is a row with an id, an account, one contact, a topic and created/last
times. The first message creates it (an id the peer supplied is adopted on first sight); every later
message touches it (`TouchThread`). A thread belongs to the one contact that created it.

A message row's status, as this package writes it: `delivered` for an inbound message, `pending` for
an outbound one (service.go, status assignment in `record`). It then leaves this package: `internal/node`
sets `delivered` when a peer accepts it, `failed`, or gives it up at its deadline
(node/send.go:39-41). The deadline is the message's `ExpiresAt`, or its creation time plus
`store.DefaultMessageExpiry` (24 hours) when it has none (store.go:252-261). `queued_for_human` is not
written by this package.

## What it refuses, and how

`Record` (wrapped with a detail after the code):

- `bad_request` (`ErrBadRequest`): empty `msg_id`; `OriginStored` (a stored message is not recorded
  again); an origin that is none of portal, mcp, peer; a peer sender that is neither agent nor human; a
  thread id that belongs to another contact; an owner-composed message giving a topic for a thread that
  already exists.
- `too_large` (`ErrTooLarge`): text over 16 KiB (`maxTextBytes`); an owner topic over 256 bytes.

Media: `too_large` for empty data or data over 5 MiB, and for a fetch over 5 MiB; `ErrQuota` (the same
code text, a distinct value) when the account's blob bytes plus the new data exceed the quota. The quota
is `Quota()` when it returns more than 0, else `MaxBytes`, else `DefaultQuotaBytes`, read at each call.
`Fetch` refuses, with the code in the error text: `bad_request` for an unparsable url, `unavailable` for
a name that does not resolve or a transport failure, `permission_denied` when any resolved address is
private (the refusal is audited as `media_fetch_refused`), and any redirect.

`BlobDir` treats anything that is not a lowercase hex SHA-256 as absent: `Get` returns
`fs.ErrNotExist`, `Remove` does nothing.

## Invariants

- A replayed `(account, contact, direction, msg_id)` returns the original thread and status and
  writes nothing; a duplicate that races the insert is resolved the same way (service.go, `record`).
- Idempotency is per direction: an inbound msg_id never swallows an outbound message.
- The sender label of anything this node composes is derived from `Origin`, never from the caller's
  `Sender`; only `OriginPeer` carries a claim, and `OriginStored` keeps the label on the row.
- A published event is appended to the store's change log before it is delivered locally; `Run` skips the
  ids this process published so a subscriber hears each event once; a full subscriber channel drops the
  event instead of blocking the publisher.
- `Fetch` dials the address it vetted (the first resolved), not the name, so a rebinding DNS answer
  cannot change the target between check and connect; it times out at 30 s and follows no redirect.
- Retention deletes locally only. A blob row goes only when past the window and referenced by no
  retained message; its file goes only when no account references the hash. If any media body fails to
  parse, no blob is deleted in that sweep (audited as `blobs_skipped_unreadable_media`). A window of 0 or
  less deletes nothing.

## Held by

- service_test.go: `TestDuplicateMsgIDAcknowledgedNotReexecuted`, `TestTextCap`,
  `TestSenderLabelValidated`, `TestAnInboundMsgIDDoesNotSwallowAnOutboundMessage`,
  `TestTheSurfaceDecidesTheSenderLabel`, `TestAStoredMessageKeepsTheLabelItWasComposedWith`,
  `TestOwnersTopicOnlyStartsAThread`, `TestPeerSuppliedThreadIDAdoptedOnFirstSight`.
- threadowner_test.go: `TestAThreadCannotBeAdoptedByASecondContact`, `TestTheOwningContactKeepsUsingItsThread`.
- media_test.go: `TestInlineStoresAndDedups`, `TestPrivateRangeFetchRefusedAndAudited`,
  `TestFetchHappyPathWithInjectedRanges`, `TestQuotaExceededError`, `TestDefaultQuotaMatchesTheSpec`,
  `TestQuotaIsReadPerCallNotCapturedAtBuildTime`; blobpath_test.go: `TestBlobPathRefusesAnythingThatIsNotAHash`.
- retention_test.go: `TestUnlimitedRetentionDeletesNothing`, `TestRetentionDeletesPastTheWindowAndKeepsLiveBlobs`,
  `TestSharedBlobBytesSurviveUntilTheLastReferenceGoes`, `TestUnreadableMediaBodyStopsBlobDeletion`,
  `TestSweepNeverDeletesBlobsInsideTheWindow`.
- bus_test.go: `TestAnEventCrossesToAnotherProcessOnTheStore` (SQLite and Postgres),
  `TestAProcessDoesNotHearItsOwnEventTwice`, `TestPostgresWakesAnotherProcessAtCommit`,
  `TestAnEventPublishedBeforeTheReaderStartsIsDelivered`.

## What it does not do

- It does not deliver. `Record` with `DirOut` leaves a `pending` row; sending, retry and the
  delivered/failed transitions are `internal/node`'s.
- It never tells a peer to forget anything: retention is local and there is no wire protocol for remote
  deletion (retention.go header).
- It does not fetch a url on receipt: `ReceiveURL` records it, and only `Fetch`, an explicit owner
  action, retrieves it.
- An event is a hint, not the ledger: it names what changed and subscribers re-read the store; a dropped
  event is made up at the subscriber's next read (bus.go header).
