# portable

The node's side of HDTP's portable export (HDTP §9.2, SPEC §3.10): one identity's contacts, its chats and the files in them, written to one unencrypted zip, and read back from one. The zip format and every rule about what a file may say belong to hdtp-identity (`hdtpidentity.WriteExportZip`, `ReadExportZip`, and the `export_merge` call); this package maps the node's store rows to the format's rows and back, and reads and writes the node's files. Its only caller is `internal/cli/portablecmd.go`: `portable.Export` (line 115), `CheckWritten` (155), `CloudCeilings` (166), `Read` (225) and `Plan.Apply` (238). It calls `core/store`, `internal/messaging` (blob directory, `MediaMeta`) and `internal/identity` (`ValidDisplayName`, `GrantToAllOwners`, `AlgoP256`).

## What it holds

Export (`export.go`)

- `Export` writes one identity by slug to an `io.Writer` and returns a `Result`.
- `contactRow`, `messageRow`, `exportStatus` map store rows to the format's rows.

Import (`import.go`)

- `Read` checks a whole export against a slug and writes nothing; it returns a `*Plan`.
- `Plan` carries the checked contents and the merge result: `Write` (contacts `Apply` writes), `Fill` (held with no leaf, the file's pin fills it), `Keep` (held, left as they are), `Skip` (roots this host holds as a stranger's request), `Conflicts` (`Conflict`: where the file disagrees with a held pin; the held pin stands).
- `Plan.Apply` writes the rows in one `st.Atomically` transaction, then the files.

Checks on a written file (`check.go`)

- `CheckWritten` reads a just-written file back as an importer would.
- `CloudCeilings` names each BatonDeck import ceiling an export is over (`cloudZipBytes`, `cloudContacts`, `cloudThreads`, `cloudMessageLines`, `cloudMediaFiles` and the rest, written as literals at `check.go:32-50`). These are warnings, never refusals.

Shared (`portable.go`)

- `ErrRefused`, `ImportCeiling` (16 GiB of decompressed bytes, disk-bound; media is streamed one file at a time), `ImportMessagesCeiling` (128 MiB; `messages.jsonl` is the one member read into memory whole), `Result`.

### The archive as the code writes it

`export.go:20-125`. The members are `manifest.json`, `contacts.csv`, `threads.csv`, `messages.jsonl` and `media/<sha256 hex>` (`TestAnExportCarriesContactsChatsAndFilesAndNothingElse` asserts the exact member list). The manifest owner is the account's `RootFingerprint`; `OwnerName` is its display name; `Tool` and the export time come from the caller.

- Contacts (`contactRow`, `export.go:130`): root fingerprint, endpoint, petname, display name, status, was-active (`EverActive` or status `active`), both permission lists, leaf and root certificate (base64url, null when absent), added time. Not exported: the preset, the trust flag, the card, the SPKI.
- Contacts in status `pending_in` (a stranger's request, `aRequest`, `portable.go:51`) are left out and named in `Result.LeftOut`.
- Threads: id, contact, topic, created and last time; ordered by `CreatedAt`. A thread whose contact is not carried is left out with a truthful reason (a request never accepted, or a contact removed from this identity).
- Messages (`messageRow`, `export.go:145`): id, thread, contact, msg id, direction, sender, time, body, status, reply_to. A media message's description JSON (`messaging.MediaMeta`) is lifted into one attachment and the body is emptied; a media message with no hash (a link never fetched) travels the link as the body.
- Status mapping (`exportStatus`): `pending` and `queued_for_human` become `queued`; `failed` stays; everything else is `delivered`.
- Media: each distinct hash once, with its size read from the blob; sorted by hash.
- The writer itself (hdtp-identity) omits messages whose body or file reads as a private key, and nulls a `reply_to` the file does not carry; each is returned and recorded in `Result.LeftOut` and `LeftOutMessages`.

### The import as the code reads it

`import.go`.

1. `Read` finds the slug. A slug that exists must have a root; a new slug takes the owner the manifest names (`manifestOwner`) and its display name (`ownerName`), checked with `identity.ValidDisplayName`.
2. `ReadExportZip` validates the whole file under that owner and `ImportCeiling`.
3. For an existing slug, held contacts (except requests) are handed to `export_merge` with the file's rows (`merge`); a held pin is never replaced.
4. `Apply` creates the account when `New` (algo `identity.AlgoP256`, `SetAccountRoot` with the fingerprint and no certificate, `GrantToAllOwners`), imports contacts (`HandshakeDueAt = now`), checks the contact cap, imports threads, then each message with its blob row, then writes the media files to the blob directory.
5. Status on import (`storeMessage`): inbound arrives `delivered`; an outbound `queued` or `failed` arrives `failed` (this host was not asked to deliver it); everything else `delivered`. Contacts get `TrustFlag` `messages_only`. A contact with a leaf is pinned (SPKI from the parsed leaf; `PinnedAt` set for `active`, `blocked`, `pending_out`).

## What it refuses, and how

Every refusal wraps `ErrRefused`; callers test `errors.Is(err, portable.ErrRefused)`.

- Export: an unknown slug; an account with no root (`never been issued a certificate`); a message naming a blob the node no longer holds (`message <id> names file <hash>`); a media message whose description does not parse; a blob that disappears during writing; any error from `WriteExportZip`.
- `Read`: an existing slug with no root; a new slug whose manifest names no owner; a root already on this node under another slug; `messages.jsonl` over `ImportMessagesCeiling` (by declared size, before reading); any error from `ReadExportZip` (the corpus tests hold these to the core's words); an invalid owner name; a file thread whose id the identity already holds for another contact; an `export_merge` error.
- `Apply`: a contact cap breach (`core.ContactCapRefusal`, wrapped with `ErrRefused`) when the import leaves more contacts held than the cap and added to the count; a leaf that is not base64url or does not parse; a message whose id, or `msg_id` with that contact, is another message's. All rows roll back together. After commit, a media file that cannot be written or whose bytes no longer match its name is an error (non-refusal, the rows are already in).
- `CheckWritten`: a file `ReadExportZip` refuses (`does not read back as an export`).

## Invariants

- The export is built through the Store interface, never a database copy, and carries no key, setting, credential, session, invite, audit row or leaf ledger (`portable.go` package comment; `TestAnExportCarriesContactsChatsAndFilesAndNothingElse` searches the decompressed bytes for planted secrets and fails if any appears).
- A pin this host holds is never replaced by a file (`Plan.Conflicts`; `TestAnImportIntoTheSameIdentityMergesAndNeverReplacesAHeldPin`, `TestAMergeKeepsAHeldBlockAndSaysSo`).
- A held stranger's request is neither exported nor merged into, and an import does not overwrite it (`TestAHeldRequestIsSkippedWhenTheFileNamesTheSameRoot`).
- A refused import writes nothing: the rows go in one transaction (`TestAnImportIsHeldToTheContactCap` asserts a refused import leaves no account behind; the corpus tests assert nothing is written).
- An import into a new slug holds the file's root and no key, no root certificate and no leaf ledger (`Apply` calls `SetAccountRoot(..., nil)`; `TestANewSlugHoldsOnlyTheFilesRoot`).
- Re-importing is idempotent: rows already held are counted in `Result.AlreadyHere` and left (`TestAnImportCountsWhatItWrote`).
- Export then import round-trips what an export carries (`TestARoundTripKeepsWhatAnExportCarries`).
- `Export` does not refuse for BatonDeck's ceilings; it warns (`TestAnExportOverTheCloudsCeilingsSaysSo`, `TestTheCloudsCeilingsAtTheirBoundaries`).

## Held by

`portable_test.go`: `TestAnExportCarriesContactsChatsAndFilesAndNothingElse`, `TestTheCorpusIsImportedAsTheCoreReadsIt`, `TestTheCorpusIntoANewSlugIsRefusedInTheSameWords` (the shared hdtp-identity export corpus), `TestANewSlugHoldsOnlyTheFilesRoot`, `TestAnImportIntoTheSameIdentityMergesAndNeverReplacesAHeldPin`, `TestARoundTripKeepsWhatAnExportCarries`, `TestAnExportRefusesWhatItCannotCarry`, `TestAHeldRequestIsSkippedWhenTheFileNamesTheSameRoot`, `TestAnImportIsHeldToTheContactCap`.

`portable_review_test.go`: `TestAFileThreadIsNotMergedIntoAnotherContactsThread`, `TestAFileMessageWhoseIDIsTakenIsRefused`, `TestAnOwnerNameWithAControlCharacterIsRefusedAtTheReview`, `TestAnImportCountsWhatItWrote`, `TestAnExportSaysTrulyWhyItLeftAConversationOut`, `TestAMessageWaitingForItsHumanTravelsQueued`, `TestAnExportOverTheCloudsCeilingsSaysSo`, `TestTheCloudsCeilingsAtTheirBoundaries`, `TestOnlyAMediaNameIsAFile`, `TestTheCloudsDirectoryBounds`, `TestAnImportsMemoryFollowsItsMessages`, `TestAFileThatDoesNotReadBackIsRefused`, `TestAMergeKeepsAHeldBlockAndSaysSo`.

`scale_test.go`: `TestAnImportGrowsLinearlyWithItsThreads` skips unless `HDTP_EXPORT_SCALE` is set to at least 400 threads, so it measures nothing in a normal run.

## What it does not do

- It does not mint, import or carry a leaf key, and it does not install a leaf. Every import ends with a new leaf, but that is the caller's step: `nextLeaf` in `internal/cli/portablecmd.go` mints a `move` (new identity) or `renew` (existing) request and the wallet completes it; installing the leaf sends every imported contact this host's handshake (`HandshakeDueAt` is set to the import time here, `Apply`). This package never contacts a peer.
- It does not sync contacts. It reads one file the person hands it.
- It does not ask the person: the review (`Plan`) is shown and confirmed by the CLI (`-yes`), not here.
- It does not encrypt the zip.
- It does not merge a thread into another contact's thread, or a message into another message's id.
- The BatonDeck ceilings in `check.go` are the cloud's, not the format's; another host may take more.
