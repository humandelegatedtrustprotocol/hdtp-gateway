# One way to hold an identity: the passkey; the vault file and recovery key bring it back

Owner, 2026-09-26 (verbatim where quoted):

- "storing leaf there is against the platform's compliance" — the ledger's full leaf certificate
  has no business in the file (it grants nothing — a leaf is public and speaking as the host takes
  the leaf's private key, which never leaves the host — and nothing reads it: every wallet rule
  reads `endpoint`, `not_before`, `not_after`).
- "vault = root key + certificate + PRF output" — and a downloadable recovery-key file at first
  issuance, "so user have it".
- "we need to have new way as only way. Passkey is option 1 if its lost then upload vault with
  Recovery key to recover identity for signing it again and generate and save new passkey to
  password manager. cli and other places will follow this as default and only one way. no
  backward compatiblity required here at all so update & refractor all related places to adopt to
  this including specification and no new release its all in same version."

Measured 2026-09-26 (scratchpad root-probe, the wallet's own Wasm core in a real Chrome): one
passkey derives the same root on every assertion and after a page reload (PRF bytes identical); a
new passkey under the same name derives a different root; the core's PRF salt equals
SHA-256("pact/vault/1") computed independently. Not measurable here: the same passkey synced to a
second device (DevTools cannot carry a credential's PRF secret across authenticators).

## The one way

```
create   passkey (PRF) ──derives──▶ root, store key, store id
         the record at store id, sealed under store key: roots (no key), ledger, contacts
         ONE download: the vault file  { v: 2, roots: [{…, pkcs8}], prf, passkey }  sealed under
         the recovery key; the recovery key shown once, with Copy and Download-as-a-file
sign     "Use my passkey" → derive → the record → §2.2 proof → sign → the record grows.
         Nothing downloads.
lost     "I lost my passkey" → the vault file + recovery key → the prf in it opens the old record
         → a NEW passkey is created (the flow ends there, not an option) → the root key is sealed
         INTO the new record under the new store key, ledger and contacts carried → the old record
         deleted → ONE download: a fresh vault file with the new prf, under the same recovery key
after    "Use my passkey" with the new passkey: derive → the record → its root entry carries
         pkcs8 → that key signs, under the SAME fingerprint. Nothing on the wire can tell.
```

The record's root entry carries `pkcs8` exactly when the credential's derived root is not the
identity's root (a re-bound identity); otherwise never, as today.

No other way remains:

- **No browser-held key.** The `local` mode (an authenticator without PRF: key generated in the
  browser as a non-extractable handle, IndexedDB record) and the `file` mode as a way to *sign*
  (open a file, sign, no record) go. A passkey that answers without a PRF secret is refused with
  a sentence naming the providers that carry one; a file is opened only to re-bind.
  CONSEQUENCE, flagged for the owner: on an authenticator without PRF, nobody can create or use an
  identity. 1Password carries PRF (measured by the owner's own use); iCloud Keychain and Google
  Password Manager are unmeasured (memory: derived-roots-shipped).
- **No `v: 1` anything.** A `v: 1` vault file or record is refused, not read. The `.initial`
  stage, the post-signing download, the "updated vault" form and the "Download it again after
  signing" go. CONSEQUENCE: identities made before this ships cannot open their records; staging's
  are throwaway and are wiped by the pair harness; if any production identity matters, say so
  before I5 (the owner's files sumit/pallavi are staging's, by their passkey labels).
- **The `pact` CLI follows.** Its vault file becomes keys only; the ledger and contacts live in
  `<name>.pact-record.json`, sealed under the same recovery key and envelope. There is no passkey
  in a terminal, so the CLI's "lost" path is what it always was: the file and the recovery key.
- **The spec is corrected in place.** SPEC.md stays `2.1.3` (owner: "no new release its all in
  same version"); §9's wallet paragraph and §2.1 say what the code does. No wire change, no
  vector change. NOTE: a reader cannot tell the corrected 2.1.3 from the earlier one; the date on
  the version line is the only mark, and it is updated.

## Items, in landing order (each: build → gates → commit → push, before the next)

### I1 · pact-protocol (a PR; the owner merges — a push is publishing)
- §9 wallet paragraph: the file carries the root, its certificate and, for a derived root, the PRF
  secret of §2.1, and nothing else; the ledger and contact book live in the record under §2.1's
  store key; a wallet holds a re-bound root at rest inside that record when the credential that
  derived it is lost, on the person's act, and nowhere else. "Better, the root is not at rest at
  all" keeps its force for the ordinary case.
- §2.1: the root MUST be derived from a credential (MAY → MUST); the record's contents named.
- Version line: `2.1.3 · 2026-09-26`. `npm run vectors:check`, `npm run build`.

### I2 · pact-identity: contract, both ports, the CLI, the pin
- `contract/contract.json`: `LedgerEntry` without `leaf`; `VaultPlaintext` and `RecordPlaintext`
  defined (`v: 2`; the file: roots with `pkcs8`, `prf`, `passkey`; the record: roots without,
  `ledger`, `contacts`, `passkey`, `backup_verified_at`). CONTRACT.md regenerated.
- Rust `wallet_issue`/Go `WalletIssue`: take the record plaintext; the entry without `leaf`.
  `vault_open` refuses `v` ≠ 2. Parity's two `ledger_entry.leaf` lines go; intrusion suite
  unchanged.
- CLI: `id_create` writes the vault (keys) and the record; `id_issue`, `id_ledger` (no key
  column), `id_show`, `id_backup`/`id_restore` (both files), `contacts_export`/`import`, `card_*`
  read and write the record. A `v: 1` file is refused with the one sentence.
- `sh gate.sh`; then the pin: commit → `sh js/reproduce.sh --pin` → commit the manifest → vendor
  into `pact-cloud/gateway/vendor/pact-identity/` → `check-wasm` → `build-ceremony --pin`.

### I3 · pact-cloud: the wallet page (`gateway/src/ceremony/`)
- Creation: the file as above, one download, no `.initial`; the recovery-key file
  (`<name>.recovery-key.txt`: the key and one line saying what it opens) beside Copy.
- The record as above; `storedPlaintext` strips `pkcs8` unless re-bound.
- Signing: no download; `dn-refresh`, `dn-again`, `dn-pass`, `vaultText` after creation, and
  every line only they used go (rule 2). The done note says the record holds the certificate.
- "I lost my passkey" (the `file` screen, renamed): open → derive the old store key and id from
  `prf` → read the old record (404 is reported, and the rebind goes on with an empty history) →
  create the new passkey (the 2026-09-25 label) → new record with `pkcs8`, ledger, contacts, the
  new `credential_id` → §2.2 proof from that record → delete the old record → download the fresh
  vault file under the recovery key just typed → continue to the signing that was asked for.
- "Use my passkey": a root entry with `pkcs8` signs with it; the three §2.2 checks unchanged.
- `local` mode, `idb*`, `signerFromHandle`, `openFromBrowser`, `NoSecret`'s fallback go; the
  refusal sentence for a PRF-less passkey stays.
- `MAX_VAULT_BYTES` rechecked for a `pkcs8` root plus 5,000 contacts.
- Gates: `make check`; `make wallet` with new cases, each red first: one download at signup with
  exactly the file's shape; a renewal downloads nothing; the recovery-key file; the lost path
  end to end (old record 404 after; the new passkey signs under the old fingerprint; the fresh
  file opens under the recovery key and carries the new `prf`); a PRF-less passkey refused at
  signup and at rebind; a `v: 1` file refused; a wrong recovery key; a file for another root.

### I4 · pact-cloud: harness and staging
- `staging-identity.mjs`: one download, asserted by opening it with the recovery key read off the
  screen (roots + prf + passkey, nothing else); `signInWallet` asserts nothing downloads.
- Scenario **RB1**: alex, on the kept wallet tab (its authenticator holds passkey A and can hold
  B), takes the lost path with the file, ends with passkey B, renews with B under the original
  fingerprint; the certificate route's `credential_id` is B's; the old record's address is 404;
  the control: a message from bob afterwards is received.
- `make ship-staging && make e2e-pair` green; logs to `docs/release/review-2026-09-23/runs/`.

### I5 · ship
- `make ship-production` from a clean `main`; umbrella gitlinks (cloud, protocol) after both are
  pushed; the build-state memory.

## What the owner does
1. Merge the SPEC PR (I1).
2. After I4, on staging with a REAL 1Password passkey: create, keep both files, delete the
   passkey, take the lost path, renew. The one measurement a virtual authenticator cannot make.
3. Say before I5 if any production identity must survive (none is migrated).

## Out of scope
Passkey sync across devices (a provider property, §2.1); the archive/export format; the node's
own identity handling; the marketing site.

## Status, 2026-09-26

| Item | State |
|---|---|
| I1 · SPEC 2.1.3 corrected in place | pact-protocol PR #3 open (branch `spec/one-way-vault`, 30d52b5); the owner merges |
| I2 · core, contract, both ports, CLI, pin | umbrella c146fce + fb11079; gate green (parity 430/430, contract 860/860, B 116/116, intrusion 132/132, 52 MUSTs named) |
| I3 · the wallet page | cloud 6775b63; `make wallet` 112/112 on the pinned core; `make check` green |
| I4 · the pair harness, RB1 | cloud 6775b63; pair run 41 on staging in progress |
| I5 · ship | after run 41 is green |

`MAX_VAULT_BYTES` (256 KiB), measured with the core on 2026-09-26: a re-bound root's entry is 657
bytes against 555 plain (+102); a ledger entry 259; a contact carrying a leaf and a root
certificate 1,172; the sealed document is base64 of the plaintext (4/3) plus a 364-byte header, so
the cap holds about 165 such contacts. That bound predates this work (the browser wallet keeps no
contacts; the CLI's record is a file with no cap) and is unchanged.

Found on the way: puppeteer's `page.click` hangs on a page no longer in front once another page has
added a virtual authenticator (memory: puppeteer-click-needs-front); every driver page is brought to
the front after `goto`.

