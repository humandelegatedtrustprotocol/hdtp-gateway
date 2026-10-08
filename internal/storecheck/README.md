# internal/storecheck

Reads every card and certificate the store holds by the rule the identity core reads them with, and
names each that does not read. It changes nothing. It exists because the core's reading gets
stricter between releases: what a node accepted at intake under the old reading is still on file
after the bump, and the core then refuses it where it reads it (a contact's card in
`contacts.SealOf`, so `node.PeerOf` refuses to write to that contact; a pin's leaf in Decide's
`pinHolding`), with nothing to say which row until somebody calls.

Callers: `internal/cli` only, through two doors that print the same lines. `serve` prints the report
in its startup banner (`serve.go`, `announce`) and `hdtp-gateway check store` prints it and exits 1
on a refusal (`checkcmd.go`). It calls `contacts.SealOf`, `public.UnknownContactState` and
`hdtpidentity.Parse`, so it sits above them (rank 5 in `internal/integrationtest/layering_test.go`).

## What it holds

- `Run(ctx, store, now)` walks every account and reads: the account's root certificate; each leaf;
  each contact's card (empty cards are skipped), leaf and root certificate; each tombstone's leaf;
  each pending address's leaf and root certificate. A card is read by `contacts.SealOf` (the reader
  every write to a contact goes through); a certificate held as DER by `hdtpidentity.Parse`. Empty
  columns are not fields to read. It also notes each contact whose status is one the node hands the
  identity core no pin for (`public.UnknownContactState`).
- `Report`: `Read` (a count per `<table>.<field>`), `Refusals` and `NoPin`; `Fields()` is how many
  fields were read; `Lines()` is the report as the operator reads it.
- `Refusal` (`Table`, `Row`, `Field`, `Why`) and `NoPin` (`Row`, `Status`).

`Lines()` is one summary line (`store:   N cards and certificates read by the identity core's rule
(...); all read | N do NOT read`, with a clause for contacts in an unknown state when there are any),
then one `NOT READ <table> <row> <field>: <why>` line per refusal, then one `NO PIN contacts <row>
status: ...` line per unknown-state contact.

## What it refuses, and how

`Run` returns an error, and an empty `Report`, only when a store listing fails (`ListAccounts`,
`ListLeaves`, `ListContacts`, `ListTombstones`, `ListPendingAddresses`); that is not a refusal and
the report says nothing was read. A field the core cannot read is a `Refusal` in the report, not an
error. The caller decides what that means: `check store` exits 1 when there is any `Refusal` or
`NoPin`; `serve` prints `store:   NOT CHECKED` on an error and goes on serving.

## Invariants

- It writes nothing, to the store or elsewhere. `serve` writes no audit row for it: a comment in
  `announce` (`serve.go`) says that, like the rest of the banner, it writes none because nothing
  changed, and the code calls no audit function there.
- The readers are the node's own, one per field, so a row that passes here is one the core will read
  where it reads it.

## Held by

`storecheck_test.go`: `TestTheRunNamesEveryCardAndCertificateThatDoesNotRead`,
`TestAStoreWhoseFieldsAllReadSaysSo`, `TestAContactInAStateNoPinHasIsCountedAndNamed`. At the
command: `internal/cli/checkcmd_test.go`, `TestCheckStoreNamesTheCardThatDoesNotReadAndExitsOne`,
`TestCheckStoreNamesTheContactInAStateNoPinHasAndExitsOne`, `TestCheckStoreRefusals` and
`TestServeNamesTheCardThatDoesNotReadInItsBannerAndServes`.

## What it does not do

It does not repair, delete or quarantine a row, and it does not stop `serve`. It does not read
invites, pending requests or messages: they hold no card or certificate. Beyond the two readers
named above (a card by `DecodeCard` through `contacts.SealOf`, a certificate by `Parse`) it checks
nothing: it does not compare a stored column with the certificate beside it.
