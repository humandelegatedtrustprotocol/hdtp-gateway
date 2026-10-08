# calendar

The shared vocabulary of a calendar call (HDTP §6.2): a candidate interval, the acknowledgment of a booking, and the cap on how many candidates are offered. It exists so that the public surface and the calendar provider agree on three shapes without importing each other. `internal/public` (`tools.go`, `bounds.go`) and `internal/node` (`send.go`) use it for the port the public surface names; `internal/integrations/providers/calendar.go` produces and consumes it. Its only import is `time`; `internal/integrationtest/layering_test.go` ranks it 0 (it may import no node package; the standard library and third-party packages are not constrained by that guard).

## What it holds

- `MaxSlots` (`calendar.go`): 5, HDTP §12's cap on candidate slots offered in one answer.
- `Slot` (`calendar.go`): `Start` and `End` as `time.Time`, JSON keys `start` and `end` (RFC 3339 on the wire).
- `BookingAck` (`calendar.go`): `booking_id` and `ics`, what `book_slot` returns as the recorded acknowledgment (§11.2).

## What it refuses, and how

Nothing. The package has no functions and returns no errors. It does not enforce `MaxSlots`; the callers that build slot lists do.

## Invariants

- `internal/integrationtest/layering_test.go` (`TestImportsPointDownTheLayers`) ranks `internal/calendar` 0 in `layerRank`, so a non-test file here may import no node package, and the provider and the public surface, ranked above it, import it instead of each other. Today its only import is `time`. No test in this package.

## Held by

No test files in this package. Its types are exercised through `internal/integrations/providers/calendar_test.go` and `internal/integrationtest/calendar_test.go`.

## What it does not do

It does not talk to a calendar, pick slots, apply working hours or book anything. It is data and one constant.
