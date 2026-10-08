# internal/integrations/providers

Implements the HDTP core capabilities (check_availability, book_slot, cancel_booking, get_status) over an upstream MCP server's tools, driven by a recipe from `internal/integrations`. Contacts see HDTP's vocabulary; the vendor's names and raw data stay here. `internal/cli/capabilities.go` (around `:199`-`:207`) builds `providers.Calendar` and `providers.Status` from active mapped-mode exposure entries, with `ManagerCaller` as the `Caller`; `internal/public` consumes them through its `Calendar` and `StatusSource` interfaces (`tools.go`). The package calls `internal/integrations` (`Manager`, `Recipe`, `Binding`, `BuildArgs`, `Lookup*`) and `internal/calendar` (`Slot`, `BookingAck`, `MaxSlots`).

## What it holds

- `Caller`, `ManagerCaller` (`caller.go`): `ManagerCaller` binds a `Caller` to a live `Manager` session. It fails if the integration is not `Available` or has no session; on a transport error it calls `Manager.NoteCallFailure` (so an authentication failure moves the row's status) and returns an error. A tool result with `IsError` is an error; otherwise `StructuredContent` wins, else the first text content: an object or array is parsed, anything else stays a string, over `MaxUpstreamText` (256 KiB) it is refused; no content yields an empty object.
- `Calendar` (`calendar.go`): `CheckAvailability` returns at most `calendar.MaxSlots` candidate slots, earliest first, dropping slots whose end is not after the start. Two recipe kinds: `suggest` (the upstream returns candidate times, read from `Out["slots"]`, `slot_start`, `slot_end`) and `freebusy` (the provider tiles the window with duration-sized slots and keeps those that overlap no busy block, so raw free/busy never leaves). No working-hours filter exists. `BookSlot` reserves the `msg_id` through `IdemStore.PutIdempotency` before calling the upstream, reads the event id at `Out["event_id"]`, builds an opaque booking id (`EncodeBookingID`, `bk_` plus base64url) and a confirmation ICS it synthesizes itself (no upstream ICS is trusted), then writes the ack back through `UpdateIdempotencyAck`. `CancelBooking` decodes the booking id (`DecodeBookingID`) and calls the `cancel_booking` binding. `Params` are exposed to recipes as `$cfg.<name>`.
- `Status` (`status.go`): `GetStatus` reads the status string from a recipe's `get_status` binding when there is one, else asks `Local`, else returns `available`.

## What it refuses, and how

All as errors (the serving layer answers `unavailable` for upstream failures):
- A recipe lacking the capability: `recipe <name> has no check_availability` / `book_slot` / `cancel_booking`.
- An unknown availability kind; a response missing the configured path, or a slots path that is not a list.
- A booking whose `msg_id` is already reserved but has no recorded ack yet: `booking <id> is still in flight`; one already acknowledged returns the recorded ack without calling the upstream.
- An upstream that returns no event id; a store that cannot update the ack (`store cannot finalize acknowledgments`).
- A booking id without the `bk_` prefix or with bad base64.
- A recipe field reference with no value (`BuildArgs`, from `integrations`).

## Invariants

- Only candidate slots leave `CheckAvailability`, capped at `calendar.MaxSlots`; busy blocks are never returned (`TestFreebusyNeverLeaksRawAndCapsAtFive`, `TestSuggestKindOrdersAndCaps`).
- A replayed `msg_id` returns the recorded acknowledgment (`TestBookSlotICSAndIdempotency`); a booking id maps back to the upstream event id (`TestCancelBookingMapsBack`).
- A recipe parameter reaches every capability (`TestPerInstallParameterReachesEveryCapability`).
- Plain-text and numeric-looking upstream results stay strings; objects and arrays still decode; structured content wins; oversize text is refused; upstream tool errors surface (`caller_test.go`: `TestPlainTextResultIsAValueNotAnError`, `TestNumericLookingIdentifierStaysAString`, `TestJSONObjectsAndArraysStillDecode`, `TestStructuredContentWins`, `TestOversizeUpstreamTextIsRefused`, `TestUpstreamToolErrorSurfaces`).

## Held by

`calendar_test.go` (including `TestStatusLocalAndRecipeSourced`) and `caller_test.go`.

## What it does not do

- It releases nothing when the upstream call fails after the `msg_id` was reserved: the reservation stays with an empty ack in this code, and a retry then reports the booking as in flight. Whether the store expires it is the store's concern and is not read here.
- It does not filter by working hours; the connected calendar is the authority.
- It does not compute anything in a recipe; recipes only line fields up, and the slot arithmetic and ICS are here.
- No shipped recipe binds `get_status`, so `Status` answers locally in practice (`recipes/*.json`).
