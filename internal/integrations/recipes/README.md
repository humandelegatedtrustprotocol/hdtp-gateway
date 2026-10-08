# internal/integrations/recipes

Embeds the recipe documents the node ships: per-server maps from HDTP capabilities to an upstream's tools (SPEC §6.7). Exposure entries in mapped mode name one of them; `internal/cli/capabilities.go:111` calls `All()` once to build the corpus the entries are resolved against, and an entry naming a recipe that is not in it is audited `recipe_bind ... unknown` and skipped. The documents are decoded with `integrations.DecodeRecipe` and executed by `internal/integrations/providers`.

## What it holds

- `All()` reads every `*.json` embedded at build time (`//go:embed *.json`) and returns `map[string]integrations.Recipe` keyed by each recipe's own `name`.
- The four shipped recipes: `google-official` (Google's Calendar MCP; `suggest_time` kind `suggest`, `create_event`, `delete_event`; carries a caveat that the write scope is unverified), `nspady` (`@cocal/google-calendar-mcp`; `get-freebusy` kind `freebusy`, `create-event`, `delete-event`), `workspace-mcp` (`query_freebusy`, and `manage_event` with a constant `action` of `create` or `delete`), `caldav` (`caldav-mcp`; `list-events` kind `freebusy`, `create-event`, `delete-event`; three caveats, and uses `$cfg.` parameters). None binds `get_status`.
- `testdata/upstream-defs.json`: tool names and argument properties captured from each server, used by the test.

## What it refuses, and how

`All()` returns the first error it meets: an unreadable embedded file, or a document `DecodeRecipe` refuses (invalid JSON, empty name, no capabilities, a capability missing `tool` or `kind`), wrapped with the file name. A duplicate recipe name silently overwrites an earlier entry (map assignment); no test covers that.

## Invariants

- Every shipped recipe binds only tools that exist in its server's captured definitions, and every argument it builds is a property that tool declares (`TestRecipesMapOntoCapturedServerDefs`, which also asserts there are exactly four recipes, that `google-official` keeps its UNVERIFIED caveat and that `workspace-mcp` keeps its action constants).

## Held by

`recipes_test.go`: `TestRecipesMapOntoCapturedServerDefs`.

## What it does not do

- It does not execute recipes or hold any logic; recipes are field lists and constants only (`integrations/mapping.go`).
- It does not validate that a server is reachable or that a caveat has been resolved; caveats are prose for the owner.
