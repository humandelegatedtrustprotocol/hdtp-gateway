# Pre-release fixes — plan (2026-10-19)

The owner's order (2026-10-19): "fix all above in one pre-release PR with required testing done".
"Above" is the two groups of the triage: before release (v0.3.0 + ghcr image) and before the
public demo node (A4). They span two repositories, so this is one PR per repository:

| Repo | Branch | Issues |
|---|---|---|
| hdtp-gateway | `fix/pre-release-2026-10-19` from 2170fda | #221, #204, #210, #213, #207, #208, #219 |
| hdtp-gateway-agent | `fix/pre-release-2026-10-19` from origin/main | #6, #3, #11, #2, #7 |

Merge order: the node PR first (#208 gives read_thread a message id), then the agent PR, which
keys replies on that id. There is no fallback for a node without the id (standing rule 2: no
backward-compatibility code). The agent requires the node release that carries #208, and its
README says so.

## Node items (one commit per issue, in this order)

1. **#221.** The settings save accepts what the checkbox sends. One rule for both values, in one
   place. Test: post the form exactly as `settings.tsx` renders it (value "1"), and it must read
   back as true. Mutation-checked: red on 2170fda. Observed: tick "Accept LAN connections" in a
   real portal, Save, reload, and it is still ticked; the cloudflared container is accepted.
2. **#204.** The compose portal forwarder recovers after a runtime restart of the node (crash,
   `docker restart`). Probe first: the cheapest real mechanism, measured on Docker. Observed:
   `docker restart` of the node, and the portal answers within a stated bound. A hermetic guard
   holds the compose file's shape.
3. **#210.** `/api/invites` projects its answer to the fields the Invites page reads. Test: the
   answer has no hash field (red before).
4. **#207.** `send_to_contact` for an unknown contact answers the not-found refusal, the same on
   every door (rule 1). Refusal tests (rule 3).
5. **#208.** `read_thread` rows carry the message id, the same id as the change log and the
   webhook envelope's `data`. Test holds the three equal.
6. **#219.** Reproduce first. Read the outbound retry in `internal/node/send.go` and decide which
   side is wrong: a retry of a send that succeeded, or an audit row for a retry that never
   happened. Fix that side. The test fails on 2170fda.
7. **#213.** Read each high advisory against how the portal uses the package. Either bump it (a
   Z4 prompt for the owner; then `make web` and commit `dist`) or write down why it does not apply.

Gates: `make check`, `make analyze`, `make sqlc-check` under `lockf .claude/locks/gate-node.lock`.
`make harness` runs at pre-push. The compose items (#221, #204) are observed on real compose nodes.
Ports must not collide with video-v0 or other live runs.

## Rules walked (Building 1, 3, 4, 5, 7)

Each PR body says which applied and which did not, and why.
