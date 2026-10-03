# Support

**This repository is private and has not been released**, so there is no public issue
tracker or discussion forum yet. Reach the maintainer at **security@hdtp.io** with the
subject `[hdtp-gateway support]`.

**A security report is not a support question.** It goes privately to the same address, under the
subject and the policy [`SECURITY.md`](SECURITY.md) gives, and never into an issue.

## Before you ask

Most questions are answered by something already written down:

| Question | Where |
|---|---|
| What is this supposed to do? | [`SPEC.md`](SPEC.md) — normative for behaviour |
| Why does it work this way? | The build plan, `PLAN.md`, in git history before 2026-10-03, including what went wrong; what is still open is [`docs/release/open-items.md`](docs/release/open-items.md) |
| How do I run and operate a node? | [`docs/operations.md`](docs/operations.md) |
| How do I make it reachable? | [`docs/operations.md`](docs/operations.md), and `hdtp-gateway doctor` |
| Is behaviour X covered by a test? | [`docs/conformance.md`](docs/conformance.md) — each item cites its test |
| How do I contribute? | [`CONTRIBUTING.md`](CONTRIBUTING.md) |

## When something is not working

`hdtp-gateway doctor` derives your deployment mode and probes your endpoint; it is the
first thing to run and usually the last thing you need. The audit trail is
append-only and hash-chained — `hdtp-gateway audit` — and records every public call
and every refusal, which is generally the fastest way to see what a node actually did
rather than what it was expected to do.

If you report a problem, what helps most: what you ran, what you expected, what
happened, and the relevant audit rows or logs with any keys and tokens removed.
