# Support

**Nothing has been released yet.** Questions and bug reports go to this repository's
issues; the bug report template asks for what helps most. There is no discussion forum.

**A security report is not a support question.** It goes privately to the same address, under the
subject and the policy [`SECURITY.md`](SECURITY.md) gives, and never into an issue.

## Before you ask

Most questions are answered by something already written down:

| Question | Where |
|---|---|
| What is this supposed to do? | [`SPEC.md`](SPEC.md) — normative for behaviour |
| Why does it work this way? | [`PLAN.md`](PLAN.md) — the build record, including what went wrong |
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
