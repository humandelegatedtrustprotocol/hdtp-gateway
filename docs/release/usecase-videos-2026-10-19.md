# Use-case video series — plan

Owner's order (2026-10-19): "we need few videos where we're demonstrating usecases like booking
events, negotiating procurement of GPUs, rent negotiation, booking appointment with doctor/dentist,
asking for dayoff or for leave and more usecases. we need to demonstrate how humans who are busy
delegating outbound communication work to agents and only giving approvals looking at TLDR items, rest
communication is taken care by agents or sometimes completely by agents like in dentist/doctor's cases."

## What every video shows

- Two busy humans, each with their own node and their own agent. They're on Cloudflare quick tunnels,
  with the setup already done; video 1 shows the setup.
- The agents talk to each other on the humans' behalf, within limits each human set in their agent's
  instructions.
- A human is pulled in only through a **TLDR ask**: a one-glance summary card in their portal, built
  with A2UI from the node's catalog.
  - The card holds a TLDR line, the key terms, ready replies, and "write my own" last.
  - One tap approves, or picks a counter.
- Some cases need no human at all: the agents finish within limits, and the human sees a TLDR
  **notice** afterwards, not an ask.
- Everything is real: real nodes, real agents, and real model calls. Only the humans' lines, the
  instructions and the limits are planned. The agents' words are the model's own, live.

## What has to exist first (builds on docs/release/owner-asks-2026-10-19.md)

1. **N1 (node), owner asks:** stored, shown in the portal thread, answered by a tap, expiring, and
   audited. It's extended with:
   - **TLDR:** every ask leads with a one-line summary and a short key-terms list (catalog
     components Text and KeyValue). The portal also lists open asks across all threads on one
     "Needs you" page, so a busy owner sees every TLDR in one place.
   - **Notices:** a done-for-you TLDR (no buttons) for cases the agent closed alone, so the owner
     still knows what was agreed.
2. **A1 (agent), reply / ask / notify / none:**
   - `notify` is the done-for-you TLDR, sent after closing within limits.
   - **Autonomy in the instructions:** per topic, *ask before committing* or *commit within limits
     and notify*. The dentist case uses the second.
3. **Two agents per take,** one per node, with separate Studios. The recording tools are ready.

## The series (one take per video, about 60–90 s each, conversation-first layout)

| # | Use case | Parties (agent ↔ agent) | Limits in the instructions | Human touch |
|---|---|---|---|---|
| U1 | Book a meeting (time and agenda) | Ana ↔ Ben | Ana: Tue/Thu mornings busy, 30 min max; Ben: afternoons, budget + timeline | Ana approves by TLDR ask; Ben's agent confirms for him |
| U2 | Book an event venue | an organiser ↔ a venue's booking agent | date window, headcount 40, budget ceiling | the organiser approves the final quote by TLDR |
| U3 | GPU procurement | a startup's buyer ↔ a cloud/GPU vendor's sales agent | 8×H-class GPUs, 3 months, a price ceiling per GPU-hour, delivery date | the buyer's founder approves price and terms; the vendor's rep approves a discount beyond their agent's floor |
| U4 | Rent renewal | a tenant ↔ a landlord | the tenant's max increase; the landlord's min, and a 12-month term preferred | both humans approve the final terms by TLDR |
| U5 | Dentist appointment | a patient ↔ a clinic's front-desk agent | the patient's free slots; the clinic's open slots, in its instructions | **none:** booked agent-to-agent; both humans get a TLDR notice |
| U6 | Leave request | an employee ↔ a manager | the employee wants Fri plus Mon; the manager's agent knows the team's cover rule | the manager approves by TLDR ask; the employee's agent sends the handover note |
| U7, if wanted | Return or refund | a buyer ↔ a shop's support agent | the return window, refund or credit | fully agents, with a TLDR notice |

**Honest limits:** no calendar, payment or inventory system is involved. Slots, prices and stock
come from each agent's instructions, and the narration says so. A real integration (for example a
calendar via the node's integrations) would be its own item.

## Order of work

1. The A2UI probe (running), then N1 and A1 with TLDR, notices and autonomy. These are the PRs, each
   reviewed.
2. A rehearsal take per use case, with no recording: check the turns end where planned and count the
   model calls.
3. Takes, one per use case, recorded from the merged node and agent.
4. Composition: the same pipeline with a conversation-first layout and the "Needs you" TLDR card as
   the hero shot; a short voiceover per video; masks listed for the owner.
5. The owner reviews each video. Publishing is the owner's (zone Z3).

## The owner's answers (2026-10-19)

- Length: **60–90 s each.**
- First batch: **all seven** (U1 meeting, U2 event venue, U3 GPU procurement, U4 rent renewal, U5 dentist,
  U6 leave, U7 refund).
- "we need to use A2UI in these demos. if A2UI is not ready, wait for it to get ready then make videos."
  No take is recorded until the A2UI asks and notices (N1 and A1) are merged and observed in a real portal.
