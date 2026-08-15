# AFE — Monthly Work Plan (4 hours/day, 20 working days)

## How to use this document

Save the foundation document as `docs/concept.md` in the repo, so Claude Code sees it automatically. Each day: first read the **concepts** line (10-15 minutes of learning), and only then run the prompt. You are the architect and reviewer — Claude Code is the executor. After each day, make sure you can explain out loud *why* the code looks the way it does.

## Architecture decisions — before a single line of code

The foundation must be modular from day one, because the project is meant to grow over the year:

- **Split into four modules**: `agent` (the LLM harness), `baseline` (Pre-Flight and Baseline creation/signing), `gateway` (chokepoint and decision engine), `storage` (Baselines and logs).
- **Separation between policy and enforcement** — decision logic is fully separate from the actual action. This is what will allow swapping logical enforcement for real network enforcement later without touching the decision.
- **All thresholds and classifications in config, not in code** — recalibration shouldn't require a code change.
- **Two-tier storage** — JSON on disk (persistent, readable, good for debugging) + an in-memory cache on top of it, explicitly filling Redis's role: fast lookup at the chokepoint. No real Redis in the POC — a deliberate, documented substitute.
- **The request description is derived from the actual tool call**, not from the agent's self-reported intent (section 7 in the foundation document). This decision affects the entire implementation — don't deviate from it.
- **AFE runs on a closed network** — the embedding and comparison layer operates locally only, with an open-source model (not an external API), so that the tool protecting sensitive information doesn't itself become a leak path (section 2.3 in the foundation document).
- **The policy itself is signed and read-only** — not just the Baseline. The classification and threshold files are HMAC-signed like the Baseline, and kept read-only. No code writes to them at runtime — a change is a manual action only (section 2.4 in the foundation document).
- **Language: Python only.** Not C++, not Java. Over 20 working days with most of the code written by Claude Code, two languages add a build system and bindings with no benefit to the demo; and JSON handling in Java requires POJOs/Jackson while in Python it's native. If you're learning Java for interviews — practice it separately, don't mix two learning goals into a project with a deadline.

## Folder structure

```
afe-poc/
├── README.md
├── pyproject.toml
├── docs/
│   ├── concept.md
│   └── known_limitations.md
├── config/
│   ├── classification.json   # path/folder → classification level mapping
│   └── thresholds.json       # similarity threshold per classification level
├── src/afe/
│   ├── agent/
│   │   ├── harness.py        # agent loop + tool calling
│   │   └── tools.py          # mock tools
│   ├── baseline/
│   │   ├── preflight.py      # malicious-intent scanning
│   │   ├── baseline.py       # Baseline model (agent_id, dispatcher, task, commands...)
│   │   └── signing.py        # HMAC
│   ├── gateway/
│   │   ├── chokepoint.py     # the chokepoint itself
│   │   ├── classification.py # resource classification: inheritance, override, fail-secure
│   │   ├── similarity.py     # embeddings + cosine similarity
│   │   ├── policy.py         # classification-dependent thresholds, the three tiers
│   │   └── audit.py          # JSONL decision log
│   ├── storage/
│   │   └── store.py          # Store interface + JSONFileStore + CachedStore
│   └── config.py
├── scenarios/
│   ├── clean_report.md
│   ├── injected_report.md    # hidden payload
│   └── malicious_prompt.txt  # insider-threat scenario
├── eval/
│   ├── eval_set.json         # ~20 labeled requests
│   └── run_eval.py           # precision/recall
├── tests/
└── demo/
    └── run_demo.py
```

---

## Week 1 — Foundations and a working skeleton

### Day 1 — Setting up the repo
**Goal:** full folder structure, files with docstrings, choosing an LLM API and an embeddings API.
**Concepts:** API Gateway as an architectural pattern; Zero Trust.
```
Create a new Python project following the folder structure in the work plan document. Add
a pyproject.toml with dependencies for an LLM API with tool-use support (for the demo agent
only), a local embedding model like sentence-transformers (for AFE itself — no external
API, see section 2.3 in the foundation document), pydantic, and pytest. In every file add
a docstring describing its responsibility per docs/concept.md. Don't implement logic yet —
skeleton only.
```

### Day 2 — Mock tools and scenarios
**Goal:** `tools.py` + innocent scenario documents.
**Concepts:** Mocking / test doubles.
```
Implement src/afe/agent/tools.py: mock read_file(path), send_email(to, body), query_db(query)
functions, that log every call to a list and return fake data. Create
scenarios/clean_report.md with an innocent quarterly financial report.
```

### Day 3 — The agent harness
**Goal:** an agent loop with tool calling, wired to the mock tools.
**Concepts:** Tool use / function calling, agent loop.
```
Implement src/afe/agent/harness.py: a loop that sends a system prompt + task to the LLM
with the tool definitions from tools.py, handles tool_use blocks by calling the matching
function, and returns the sequence of tool calls. Add a usage example in __main__.
```

### Day 4 — Pre-Flight and Baseline
**Goal:** intent scanning + full Baseline model.
**Concepts:** Embeddings; what Pre-Flight actually checks.
```
Implement src/afe/baseline/preflight.py: a function that asks the LLM whether a system
prompt looks malicious, returning a boolean + explanation. Implement
src/afe/baseline/baseline.py: a Baseline (pydantic) class with agent_id, dispatcher, task,
task_embedding, commands, allowed_resources, created_at, status ("active"/"frozen").
task_embedding is produced by a local embedding model (sentence-transformers, loaded once
into memory) — not an external API. Add to_json/from_json.
```

### Day 5 — Signing and Storage
**Goal:** HMAC + two-tier storage.
**Concepts:** HMAC, integrity vs. secrecy, caching, abstraction behind an interface.
```
Implement src/afe/baseline/signing.py: sign_baseline and verify_baseline using HMAC-SHA256.
Implement src/afe/storage/store.py: an abstract BaselineStore class with get/save, a
JSONFileStore implementation, and a CachedStore wrapping any Store with an in-memory dict
cache — so get calls return from the cache without touching disk, exactly as Redis would.
Add a comment noting this is a deliberate substitute for Redis in the POC.
```

---

## Week 2 — Classification, Chokepoint, and the decision engine

### Day 6 — The classification layer (signed and read-only)
**Goal:** folder inheritance, file-level override, fail-secure — and the policy itself protected against tampering.
**Concepts:** Data classification, sensitivity labeling, fail-secure, segregation of duties.
```
Create config/classification.json: a path mapping to PUBLIC/INTERNAL/CONFIDENTIAL/SECRET
levels, including folders (/finance → SECRET, /reports → INTERNAL) and also single-file
overrides. Sign the file with signing.py from day 5 (the same HMAC mechanism, this time
over the config content instead of a Baseline), and keep it read-only on the filesystem.
Implement src/afe/gateway/classification.py: get_classification(path) that first verifies
the file's signature — if invalid, raises an error and AFE refuses to start (fail-secure)
— and only then returns the level per the rule: a single file overrides its folder;
downward override is marked in config and logged; a resource with no classification
returns as CONFIDENTIAL, not PUBLIC. Make sure no function in the code writes to this
file — read only. Add tests/test_classification.py including a test that an invalid
signature causes a load failure.
```

### Day 7 — Semantic similarity and classification-dependent thresholds
**Goal:** cosine similarity + mapping to tiers based on a classification-derived threshold.
**Concepts:** Cosine similarity, threshold calibration, risk-based access control.
```
Implement src/afe/gateway/similarity.py: a function that takes a request description,
produces an embedding using the local model (the same sentence-transformers model from
day 4, loaded once — no network call), and computes cosine similarity against the
Baseline's task_embedding (0-1). Create config/thresholds.json with a green threshold for
each classification level, signed the same way as classification.json on day 6 (HMAC +
read-only). Implement src/afe/gateway/policy.py: decide_tier(score, classification,
baseline) returning "green"/"yellow"/"red" — with the rules: a resource in
allowed_resources → green; PUBLIC → green; SECRET not in allowed_resources → red
regardless of score; otherwise compare against that classification level's threshold.
```

### Day 8 — The Chokepoint and Audit Trail
**Goal:** every tool call passes through the check; every decision is logged.
**Concepts:** Chokepoint pattern, audit trail, explainability.
```
Implement src/afe/gateway/audit.py: writing a JSONL line for every decision with
agent_id, timestamp, resource, classification, similarity_score, tier, reason,
triggered_by (which check decided: classification / allowlist / semantic). Implement
src/afe/gateway/chokepoint.py: evaluate_request(baseline, tool_name, tool_args) — builds
a request description from the actual tool name and arguments (not the agent's
self-reported intent!), calls classification, and if needed similarity and policy, logs
to audit, and returns a Decision. Wire it into harness.py so every tool call passes
through it.
```

### Day 9 — Kill switch and attack scenarios
**Goal:** freezing an agent after a red decision + two attack scenarios.
**Concepts:** Indirect prompt injection vs. insider threat.
```
Add to the chokepoint: when a "red" decision is made, update the Baseline to
status="frozen" via storage; every future request from a frozen agent is blocked
immediately without a semantic check. Create scenarios/injected_report.md — an innocent
report containing hidden text (in an HTML comment) instructing the agent to ignore its
instructions and access a sensitive file. Create scenarios/malicious_prompt.txt — an
explicitly malicious instruction that should be caught already at Pre-Flight. Create
scenarios/insider_prompt.txt — an instruction that sounds completely innocent
("summarize the quarterly reports") but contains, at the end, an attached request to
touch a classified file. This is the rogue-employee scenario: it should pass Pre-Flight
cleanly and only get blocked at the Chokepoint — exactly like the injection scenario,
through the same mechanism.
```
> **The point to highlight in the interview:** both scenarios — injection and rogue employee — are blocked by the same line of code, with the same `reason` in the log. This is the strongest demonstration of the source-agnosticism principle (section 2.1 in the foundation document).

### Day 10 — Integration and tests
**Goal:** end-to-end run, bug fixes, pytest.
```
Update demo/run_demo.py to run four scenarios in sequence and display the results: (1) an
overtly malicious prompt — caught at Pre-Flight; (2) normal work on clean_report.md —
green; (3) injected_report.md — red + freeze; (4) insider_prompt.txt — passes Pre-Flight,
blocked at the Chokepoint. Emphasize in the output that (3) and (4) were blocked through
the exact same mechanism despite a different source. Run it, fix errors, and add
tests/test_policy.py and tests/test_chokepoint.py.
```

---

## Week 3 — Calibration, presentation, and documentation

### Day 11 — Evaluation set and threshold calibration
**Goal:** turn "the threshold is an educated guess" into "the threshold is calibrated, here are the numbers." **This is the most important day for the interview.**
**Concepts:** Precision, recall, false positive/negative, evaluation set.
```
Create eval/eval_set.json with about 20 manually labeled requests (tool_name, args,
expected_tier), covering all classification levels and all three tiers. Implement
eval/run_eval.py that runs all of them through the chokepoint, compares against the
expected label, and prints a confusion matrix along with precision and recall for red
detection. Add an option to run with several different threshold values to see how the
numbers change.
```
> After running: **manually update config/thresholds.json** to the values that gave the best result, and document which values you tried and why you chose them. This is the material you'll present in the interview.

### Day 12 — Clean demo output
```
Improve demo/run_demo.py: clear, colored terminal output (green/yellow/red), showing the
reason and triggered_by for every decision, and a summary line with a count per tier.
```

### Day 13 — Recording the demo
**Manual task.** A 30-60 second GIF or video showing the three scenarios. This is what goes into LinkedIn and the repo.

### Day 14 — Documentation
```
Create docs/known_limitations.md based on section 11 in docs/concept.md. Write a full
README.md: the problem, the solution, the architecture diagram, how to run the demo and
the eval, calibration results, links to concept.md and known_limitations.md, and a
roadmap summary.
```

### Day 15 — Cleanup and publishing
Code cleanup, removing keys from the repo (`.env` in `.gitignore`), push to a public GitHub repo.

---

## Week 4 — Resume, LinkedIn, interview

### Day 16 — LinkedIn post
Structure: hook → the problem → the demo (GIF) → honesty about limitations → link to the repo.

### Day 17 — Interview prep
A private document with answers to: why embedding and not rules · what if the attacker controls the self-reported intent (you have a strong answer — the request is derived from the action) · how is this different from RBAC · how did you calibrate the threshold · how would you scale this · what would you do differently.

### Day 18 — A scenario designed to fail (optional)
If there's time: add a scenario that explicitly demonstrates the system's limits (e.g. gradual escalation that slips under the radar), and document it in known_limitations. Show where the system breaks harder than claiming it doesn't break.

### Day 19 — Rehearsal
Practice explaining the project out loud, polish the resume bullet points.

### Day 20 — Buffer day
Wrap-up, final publishing, one last review of the repo.

---
*If a day takes more than 4 hours — days 18 and 20 are the buffer. Don't push new features at the expense of calibration and documentation.*
