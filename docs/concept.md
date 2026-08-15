# Alpha-Flow Engine (AFE) — Project Foundation Document

> **Usage note:** This is the project's persistent context document. Save it in the repo as `docs/concept.md` so Claude Code sees it automatically in every session, without you needing to paste it again.

## One-line idea

An application-layer (Layer 7) security gate that sits between an AI agent and a sensitive resource, and checks not "is there permission" — but "does what the agent is trying to do right now still match what it was sent to do."

## 1. The Problem

Classic security tools check permissions at the network/identity level: does the agent have technical access to the resource? If yes — it passes. This check is blind to intent. Two scenarios illustrate the gap:

- **Insider threat** — an employee with valid permissions plants a hidden instruction in the original prompt. No mechanism raises an alert, because from a permissions standpoint everything is fine.
- **Indirect prompt injection** — an attacker plants hidden instructions in a file/email/page that the agent reads mid-task. The goal changes "under the radar," while using the same valid permissions.

## 2. The Solution: JIT Intent Validation

AFE is a mandatory chokepoint between the agent and every classified resource, that checks one thing: **is the current request still consistent with the task the agent was defined for when it was created?** Validation happens Just-In-Time, not only at creation time. In simple terms: checking that how the agent is acting now is how it "came in."

### 2.1 Core principle: agnostic to the threat's source

AFE doesn't try to identify who the attacker is or where the deviation came from. The only question it asks is: *why are you trying to access this resource, if it is classified and wasn't approved for you?* If the answer isn't consistent with the signed task — the request is stopped, whether the source is an injection in a file the agent read, or a rogue employee who planted it in the prompt from the start.

This isn't a phrasing convenience but a result of the architecture: because the comparison is between the **actual action** and the **signed task**, the two attack vectors converge to the same signature — deviation from the task. From this follow two implications:

- No need for a signature database or a model of "what an attacker looks like" — unlike signature-based or anomaly-based detection.
- Attack techniques not yet invented are caught by the same mechanism, as long as they produce a deviation from the task.

**Important caveat:** the source doesn't matter for **enforcement**, but is critical for **response**. After a block, the organization needs to know whether it's a poisoned document (clean it up) or an employee (internal investigation). That's why the Baseline stores `dispatcher` and every decision is recorded in the audit trail — the chain of attribution is preserved for the post-incident investigation.

### 2.2 Boundaries of protection — what AFE does not cover

AFE protects only the channel that passes through AI agents. An employee who accesses files directly, outside the agent, doesn't touch the system at all — that's the job of classic DLP and IAM systems. Precisely stated: AFE is not a general-purpose insider-espionage detection tool, but prevents the use of an AI agent as a proxy for unauthorized access.

### 2.3 Core principle: AFE does not leave the internal network

AFE is a tool whose purpose is to protect sensitive information — so it must not itself become a leak path. If the semantic comparison layer sends request descriptions (file name, task content) to an external cloud embedding service, AFE itself becomes a point of exposure — the classic irony of a protection tool that is itself the breach.

Therefore: **AFE's decision engine (embedding + comparison) runs locally (on-premise), with no outbound network calls to third-party services.** This also guarantees there's no external dependency that can be attacked, throttled (provider rate limiting), or go down (outage) and silence the gate.

**In the POC:** the embedding is produced by a small open-source model that runs locally (e.g. sentence-transformers) — no API key, no network call at runtime. This also removes the external I/O layer from the comparison itself, making it local and fast.

**What stays outside this boundary, and why that's fine:** the agent's "brain" (the LLM that runs tool use) is a system separate from AFE — AFE only intercepts tool calls, it doesn't matter where the agent's LLM runs. In a production deployment inside a closed organization, the agents themselves would also run on an internal LLM — but that's a separate project. In the POC, the demo agent (the harness, not AFE) may still use an external LLM API for demonstration purposes only — documented as a demo simplification, not part of AFE's design.

### 2.4 Core principle: the rules themselves are locked too, not just the badge

The HMAC on the Baseline protects a single agent's "entry badge." But there's another asset that needs separate protection: **the policy itself** — the classification map and the threshold files. If they can be edited at runtime, a SECRET resource can be downgraded to PUBLIC and the entire system bypassed without ever touching the Baseline.

**Principle:** the policy files (`classification.json`, `thresholds.json`) are HMAC-signed exactly like the Baseline, and kept read-only on the filesystem. No code — not the agent, not AFE itself, not even the LLM that runs Pre-Flight — writes to them at runtime. A policy change is a manual, out-of-band action: a human edits, re-signs, and only then does AFE load it. An invalid signature = AFE refuses to start (fail-secure).

This is effectively **segregation of duties**: the controlled party (the agent) cannot touch the rule that governs it. This principle is also familiar in the broader context of AI system safety — a system under oversight shouldn't be able to modify the oversight mechanism over itself.

## 3. Architecture — three stages

1. **Pre-Flight & Baseline** — when an agent is created, the prompt is scanned for malicious intent. If clean, a Baseline is created (see schema in section 4), cryptographically signed (HMAC), and stored.
2. **Free operation** — the agent runs. Files/emails/pages it reads may contain text trying to "rewrite" its goal.
3. **JIT Chokepoint** — when the agent requests access to a resource, the request passes through AFE, which compares it against the signed Baseline and decides within milliseconds.

## 4. Baseline schema (JSON file per agent)

| Field | Description |
|---|---|
| `agent_id` | Unique agent identifier ("ID card") |
| `dispatcher` | Who created/dispatched the agent |
| `task` | Text description of the task |
| `task_embedding` | Semantic representation of the task |
| `commands` | Tools authorized for the agent |
| `allowed_resources` | Resources pre-approved in Pre-Flight |
| `created_at` | Timestamp |
| `status` | `active` / `frozen` |
| `signature` | HMAC signature over all fields above |

The signature guarantees **integrity**, not secrecy — the Baseline can't be modified without the system detecting it.

## 5. Resource Classification

Not every resource warrants a full semantic check. Every resource has a **classification level**, and that level determines how strict the check will be.

### 5.1 Classification scale

| Level | Example | Handling at Chokepoint |
|---|---|---|
| `PUBLIC` | Open documentation | Always passes, no check |
| `INTERNAL` | Regular reports | Passes, logged only |
| `CONFIDENTIAL` | Source code, contracts | Triggers the full semantic engine |
| `SECRET` | Payroll, keys, confidential financials | Requires explicit match in `allowed_resources` — semantic similarity alone isn't enough |

### 5.2 Inheritance with override

A folder defines a default classification for everything inside it, and an individual file can override it. This way you don't need to manually tag every file, but you can still flag a sensitive file inside a normal folder.

- **Upward override** (file classified higher than its folder) — allowed automatically.
- **Downward override** (file classified lower than its folder) — requires explicit marking in config, and is logged.
- **Resource with no classification at all** — treated as `CONFIDENTIAL`, not `PUBLIC`. This is the **fail-secure** principle: when something is undefined, the system closes, not opens.

### 5.3 Classification affects the threshold, not just "whether to check"

The higher the classification, the higher the semantic similarity required for a green approval. Thresholds are kept in config, not in code:

| Classification | Threshold for green (example — to calibrate) |
|---|---|
| `INTERNAL` | 0.55 |
| `CONFIDENTIAL` | 0.75 |
| `SECRET` | Requires explicit allowlist |

This is risk-based access control: the exact same request can come out green on an INTERNAL resource and red on a SECRET one.

## 6. The three-tier decision engine

Not a binary allow/block (which causes false positives and effectively gets the system turned off), but three levels:

| Level | When triggered | Action |
|---|---|---|
| **1 — Green** | Resource is in `allowed_resources`, or similarity is above the threshold for its classification level | Immediate approval |
| **2 — Yellow** | Medium similarity — close to the task but not conclusive | Approval + logging + async human review |
| **3 — Red** | Low similarity, or an attempt to access `SECRET` without an allowlist entry | Block, freeze the agent, alert |

**Kill switch:** the moment a red decision is made, the Baseline is marked `status=frozen`, and every subsequent request from that agent is automatically blocked without further semantic checking.

## 7. Request description — derived from the action, not self-reporting

A critical architectural point: the description that enters the semantic comparison is built from the **actual tool call** (tool name + arguments + resource), not from text where the agent reports its own intent. If the agent reported its own intent, an attacker who injected instructions into it could phrase a report that sounds aligned while the real target is different — meaning the check would rely on a source that was itself compromised.

If a reported `current_intent` is still collected, it's stored in the log **as evidence only**, and does not enter the decision computation.

## 8. Audit Trail

Every decision is recorded as a JSONL line with: `agent_id`, `timestamp`, `resource`, `classification`, `similarity_score`, `tier`, `reason`, and `triggered_by` (which check decided — classification, allowlist, or semantics). This last field is what makes the decision explainable rather than a "black box."

## 9. Current POC scope

**Yes, within the coming month:**
- A single agent with LLM + tool calling, against mock tools
- Pre-Flight, Baseline, embedding, HMAC signing
- Tiered resource classification with inheritance, override, and fail-secure
- Chokepoint with three tiers and classification-dependent thresholds
- Kill switch (agent freeze)
- Audit trail in JSONL
- At least one indirect-injection scenario correctly caught
- A labeled evaluation set for threshold calibration + precision/recall measurement
- README, diagrams, recorded demo
- **Python as the sole implementation language**
- **Two-tier storage**: JSON files on disk + an in-memory cache that fills Redis's role

**Explicitly not in this scope (so Claude Code doesn't "sprawl"):**
- Real network enforcement (today the mechanism is logical only)
- Production-grade key management (KMS)
- Multi-tenant / multiple concurrent agents
- A dashboard for the yellow-tier human review — logging is enough
- Integration with real MCP servers
- Real Redis (the in-memory cache is a deliberate, documented substitute)
- C++/Java (see rationale in the work plan)

## 10. Future roadmap

- **Real network enforcement** — a reverse proxy in front of real MCP servers, not just internal logic
- **Tamper-evident log** — chained signing: every decision signs the hash of the previous one, so deleting a line breaks the chain
- **TTL for the Baseline** — an agent running for many hours perhaps shouldn't keep operating under the same Baseline forever
- **Rate limiting by classification** — an additional signal beyond semantics
- **Splitting the task into multiple embeddings** — a complex task isn't well represented by a single vector
- Moving to a **real Redis** (needed once there's more than one process, or persistence across runs)
- Production-grade key management, multi-tenant, a dashboard for human review
- Detecting behavioral drift over time, not just per-request
- An enforcement component in a fast language (C++/Rust/Go) if critical latency is ever required
- **A local LLM for the agent's brain itself too** (not just for AFE) — to fully close off the network, not only at the decision layer
- **A formal policy-management process** — policy-as-code with code review and multiple signatures, instead of a single manual edit

## 11. Known limitations (to know, not hide in an interview)

- **The threshold is a calibrated parameter, not an absolute truth** — it's calibrated on a small evaluation set (~20 cases), which isn't representative of real production.
- **Semantic checking is inherently probabilistic** — the deterministic checks (allowlist, classification, fail-secure) are the genuinely strong ones; semantics is an additional layer, not the only one.
- **"Cannot be bypassed" is only true with real network enforcement** — today that's an assumption that hasn't been implemented.
- **Manual classification doesn't scale** — in production, automatic tagging or integration with an existing DLP system would be needed.
- **The log is not tamper-evident** — anyone with disk write access can edit it; chained signing is on the roadmap.
- **The demo agent (harness) uses an external LLM API for the demo** — AFE itself is closed off from the internal network (local embedding), but this doesn't reflect a full deployment where the agent's "brain" is internal too.
- **Policy locking (read-only + signature) is at the level of a single file** — not a real organizational change-management process (code review, multiple approvals, Git history).
- **Baseline updates are not atomic** — the read → decide → write sequence behind the
  kill switch is three separate operations; Python's GIL protects each one individually,
  not the sequence as a whole, so two near-simultaneous requests for the same agent could
  race (a TOCTOU condition) and overwrite a freeze. Not handled in the POC (single agent,
  no concurrent requests); a production fix would use per-agent locking, optimistic
  concurrency (a version field), or a store backend with real transactions.
- - **The demo agent (harness) and Pre-Flight's malicious-intent check both use an
  external LLM API for the demo** — only the Chokepoint's embedding + cosine-similarity
  decision engine (§2.3) is required to run fully local. Pre-Flight needs nuanced
  judgment about disguised intent that a small local model can't reliably provide,
  unlike the Chokepoint's mechanical similarity comparison. A production deployment
  would run all three — harness, Pre-Flight, and the local engine — fully internal.
- - **`read_file` has no path restriction today** — it will open any path on disk, including
  files outside `scenarios/`. Nothing currently prevents an injected instruction from
  reading real secrets (e.g., `.env`) before the Chokepoint (day 8/9) is wired in to
  intercept the call. This is exactly the gap the Chokepoint closes at the application
  layer; container-level filesystem restrictions (see roadmap) would close it
  independently at the OS layer.
## 12. Key concepts

Zero Trust · API Gateway / chokepoint · Prompt Injection (direct/indirect) · Agentic AI / Tool Use · HMAC (integrity vs. secrecy) · JWT · Embeddings · Cosine Similarity · Threshold Calibration · Precision/Recall · False Positive/Negative · Tiered Decision Making · Data Classification / Sensitivity Labeling · Fail-secure · Risk-based Access Control · Audit Trail · MITRE ATLAS · OWASP LLM Top 10

---
*This document describes the concept and the POC scope. Day-to-day execution detail is in the "Monthly Work Plan" document.*
