# AFE — Glossary of Concepts

> A map of every concept that came up in conversation, grouped by topic, with a short explanation and why it's relevant to your project.

---

## 1. Security and access — the basics

**Authentication vs. Authorization**
Authentication = "who are you" (identification). Authorization = "what are you allowed to do" (permission). Most security systems stop here — they check permission and nothing more. AFE adds a third layer: not just "what's allowed," but "does this still match what you were asked to do."

**RBAC / ABAC**
Role-Based / Attribute-Based Access Control — classic permission models: RBAC by role ("an admin can do X"), ABAC by attributes ("someone in Finance during work hours can do X"). Both are static — set in advance, without checking real-time context. AFE is the layer above them.

**Zero Trust Architecture**
Principle: "never trust, always re-verify." Instead of granting broad access because someone is "inside," every request is checked on its own. This is exactly the idea behind AFE — it doesn't trust a permission granted once at agent creation, it re-validates every request.

**API Gateway**
An architectural pattern: a central layer that all traffic passes through before reaching its destination, enforcing policy there (permissions, rate, logs). AFE is essentially an API Gateway specific to AI agents.

**Chokepoint Pattern**
A mandatory passage point — every request *must* go through it, with no bypass route. This is what turns enforcement from a "recommendation" into a real block, provided there's no bypass path (hence your known-limitations note that this depends on real network enforcement).

**IAM**
Identity and Access Management — the general field of managing identities and permissions in an organization. RBAC/ABAC are part of it.

**DLP**
Data Loss Prevention — systems that detect and prevent leakage of sensitive information (e.g., blocking an email with an attached file containing credit card numbers). Mentioned in the context: "AFE doesn't replace classic DLP, it only covers the channel that passes through AI agents."

---

## 2. AI-specific threats

**Prompt Injection — direct vs. indirect**
Direct: the agent's original instruction is itself malicious. Indirect: the agent reads a document/email/page containing a hidden instruction that tries to "rewrite" its goal mid-task. The distinction is critical for you — direct is caught at Pre-Flight, indirect is only caught at the Chokepoint.

**Agentic AI / Tool Use**
An "agent" = an LLM given the ability to act in the world through tools (reading files, sending emails), not just answer with text. Tool Use / Function Calling is the technical mechanism that lets the LLM "request" a tool invocation, letting your program intercept the request before it executes.

**Agent Hijacking**
When an agent that started on a legitimate task gets hijacked mid-run (usually via indirect injection) and starts acting toward a different goal, while using the same valid permissions.

**Insider Threat**
A threat originating from a party with legitimate permissions (an employee) who abuses them. In your case — an employee who phrases a task for the agent that sounds innocent but includes a request for out-of-scope access.

**MITRE ATLAS**
A threat matrix dedicated to AI (the AI equivalent of MITRE ATT&CK, which is better known from classic IT security). Classifies attack techniques specific to machine learning systems. A name interviewers in the field recognize immediately.

**OWASP LLM Top 10 / GenAI Security Project**
A list of the top ten risks in LLM applications (including Prompt Injection at #1), published by OWASP — the organization that also publishes the classic web application security Top 10.

---

## 3. Cryptography and integrity

**HMAC**
Hash-based Message Authentication Code — a mechanism that produces a short "signature" over data, using a shared secret key. Its purpose is **not** to hide information (secrecy) but to prove it **hasn't changed** since it was signed (integrity). This is exactly what you do on the Baseline.

**Integrity vs. Secrecy**
Integrity = "the information hasn't changed." Secrecy = "the information is confidential." HMAC gives you the first, not the second. Classic interview question: "If the Baseline leaks, is that a problem?" — yes, but a different problem (information exposure) than "someone changed it without you knowing" (which is what HMAC prevents).

**Digital Signature**
Similar in concept to HMAC (proving integrity + identity), but uses an asymmetric key pair (public/private) instead of one shared key. HMAC is simpler and sufficient when the same party both signs and verifies (as in your case).

**JWT**
JSON Web Token — a standard format for a signed token, built from three parts (header.payload.signature). You didn't use it directly, but it's the most familiar example of "signed information that can be transmitted and verified" — the same idea as your signed Baseline, just in a standard format.

---

## 4. The semantic layer (ML)

**Embedding**
A representation of text as a vector of numbers (a list of tens/hundreds of numbers) that captures its *meaning*, not just its words. Two sentences similar in meaning get "close" vectors. This is the basis for all the semantic comparison in your system.

**Cosine Similarity**
A way to measure how "close" two vectors are — effectively the angle between them in space. A score of 1 = identical in meaning, 0 = completely unrelated. This is the calculation that decides whether a request is "similar enough" to the original task.

**Threshold Calibration**
The process of setting the numeric threshold (e.g. 0.75) above which something counts as "similar enough." This is **not** a mathematical constant — it's a parameter that needs to be checked empirically against real examples, exactly what you did on day 11 with the evaluation set.

**Precision / Recall**
Two metrics for measuring classification quality. Precision = out of everything you flagged "red," how many were actually problematic (how many false alarms). Recall = out of all the actually problematic requests, how many did you catch (how many did you miss). There's a trade-off between them — a stricter threshold raises precision and lowers recall.

**False Positive / False Negative**
False Positive = the system blocked an innocent request by mistake. False Negative = the system approved a problematic request by mistake. A False Negative is usually more dangerous (a threat got through), but too many False Positives kill user trust in the system — exactly the reasoning behind three tiers instead of a binary switch.

**Confusion Matrix**
A table showing how many correct/incorrect predictions of each type (True/False Positive/Negative) — the standard tool for presenting evaluation-set results.

**Evaluation Set**
A collection of manually labeled examples ("this request should come out green") used to measure the system's actual performance, not just to check that the code "runs."

---

## 5. System and product design

**Tiered Decision Making**
Graduated decision-making (green/yellow/red) instead of a binary allow/block switch. Spreads out risk and enables human review at edge cases, without blocking everything or approving everything.

**Fail-secure / Fail-closed**
Principle: when something is unclear or undefined, the system leans toward **blocking**, not approving. The opposite is fail-open — dangerous, because a system failure automatically becomes an approval.

**Risk-based Access Control**
An approach where the level of checking/threshold varies with the risk of the resource — not every request is checked to the same degree. In your case: the higher the classification, the stricter the threshold for approval.

**Data Classification / Sensitivity Labeling**
Tagging resources by sensitivity level (Public/Internal/Confidential/Secret). Exists in every large organization (e.g. Microsoft Purview) precisely to focus security effort on what actually matters.

**Audit Trail / Explainability**
Full documentation of every decision, including the *reason* for it (`triggered_by` in your system). This is what turns a system decision from a "black box" into something investigable.

**Config-driven Design**
Principle: parameters likely to change (thresholds, classification mappings) live in a config file, not hardcoded directly in code. This allows recalibration without touching the logic.

**Policy vs. Enforcement**
A separation between "what the decision is" (policy — whether to approve) and "how it's actually carried out" (enforcement — actual blocking, at the network level, etc.). This separation allows swapping the enforcement layer (e.g. from logical → real network) without touching the decision logic.

**Attribution (chain of responsibility)**
The ability to retroactively associate an action with its true source (e.g., the `dispatcher` that created the agent). Critical for post-incident investigation, even if not relevant to the enforcement decision itself.

**TTL (Time To Live)**
A duration after which a record (like a Baseline) is considered invalid. A roadmap idea: an agent running for many hours perhaps shouldn't keep operating under the same Baseline forever.

**Rate Limiting**
Limiting the number of requests allowed in a given time window. Mentioned as an additional possible protection layer: a maximum number of requests per minute for SECRET-level classification.

**Chained Hashing / Tamper-evident Log**
Every log entry also includes a hash of the previous entry, so a record in the middle can't be deleted/changed without breaking the entire chain that follows it — makes the log "tamper-evident," not just "recorded."

---

## 6. General software engineering concepts (came up discussing the language)

**Mocking / Test Doubles**
Creating a fake version of a component (e.g. a `read_file` that returns a fixed value instead of accessing real disk) for testing/demo purposes without depending on a real environment.

**Interface Abstraction**
Defining a general "contract" (e.g. `BaselineStore` with `get`/`save`) without committing to a specific implementation — so JSON can be swapped for SQL later without changing code that calls the interface.

**CPU-bound vs. I/O-bound**
CPU-bound = time is spent on computation (the processor is busy). I/O-bound = time is spent waiting on network/disk. This was the basis for my argument against C++: calls to an LLM/embedding API are I/O-bound, so a "faster" language doesn't actually improve performance.

**Bindings / FFI**
A mechanism that connects code between two languages (e.g. pybind11 between Python and C++), to call functions from one language in the other. A common source of hard-to-debug bugs, which is why I avoided recommending them.

**Redis**
A fast in-memory key-value store, commonly used in industry as a caching layer between an application and persistent storage. In your POC it's replaced by a simple in-memory dict, which fills the same role at a small scale.

**On-premise**
Running software/a model **inside** the organization's own infrastructure, as opposed to a Cloud API that runs at an external provider. The word "premise" means "the grounds/site" — i.e., "inside your own site," not someone else's.

**Egress (network egress)**
Network traffic leaving **outward** from the internal network to the internet. "Blocking egress" = preventing information from leaving — exactly the principle behind running the embedding locally in AFE.

**Attack Surface**
All the points through which a system can be attacked. Every external dependency (like a cloud API) is another point on that surface — fewer external dependencies = a smaller attack surface.

**Self-hosted Model**
An AI/ML model (e.g. an embedding model) that runs on your own hardware, not as a service from a provider. In AFE: sentence-transformers runs this way — the weights are downloaded once, and every subsequent use is fully local.

**Segregation of Duties**
A security principle: the party being controlled/overseen shouldn't also be the one who sets the rules that oversee it. In AFE: the agent can't touch the config (the rule that governs it) — two completely separate authorities, with no overlap.

**Out-of-band**
An action carried out through a channel entirely separate from the regular automated process. In AFE: a policy change (classification/threshold files) is done manually by a human who edits and re-signs, not through an API call or code running at runtime.

---
*Save this file as `docs/glossary.md` — when Claude Code sees it, it will also use these terms consistently throughout the project.*
