"""
Baseline model — an agent's signed "ID card".

Defines the Baseline (pydantic model) per the schema in docs/concept.md §4: agent_id,
dispatcher, task, task_embedding, commands, allowed_resources, created_at, status
("active"/"frozen"), and signature. task_embedding is produced by AFE's local embedding
model (sentence-transformers), never an external API. Every JIT request at the chokepoint
is ultimately compared against a stored Baseline.
"""
