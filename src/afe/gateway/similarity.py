"""
Similarity — local semantic comparison.

Produces an embedding for a request description using AFE's local sentence-transformers
model (loaded once, no network call at runtime — docs/concept.md §2.3), and computes
cosine similarity between that embedding and a Baseline's task_embedding to score how
consistent the current request is with the task the agent was dispatched for.
"""
