"""
Store — Baseline persistence, two-tier.

Defines an abstract BaselineStore interface (get/save), a JSONFileStore implementation
(on-disk, persistent, readable), and a CachedStore that wraps any Store with an in-memory
dict cache so chokepoint lookups are fast without touching disk on every request. Per
docs/work_plan.md, CachedStore is a deliberate, documented substitute for Redis in this
POC — not a production caching layer.
"""
