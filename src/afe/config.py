"""
Central configuration for AFE.

Loads and exposes settings that must stay out of code so they can be recalibrated without
a code change (config-driven design, per docs/work_plan.md): paths to the signed policy
files (config/classification.json, config/thresholds.json), the HMAC secret key used to
sign/verify Baselines and policy files, the local embedding model name, and the storage
location for Baselines and the audit log.
"""
