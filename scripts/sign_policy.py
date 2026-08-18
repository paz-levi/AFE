"""
sign_policy.py — sign a plain JSON policy file and lock it read-only.

Standalone, manual script for a human security admin to run — deliberately NOT imported
by anything under src/afe/. Per docs/concept.md §2.4, a policy change (classification.json,
thresholds.json) is a manual, out-of-band action: a human edits the plain JSON, runs this
script to re-sign and re-lock it, and only then does AFE load it. No code under src/afe/
writes to a policy file at runtime.

Usage:
    python scripts/sign_policy.py <path-to-policy.json>

Reads the plain JSON at `path`, computes its canonical signature (the same
json.dumps(..., sort_keys=True) pattern signing.py's Baseline signing uses), and
overwrites the file with {"policy": <original content>, "signature": "<hex>"}, then
removes write permission from the file (os.chmod with stat.S_IREAD).
"""

from __future__ import annotations

import argparse
import json
import os
import stat

from afe.baseline.signing import sign_bytes
from afe.config import get_hmac_secret


def sign_policy_file(path: str) -> None:
    """Read the plain JSON policy at `path`, sign it, overwrite it with the signed
    envelope, and lock it read-only. Idempotent: safe to run again on an already-signed
    file (the human unlock -> edit -> re-sign workflow, docs/concept.md §2.4), whether
    or not the content was actually edited in between."""
    with open(path, encoding="utf-8") as f:
        loaded = json.load(f)

    if isinstance(loaded, dict) and set(loaded.keys()) == {"policy", "signature"}:
        # Already a signed envelope from a prior run — unwrap it so re-running this
        # script re-signs the actual policy content, not a nested copy of the old
        # envelope.
        content = loaded["policy"]
    else:
        content = loaded

    canonical = json.dumps(content, sort_keys=True).encode("utf-8")
    signature = sign_bytes(canonical, get_hmac_secret())
    payload = {"policy": content, "signature": signature}

    # In case the file was already locked read-only by a prior run, make it writable
    # again before overwriting — supports the human unlock -> edit -> re-sign flow.
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    os.chmod(path, stat.S_IREAD)
    print(f"Signed and locked {path} (read-only).")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sign a plain JSON policy file and lock it read-only."
    )
    parser.add_argument("path", help="Path to the plain JSON policy file to sign.")
    args = parser.parse_args()
    sign_policy_file(args.path)


if __name__ == "__main__":
    main()
