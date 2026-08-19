# Security Findings — AFE Development Log

Short, dated writeups of security issues found (and fixed) in AFE's own code
during development. This file will grow if further findings turn up before
the project ships.

## Path traversal in resource classification (found and fixed during Day 9)

**Trigger:** while discussing the July 2026 OpenAI/Hugging Face sandbox-escape
incident (an AI agent exploited a gap between what a permission check validated
and what its underlying action actually reached), I re-examined AFE's own
path-matching logic for the same class of gap.

**The vulnerability:** `_is_under_folder`'s prefix check
(`path.startswith(folder + "/")`) operated on the raw path string. A request for
`"reports/../finance/payroll.csv"` matched the `/reports` folder (INTERNAL) as a
string prefix — but the OS, when the file is actually opened, resolves `..` and
reaches the real file under `/finance` (SECRET). The classification check and the
actual filesystem access disagreed about what path was being touched.

**The fix:** `normalize_resource_path` now collapses `..`/`.` segments
(`posixpath.normpath`) before any comparison happens, so the string that gets
classified is the same one the OS would actually resolve to.

**Why this matters for the project's own thesis:** this is the same category of
bug — a validation step and an execution step disagreeing about what they're
each looking at — that this whole project exists to catch when an *agent's*
actions diverge from its *approved* task. Finding one inside AFE's own code is a
reminder that "checks I built are also code that can have bugs" — worth stating
plainly rather than glossing over.
