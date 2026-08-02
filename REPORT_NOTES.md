## Scope and methodology

This platform was built around a single architectural decision: every
pipeline stage tries the real forensic tool first, and falls back to
realistic sample data only when that tool or its input is unavailable —
the interface between stages is fixed regardless of which path executes.
This means the full pipeline is always demonstrable end-to-end, and each
stage can be upgraded independently without touching the rest of the
system.

Stages validated against real data: Volatility3 (`pstree`, `netscan`,
`malfind`) run against a live-captured RAM image of the development
machine; the MemMal-D2024 and CICIDS2017 classifiers; heuristic malware
triage; and the LLM analysis layer, which reads the aggregated results of
the above and drafts the report's analysis section via a live API call.

Stages still running on sample data: Ghidra decompilation (requires a
local Ghidra install and `GHIDRA_HOME`, not configured in this
environment) and Autopsy (not integrated — out of scope for this
iteration). Registry parsing is implemented and tested against `regipy`'s
hive-parsing API but not validated against a hive extracted from the
captured image.

The UI distinguishes live from sample results on every screen, so this
boundary is never hidden from the person reviewing it.