# Frozen manual baseline — 2026-08-27

These files are immutable rollback/control artifacts from the manually validated ru-blocked-cleaned run.

- `ru-blocked-cleaned-15759.txt` — 15,759 hostnames kept after manual filtering and validation.
- `confirmed-nxdomain-6230.txt` — 6,230 hostnames strictly confirmed as NXDOMAIN during the manual run.

Rules:
- automation MUST NOT overwrite either file;
- FAST monthly runs may use the current confirmed-NXDOMAIN database, initially derived from this baseline;
- FULL runs may produce a newer confirmed-NXDOMAIN database, but this manual baseline remains untouched for rollback/audit;
- the manual cleaned baseline Git blob is `9844ca804ca003b111b72e38d7724d81ab766f49`;
- the manual NXDOMAIN baseline Git blob is `52ddc1ef0f419679d5cbd23563b04769925a1dc2`;
- the manually validated cleaned-list SHA256 is `1ed42c3c9a577c6ceb0cbc276e3a903033c08e8f43d66dbcf3c5a8583e2531c6`.
