# ru-blocked-cleaned monthly automation

## Safety baseline

The manually validated 2026-08-27 result is frozen and never overwritten:

- `baselines/manual-2026-08-27/ru-blocked-cleaned-15759.txt`
- `baselines/manual-2026-08-27/confirmed-nxdomain-6230.txt`

The workflow verifies their line counts and Git blob hashes before every run.

The mutable NXDOMAIN database used by FAST mode is separate:

- `generated/automation/nxdomain/confirmed-current.txt`

It starts as an exact copy of the manual 6,230 list and may only be replaced by an explicitly requested successful FULL run (`update_nxdomain_db=true`).

## Run isolation

Every Stage 1 run uses a fixed `RUN_ID` determined before processing starts, for example:

`2026-09-01_230000Z`

Everything for that run stays under:

`runs/<RUN_ID>/`

Crossing midnight does not change the run folder. `state.json`, `.steps/`, logs and intermediate lists support resume after failure.

## Stage 1 — build cleaned candidate

Workflow: `Monthly ru-blocked orchestrator`

Choose `stage1` and:

- `nxdomain_mode=fast` — normal monthly update. Download/filter the fresh upstream list and immediately exclude hostnames present in `confirmed-current.txt`.
- `nxdomain_mode=full` — periodic deep audit. Uses `check_hostnames.py`, two lower-load `recheck_uncertain.py` passes and strict authoritative `confirm_nxdomain.py` confirmation. Only confirmed NXDOMAIN is removed; uncertain/inconsistent names remain in the candidate.
- `update_nxdomain_db=true` — FULL only; promote that successful FULL result to the mutable current NXDOMAIN database.
- `resume=true` with the same `run_id` — continue an interrupted run from saved step/checkpoint state.
- `debug=true` — verbose workflow diagnostics and state/file snapshot.

Suffixes are not hard-coded. Edit:

`config/ru-blocked-suffixes.txt`

Matching is on DNS label boundaries. Add future suffixes one per line.

Stage 1 output:

`runs/<RUN_ID>/04_final/ru-blocked-cleaned.txt`

The run also contains source, filtered input, checks, logs and comparison against the frozen manual 15,759 baseline.

## Stage 2 — build client artifacts

Run the same workflow with `stage2` and the successful Stage 1 `run_id` (or leave it blank to use `generated/automation/latest-stage1-run.txt`).

Stage 2 builds under:

`runs/<RUN_ID>/06_clients/`

It creates:

- Shadowrocket `ru-blocked-cleaned.list` with exact `DOMAIN,<hostname>` rules;
- a full Runet Freedom `geosite.dat` with all upstream categories preserved plus `RU-BLOCKED-CLEANED` as exact FULL rules.

By default Stage 2 does **not** replace live client files.

Only with `publish_clients=true` are validated artifacts copied to the stable paths used by clients:

- Shadowrocket: `generated/clients/ru-blocked-cleaned/ru-blocked-cleaned.list`
- Happ: `generated/clients/ru-blocked-cleaned/geosite.dat`

Permanent client URLs therefore do not change.

Routing semantics:

- `ru-blocked-cleaned` → **PROXY**
- generic Russian / `category-ru` / bank rules → **DIRECT**
- in Shadowrocket the `ru-blocked-cleaned` RULE-SET must remain above generic `.ru → DIRECT` because rules are first-match.
