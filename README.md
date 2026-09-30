# OT Configuration Drift Lab

A small, reproducible Python research repository for detecting changes between
an **approved OT configuration baseline** and an **independently collected,
read-only observation**. It produces structured evidence and checks whether a
change matches an approved maintenance ticket. It does not connect to PLCs or
send Modbus commands.

The original demonstration used `baseline.copy()`, which aliases nested JSON
objects and can hide a change. This repository reads two separate snapshots and
compares nested values without mutating either one.

## Quick start

Requires Python 3.9 or newer. No package installation or network access is
needed for the examples.

```bash
python3 check_drift.py \
  --baseline configs/baseline.json \
  --observed examples/observed-auth-disabled.json \
  --policy configs/policy.json \
  --approvals examples/approvals-empty.json \
  --json
```

This example reports `/security_controls/gateway_auth_enabled` changing from
`true` to `false` and exits with code `2`. Run it with
`examples/observed-clean.json` to see an unchanged snapshot, or with
`examples/approvals-maintenance.json` to see an `approval_match` classification.
The latter is retained in the findings; it is never silently dropped.
All checked-in snapshots and tickets are synthetic fixtures; their `source`
values do not claim that a live device was measured.

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

The optional `--max-age-seconds 300` rejects an observation older than five
minutes. The checked-in examples have fixed historical timestamps, so omit
this option when replaying them.

Exit codes: `0` = no change or all changes match an approval; `2` = at least
one unapproved change; `3` = invalid, mismatched, or stale input. A tool that
calls this CLI should inspect the JSON `status` and `findings` even when the
exit code is `0`.

## Input contract

- `configs/baseline.json`: `schema_version`, `baseline_id`, `asset_id`,
  `captured_at`, `source`, and nested `config`.
- Observed snapshot: `schema_version`, matching `asset_id`, `observed_at`,
  `source`, and independently collected `config`.
- `configs/policy.json`: ordered, exact JSON Pointer rules. The first rule
  whose path and optional `when_after` value match supplies severity and
  rationale. Unknown paths use `default_severity`.
- Approvals: each ticket has an exact asset, path, before/after values,
  approval status, and UTC validity window. For key additions or removals,
  set `before_present` or `after_present` to `false` in the ticket.

All timestamps need a timezone offset. JSON duplicate keys and nonstandard
`NaN`/`Infinity` values are rejected. Arrays are compared as whole values in
this first version; order is significant. Added or removed objects are expanded
to leaf changes so a missing parent cannot hide a field-level rule. Changing an
object into another type also reports its removed leaves. Results use JSON Pointer paths and
include a SHA-256 digest of each canonicalized configuration for replay and
comparison. The digest is **not** a signature or proof that a device supplied
the snapshot.

`approval_match` means that a ticket matches the observed values and was
valid **at observation time**. Without an authenticated change event, it
cannot establish when or by whom the configuration was changed. Similarly,
`source` is recorded metadata, not independently verified provenance.

## What the example setting means

The sample models a **gateway authentication control** protecting access to a
traditional Modbus/TCP service on port 502. Port 502 itself does not add
protocol-native authentication. [Modbus Security](https://www.modbus.org/modbus-specifications)
is a separate TLS/certificate-based protocol, normally on port 802. A real
collector and policy must describe which device or gateway owns each control.
The alert states a policy deviation and a potential risk; it does not claim
that unauthorized commands or a process impact occurred.

## Research progression

1. **Configuration evidence:** add read-only vendor/export adapters, signed
   baselines, device-specific normalization, field visibility, and explicit
   collection failures. Keep credentials and other secrets out of snapshots.
2. **Change context:** ingest authenticated change events, maintenance tickets,
   asset roles, and baseline validity windows. Evaluate authorized changes,
   rollback, and stale or missing observations separately.
3. **Cross-layer analysis:** attach passive protocol events, host/PLC provenance,
   and process time series to the same asset and time window. A process model
   can support impact analysis without suppressing a configuration-only alert.
4. **Evaluation:** collect paired snapshots and ground-truth changes on an
   authorized isolated testbed; compare config-only, process-only, and fusion
   variants using event-level metrics and held-out devices/versions.

See the detailed [research plan](docs/research-plan.md) and
[dataset notes](docs/datasets.md). The public Sherlock and ProvICS datasets
are useful for network, provenance, and process submodules, but they do not
provide approved configuration snapshots and tickets for direct drift labels.
No third-party datasets are included in this repository.

This is an offline research prototype. Before use on operational equipment,
validate collector safety, baseline custody, secrets handling, clock quality,
vendor-specific semantics, and performance in a representative lab.
