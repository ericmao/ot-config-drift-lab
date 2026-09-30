"""Pure comparison and validation logic for configuration snapshots.

This module never connects to a controller. A collector must supply an
independently obtained, read-only observation before analysis can begin.
"""

from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class InputError(ValueError):
    """An input cannot be used as trustworthy comparison evidence."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InputError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise InputError(f"non-JSON numeric constant: {value}")


def load_json_document(path: str | Path) -> dict[str, Any]:
    """Load strict JSON; duplicate keys and NaN/Infinity are errors."""
    source = Path(path)
    try:
        document = json.loads(
            source.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise InputError(f"cannot read {source}: {exc}") from exc
    if not isinstance(document, dict):
        raise InputError(f"{source}: top-level JSON value must be an object")
    return document


def _canonical(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def _same(left: Any, right: Any) -> bool:
    # Python considers True == 1, but JSON boolean and number have different meaning.
    return _canonical(left) == _canonical(right)


def _timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise InputError(f"{field} must be an ISO 8601 string with a UTC offset")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InputError(f"{field} is not a valid ISO 8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise InputError(f"{field} must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _nonempty_string(document: dict[str, Any], key: str, label: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value.strip():
        raise InputError(f"{label}.{key} must be a nonempty string")
    return value


def _validate_snapshot(document: dict[str, Any], *, baseline: bool) -> datetime:
    label = "baseline" if baseline else "observed"
    if type(document.get("schema_version")) is not int or document["schema_version"] != 1:
        raise InputError(f"{label}.schema_version must be 1")
    _nonempty_string(document, "asset_id", label)
    _nonempty_string(document, "source", label)
    if not isinstance(document.get("config"), dict):
        raise InputError(f"{label}.config must be an object")
    field = "captured_at" if baseline else "observed_at"
    return _timestamp(document.get(field), f"{label}.{field}")


def _validate_policy(document: dict[str, Any]) -> None:
    if type(document.get("schema_version")) is not int or document["schema_version"] != 1:
        raise InputError("policy.schema_version must be 1")
    severities = {"critical", "high", "medium", "low", "info"}
    if not isinstance(document.get("default_severity"), str) or document["default_severity"] not in severities:
        raise InputError("policy.default_severity is invalid")
    rules = document.get("rules")
    if not isinstance(rules, list):
        raise InputError("policy.rules must be an array")
    identifiers: set[str] = set()
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise InputError(f"policy.rules[{index}] must be an object")
        rule_id = _nonempty_string(rule, "id", f"policy.rules[{index}]")
        if rule_id in identifiers:
            raise InputError(f"duplicate policy rule id: {rule_id}")
        identifiers.add(rule_id)
        _nonempty_string(rule, "path", f"policy.rules[{index}]")
        if not rule["path"].startswith("/"):
            raise InputError(f"policy rule {rule_id} path must be a JSON Pointer")
        if not isinstance(rule.get("severity"), str) or rule["severity"] not in severities:
            raise InputError(f"policy rule {rule_id} has invalid severity")
        _nonempty_string(rule, "title", f"policy.rules[{index}]")
        _nonempty_string(rule, "rationale", f"policy.rules[{index}]")
        if not isinstance(rule.get("references", []), list) or not all(
            isinstance(item, str) for item in rule.get("references", [])
        ):
            raise InputError(f"policy rule {rule_id} references must be strings")


def _validate_approvals(document: dict[str, Any]) -> None:
    if type(document.get("schema_version")) is not int or document["schema_version"] != 1:
        raise InputError("approvals.schema_version must be 1")
    changes = document.get("changes")
    if not isinstance(changes, list):
        raise InputError("approvals.changes must be an array")
    for index, change in enumerate(changes):
        label = f"approvals.changes[{index}]"
        if not isinstance(change, dict):
            raise InputError(f"{label} must be an object")
        for field in ("ticket_id", "asset_id", "path"):
            _nonempty_string(change, field, label)
        if not change["path"].startswith("/"):
            raise InputError(f"{label}.path must be a JSON Pointer")
        for field in ("before", "after"):
            if field not in change:
                raise InputError(f"{label}.{field} is required")
        for field in ("before_present", "after_present"):
            if field in change and not isinstance(change[field], bool):
                raise InputError(f"{label}.{field} must be a boolean")
        if not isinstance(change.get("status"), str) or change["status"] not in {"approved", "pending", "rejected"}:
            raise InputError(f"{label}.status is invalid")
        start = _timestamp(change.get("valid_from"), f"{label}.valid_from")
        end = _timestamp(change.get("valid_until"), f"{label}.valid_until")
        if end < start:
            raise InputError(f"{label}.valid_until precedes valid_from")


def _pointer_segment(key: str) -> str:
    return key.replace("~", "~0").replace("/", "~1")


def compare_configs(expected: dict[str, Any], actual: dict[str, Any]) -> list[dict[str, Any]]:
    """Return typed JSON Pointer changes without mutating either input."""
    findings: list[dict[str, Any]] = []

    def emit_branch(value: Any, path: str, *, added: bool) -> None:
        # Preserve leaf paths even if a whole parent object disappears. This
        # keeps field-specific policy checks visible for subtree removal.
        if isinstance(value, dict) and value:
            for key in sorted(value):
                emit_branch(value[key], f"{path}/{_pointer_segment(key)}", added=added)
            return
        findings.append({
            "path": path,
            "change_type": "added" if added else "removed",
            "before_present": not added,
            "after_present": added,
            "before": None if added else value,
            "after": value if added else None,
        })

    def walk(before: Any, after: Any, path: str) -> None:
        if isinstance(before, dict) and isinstance(after, dict):
            for key in sorted(before.keys() | after.keys()):
                child = f"{path}/{_pointer_segment(key)}"
                if key not in before:
                    emit_branch(after[key], child, added=True)
                elif key not in after:
                    emit_branch(before[key], child, added=False)
                else:
                    walk(before[key], after[key], child)
        elif isinstance(before, dict) and not isinstance(after, dict):
            if before:
                emit_branch(before, path, added=False)
            findings.append({
                "path": path, "change_type": "type_changed", "before_present": True,
                "after_present": True, "before": before, "after": after,
            })
        elif isinstance(after, dict) and not isinstance(before, dict):
            if after:
                emit_branch(after, path, added=True)
            findings.append({
                "path": path, "change_type": "type_changed", "before_present": True,
                "after_present": True, "before": before, "after": after,
            })
        elif not _same(before, after):
            findings.append({
                "path": path, "change_type": "modified", "before_present": True,
                "after_present": True, "before": before, "after": after,
            })

    walk(expected, actual, "")
    return findings


def _matching_rule(change: dict[str, Any], rules: list[dict[str, Any]]) -> dict[str, Any] | None:
    for rule in rules:
        if rule["path"] != change["path"]:
            continue
        if "when_after" in rule and (
            not change["after_present"] or not _same(rule["when_after"], change["after"])
        ):
            continue
        return rule
    return None


def _matching_ticket(
    change: dict[str, Any], asset_id: str, observed_at: datetime, tickets: list[dict[str, Any]]
) -> str | None:
    matches: list[str] = []
    for ticket in tickets:
        if ticket["status"] != "approved" or ticket["asset_id"] != asset_id:
            continue
        if ticket["path"] != change["path"]:
            continue
        if ticket.get("before_present", True) != change["before_present"]:
            continue
        if ticket.get("after_present", True) != change["after_present"]:
            continue
        if change["before_present"] and not _same(ticket["before"], change["before"]):
            continue
        if change["after_present"] and not _same(ticket["after"], change["after"]):
            continue
        if not (
            _timestamp(ticket["valid_from"], "ticket.valid_from")
            <= observed_at
            <= _timestamp(ticket["valid_until"], "ticket.valid_until")
        ):
            continue
        matches.append(ticket["ticket_id"])
    if len(matches) > 1:
        raise InputError(f"multiple approval tickets match {change['path']}: {matches}")
    return matches[0] if matches else None


def analyze(
    baseline: dict[str, Any],
    observed: dict[str, Any],
    policy: dict[str, Any],
    approvals: dict[str, Any] | None = None,
    *,
    max_age_seconds: float | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Compare independent snapshots, preserving evidence and approval context.

    An approval match is only a matching ticket at observation time. Without an
    authenticated change event, it does not prove when or by whom a change was made.
    """
    baseline_time = _validate_snapshot(baseline, baseline=True)
    observed_time = _validate_snapshot(observed, baseline=False)
    _validate_policy(policy)
    if approvals is None:
        approvals = {"schema_version": 1, "changes": []}
    _validate_approvals(approvals)
    if baseline["asset_id"] != observed["asset_id"]:
        raise InputError("baseline and observed asset_id do not match")
    if observed_time < baseline_time:
        raise InputError("observed snapshot predates baseline capture")
    if max_age_seconds is not None:
        if not math.isfinite(max_age_seconds) or max_age_seconds < 0:
            raise InputError("max_age_seconds must be a finite nonnegative number")
        clock = now or datetime.now(timezone.utc)
        if clock.tzinfo is None or clock.utcoffset() is None:
            raise InputError("now must include a UTC offset")
        age = (clock.astimezone(timezone.utc) - observed_time).total_seconds()
        if age < 0 or age > max_age_seconds:
            raise InputError(f"observed snapshot is outside maximum age: {age:.1f}s")

    changes = compare_configs(baseline["config"], observed["config"])
    findings: list[dict[str, Any]] = []
    for change in changes:
        rule = _matching_rule(change, policy["rules"])
        ticket_id = _matching_ticket(
            change, baseline["asset_id"], observed_time, approvals["changes"]
        )
        finding = {
            **change,
            "classification": "approval_match" if ticket_id else "unapproved",
            "severity": rule["severity"] if rule else policy["default_severity"],
            "rule_id": rule["id"] if rule else None,
            "title": rule["title"] if rule else "Configuration changed",
            "rationale": rule["rationale"] if rule else "Review this change against OT policy.",
            "references": rule.get("references", []) if rule else [],
        }
        if ticket_id:
            finding["ticket_id"] = ticket_id
        findings.append(finding)

    status = (
        "drift" if any(item["classification"] == "unapproved" for item in findings)
        else "approved_change" if findings else "ok"
    )
    return {
        "schema_version": 1,
        "status": status,
        "asset_id": baseline["asset_id"],
        "baseline_id": baseline.get("baseline_id"),
        "baseline_captured_at": baseline["captured_at"],
        "observed_at": observed["observed_at"],
        "baseline_source": baseline["source"],
        "observed_source": observed["source"],
        "baseline_sha256": hashlib.sha256(_canonical(baseline["config"]).encode()).hexdigest(),
        "observed_sha256": hashlib.sha256(_canonical(observed["config"]).encode()).hexdigest(),
        "findings": findings,
        "summary": {
            "total_changes": len(findings),
            "unapproved": sum(item["classification"] == "unapproved" for item in findings),
            "approval_matches": sum(item["classification"] == "approval_match" for item in findings),
        },
    }
