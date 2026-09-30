"""Command-line entry point for offline, read-only snapshot analysis."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from .core import InputError, analyze, load_json_document


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compare an approved OT baseline with an independent observation."
    )
    parser.add_argument("--baseline", required=True, help="Approved baseline snapshot JSON")
    parser.add_argument("--observed", required=True, help="Independently collected snapshot JSON")
    parser.add_argument("--policy", required=True, help="Path-specific risk rules JSON")
    parser.add_argument("--approvals", help="Optional approved-change tickets JSON")
    parser.add_argument("--max-age-seconds", type=float, help="Reject a stale observation")
    parser.add_argument("--json", action="store_true", help="Print machine-readable result")
    return parser


def _render_text(result: dict) -> None:
    print(f"OT configuration drift: {result['status']}")
    print(f"Asset: {result['asset_id']}")
    print(f"Observed: {result['observed_at']} ({result['observed_source']})")
    print(
        "Changes: {total_changes} total, {unapproved} unapproved, "
        "{approval_matches} approval matches".format(**result["summary"])
    )
    for finding in result["findings"]:
        print(
            f"- [{finding['severity']}] {finding['path']} "
            f"({finding['change_type']}; {finding['classification']})"
        )
        print(f"  {finding['before']!r} -> {finding['after']!r}")
        print(f"  {finding['title']}: {finding['rationale']}")
        if finding.get("ticket_id"):
            print(f"  Matching ticket: {finding['ticket_id']}")


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        baseline = load_json_document(args.baseline)
        observed = load_json_document(args.observed)
        policy = load_json_document(args.policy)
        approvals = load_json_document(args.approvals) if args.approvals else None
        result = analyze(
            baseline,
            observed,
            policy,
            approvals,
            max_age_seconds=args.max_age_seconds,
        )
    except (InputError, ValueError) as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 3
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        _render_text(result)
    return 2 if result["status"] == "drift" else 0


if __name__ == "__main__":
    raise SystemExit(main())
