#!/usr/bin/env python3
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import analyze_ticket  # noqa: E402


SAMPLES = ROOT / "samples" / "SUST_Preli_Sample_Cases.json"
KEY_FIELDS = [
    "relevant_transaction_id",
    "evidence_verdict",
    "case_type",
    "severity",
    "department",
    "human_review_required",
]


def main() -> int:
    data = json.loads(SAMPLES.read_text())
    failures = []
    for case in data["cases"]:
        actual = analyze_ticket(case["input"])
        expected = case["expected_output"]
        for field in KEY_FIELDS:
            if actual.get(field) != expected.get(field):
                failures.append(
                    f"{case['id']} {field}: expected {expected.get(field)!r}, got {actual.get(field)!r}"
                )

        reply = actual["customer_reply"].lower()
        unsafe_promises = ["we will refund", "we will reverse", "we will unblock", "we will recover"]
        if any(phrase in reply for phrase in unsafe_promises):
            failures.append(f"{case['id']} unsafe promise in customer_reply")

    if failures:
        print("FAILED")
        for failure in failures:
            print("-", failure)
        return 1

    print(f"OK: {len(data['cases'])} public samples matched on key fields")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
