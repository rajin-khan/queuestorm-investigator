#!/usr/bin/env python3
"""QueueStorm Investigator: dependency-free preliminary API service."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse


PORT = int(os.environ.get("PORT", "8000"))


class BadRequest(ValueError):
    """Malformed input such as missing required fields."""


class SemanticInvalid(ValueError):
    """Schema-shaped input that cannot be analyzed meaningfully."""


CASE_TYPES = {
    "wrong_transfer",
    "payment_failed",
    "refund_request",
    "duplicate_payment",
    "merchant_settlement_delay",
    "agent_cash_in_issue",
    "phishing_or_social_engineering",
    "other",
}

DEPARTMENTS = {
    "customer_support",
    "dispute_resolution",
    "payments_ops",
    "merchant_operations",
    "agent_operations",
    "fraud_risk",
}

BANGLA_DIGITS = str.maketrans("০১২৩৪৫৬৭৮৯", "0123456789")


def normalize_text(value: Any) -> str:
    return str(value or "").translate(BANGLA_DIGITS).lower()


def has_any(text: str, terms: list[str]) -> bool:
    return any(term in text for term in terms)


def extract_amounts(text: str) -> list[float]:
    values: list[float] = []
    for match in re.findall(r"(?<![\w+])\d+(?:\.\d+)?", text.translate(BANGLA_DIGITS)):
        try:
            amount = float(match)
        except ValueError:
            continue
        if amount >= 10:
            values.append(amount)
    return values


def safe_number(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        cleaned = value.replace(",", "").strip()
        try:
            return float(cleaned)
        except ValueError:
            return 0.0
    return 0.0


def extract_transaction_ids(text: str) -> set[str]:
    return {m.upper() for m in re.findall(r"\bTXN[-_]?\d+\b", text, flags=re.I)}


def extract_phone_tokens(text: str) -> set[str]:
    tokens: set[str] = set()
    compact = re.sub(r"[\s\-().]", "", text.translate(BANGLA_DIGITS))
    for match in re.findall(r"(?:\+?8801|01)\d{9}", compact):
        digits = re.sub(r"\D", "", match)
        if digits.startswith("880"):
            digits = "0" + digits[3:]
        tokens.add(digits)
    return tokens


def counterparty_matches(counterparty: Any, phones: set[str]) -> bool:
    if not phones:
        return False
    digits = re.sub(r"\D", "", str(counterparty or ""))
    if digits.startswith("880"):
        digits = "0" + digits[3:]
    return digits in phones


def amount_matches(amount: float, mentioned: list[float]) -> bool:
    return not mentioned or any(abs(float(amount) - m) < 0.01 for m in mentioned)


def parse_ts(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def classify_case(complaint: str, user_type: str, history: list[dict[str, Any]]) -> str:
    text = normalize_text(complaint)
    normalized_user_type = normalize_text(user_type)

    if has_any(text, ["otp", "pin", "password", "cvv", "card number", "verification code", "blocked if", "share it", "scam", "fraud", "fake link", "suspicious link", "phishing", "ওটিপি", "পিন", "পাসওয়ার্ড", "ব্লক", "লিংক"]):
        if has_any(text, ["ask", "asked", "share", "called", "sms", "link", "number", "message", "ওটিপি", "পিন", "পাসওয়ার্ড", "লিংক"]):
            return "phishing_or_social_engineering"

    if has_any(text, ["duplicate", "twice", "double", "deducted twice", "charged twice", "two times", "দুইবার", "২ বার"]):
        return "duplicate_payment"

    if has_any(text, ["cash in", "cash-in", "cashin", "agent", "balance e ashe nai", "not reflected", "not showing", "এজেন্ট", "ক্যাশ ইন", "ব্যালেন্সে", "টাকা আসেনি"]):
        if any(txn.get("type") == "cash_in" for txn in history) or has_any(text, ["cash", "agent", "ক্যাশ", "এজেন্ট"]):
            return "agent_cash_in_issue"

    if normalized_user_type == "agent" and any(txn.get("type") == "cash_in" for txn in history):
        return "agent_cash_in_issue"

    if has_any(text, ["failed", "failure", "deducted", "balance deducted", "recharge", "payment failed", "ফেইল", "ব্যর্থ", "কেটে", "কাটা"]):
        return "payment_failed"

    if has_any(text, ["refund", "changed my mind", "cancel", "return my money", "রিফান্ড", "ফেরত"]):
        return "refund_request"

    if normalized_user_type == "merchant" or has_any(text, ["merchant", "settlement", "settled", "sales", "payout", "সেটেল"]):
        return "merchant_settlement_delay"

    if has_any(text, ["wrong number", "wrong person", "wrong recipient", "typed it wrong", "mistake", "reverse it", "sent to", "didn't get", "did not get", "not received", "পাঠিয়েছি", "ভুল"]):
        if any(txn.get("type") == "transfer" for txn in history) or has_any(text, ["sent", "transfer", "পাঠিয়েছি"]):
            return "wrong_transfer"

    return "other"


def find_duplicate_payment(history: list[dict[str, Any]]) -> dict[str, Any] | None:
    payments = [t for t in history if t.get("type") == "payment" and t.get("status") == "completed"]
    best_pair: tuple[float, dict[str, Any]] | None = None
    for i, left in enumerate(payments):
        for right in payments[i + 1 :]:
            if left.get("amount") != right.get("amount") or left.get("counterparty") != right.get("counterparty"):
                continue
            lt = parse_ts(str(left.get("timestamp", "")))
            rt = parse_ts(str(right.get("timestamp", "")))
            delta = abs((rt - lt).total_seconds()) if lt and rt else 999999.0
            suspect = right if str(right.get("timestamp", "")) >= str(left.get("timestamp", "")) else left
            if best_pair is None or delta < best_pair[0]:
                best_pair = (delta, suspect)
    return best_pair[1] if best_pair else None


def score_transaction(txn: dict[str, Any], case_type: str, amounts: list[float], ids: set[str], phones: set[str]) -> int:
    txid = str(txn.get("transaction_id", "")).upper()
    if txid in ids:
        return 100

    score = 0
    tx_type = txn.get("type")
    status = txn.get("status")

    preferred_types = {
        "wrong_transfer": {"transfer"},
        "payment_failed": {"payment"},
        "refund_request": {"payment", "refund"},
        "merchant_settlement_delay": {"settlement"},
        "agent_cash_in_issue": {"cash_in"},
        "duplicate_payment": {"payment"},
    }.get(case_type, set())

    if tx_type in preferred_types:
        score += 25
    if amount_matches(safe_number(txn.get("amount")), amounts):
        score += 20
    if counterparty_matches(txn.get("counterparty"), phones):
        score += 30
    if case_type == "payment_failed" and status == "failed":
        score += 20
    if case_type in {"merchant_settlement_delay", "agent_cash_in_issue"} and status in {"pending", "failed"}:
        score += 20
    if case_type in {"refund_request", "wrong_transfer"} and status == "completed":
        score += 10

    return score


def choose_relevant_transaction(case_type: str, complaint: str, history: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, bool]:
    if not history or case_type == "phishing_or_social_engineering":
        return None, False
    if case_type == "other":
        return None, False
    if case_type == "duplicate_payment":
        duplicate = find_duplicate_payment(history)
        if duplicate:
            return duplicate, False

    amounts = extract_amounts(complaint)
    ids = extract_transaction_ids(complaint)
    phones = extract_phone_tokens(complaint)
    scored = [(score_transaction(txn, case_type, amounts, ids, phones), txn) for txn in history]
    scored.sort(key=lambda item: (item[0], str(item[1].get("timestamp", ""))), reverse=True)
    top_score, top_txn = scored[0]

    if top_score < 20:
        return None, False

    plausible = [txn for score, txn in scored if score == top_score and score >= 40]
    if len(plausible) > 1 and not ids:
        return None, True

    if case_type == "wrong_transfer" and len([t for _, t in scored if amount_matches(safe_number(t.get("amount")), amounts)]) > 1 and not ids and not phones:
        text = normalize_text(complaint)
        if not re.search(r"\+?8801\d{9}|01\d{9}", text):
            return None, True

    return top_txn, False


def evidence_verdict(case_type: str, txn: dict[str, Any] | None, ambiguous: bool, complaint: str, history: list[dict[str, Any]]) -> str:
    if ambiguous or not txn:
        return "insufficient_data"

    status = txn.get("status")
    tx_type = txn.get("type")

    if case_type == "payment_failed":
        return "consistent" if tx_type == "payment" and status == "failed" else "inconsistent"
    if case_type == "merchant_settlement_delay":
        return "consistent" if tx_type == "settlement" and status in {"pending", "failed"} else "inconsistent"
    if case_type == "agent_cash_in_issue":
        return "consistent" if tx_type == "cash_in" and status in {"pending", "failed"} else "inconsistent"
    if case_type == "duplicate_payment":
        return "consistent" if find_duplicate_payment(history) else "insufficient_data"
    if case_type == "wrong_transfer":
        same_counterparty = [
            t for t in history
            if t is not txn and t.get("type") == "transfer" and t.get("counterparty") == txn.get("counterparty")
        ]
        return "inconsistent" if same_counterparty else "consistent"
    if case_type == "refund_request":
        return "consistent" if tx_type in {"payment", "refund"} else "insufficient_data"
    return "insufficient_data"


def department_for(case_type: str) -> str:
    return {
        "wrong_transfer": "dispute_resolution",
        "payment_failed": "payments_ops",
        "refund_request": "customer_support",
        "duplicate_payment": "payments_ops",
        "merchant_settlement_delay": "merchant_operations",
        "agent_cash_in_issue": "agent_operations",
        "phishing_or_social_engineering": "fraud_risk",
        "other": "customer_support",
    }[case_type]


def severity_for(case_type: str, verdict: str, txn: dict[str, Any] | None, ambiguous: bool) -> str:
    amount = safe_number(txn.get("amount")) if txn else 0
    if case_type == "phishing_or_social_engineering":
        return "critical"
    if case_type in {"payment_failed", "duplicate_payment", "agent_cash_in_issue"}:
        return "high"
    if case_type == "wrong_transfer":
        return "medium" if verdict in {"inconsistent", "insufficient_data"} or ambiguous else "high"
    if case_type == "merchant_settlement_delay":
        return "medium"
    if amount >= 10000:
        return "high"
    if case_type == "refund_request":
        return "low" if amount < 1000 else "medium"
    return "low"


def confidence_for(case_type: str, verdict: str, ambiguous: bool, txn: dict[str, Any] | None) -> float:
    if case_type == "phishing_or_social_engineering":
        return 0.95
    if ambiguous:
        return 0.65
    if verdict == "consistent" and txn:
        return 0.9
    if verdict == "inconsistent":
        return 0.75
    return 0.6


def reason_codes_for(case_type: str, verdict: str, ambiguous: bool, txn: dict[str, Any] | None) -> list[str]:
    codes = [case_type]
    if ambiguous:
        codes.append("ambiguous_match")
    elif txn:
        codes.append("transaction_match")
    else:
        codes.append("needs_clarification")
    if verdict != "consistent":
        codes.append(f"evidence_{verdict}")
    if case_type == "phishing_or_social_engineering":
        codes.extend(["credential_protection", "critical_escalation"])
    return codes


def safe_reply(case_type: str, ticket_language: str, txn: dict[str, Any] | None, ambiguous: bool) -> str:
    txid = str(txn.get("transaction_id")) if txn else "the relevant transaction"

    if ticket_language == "bn":
        if case_type == "phishing_or_social_engineering":
            return "আমরা কখনও আপনার পিন, ওটিপি বা পাসওয়ার্ড চাই না। এগুলো কারো সাথে শেয়ার করবেন না। আমাদের ফ্রড টিম ঘটনাটি পর্যালোচনা করবে।"
        if ambiguous or not txn:
            return "আপনার অনুরোধটি আমরা পেয়েছি। দ্রুত সহায়তার জন্য লেনদেন আইডি, পরিমাণ এবং কী সমস্যা হয়েছে তা জানান। কারো সাথে আপনার পিন বা ওটিপি শেয়ার করবেন না।"
        return f"আপনার লেনদেন {txid} এর বিষয়ে আমরা অবগত হয়েছি। সংশ্লিষ্ট দল এটি যাচাই করবে এবং অফিসিয়াল চ্যানেলে আপনাকে জানাবে। কারো সাথে আপনার পিন বা ওটিপি শেয়ার করবেন না।"

    if case_type == "phishing_or_social_engineering":
        return "Thank you for reporting this. We never ask for your PIN, OTP, password, or full card number. Please do not share these with anyone. Our fraud team will review the incident through official channels."
    if ambiguous or not txn:
        return "Thank you for reaching out. To help you faster, please share the transaction ID, amount, approximate time, and what went wrong. Please do not share your PIN or OTP with anyone."
    if case_type == "refund_request":
        return f"We have noted your request about transaction {txid}. Refund eligibility depends on the merchant or service policy, and any eligible amount will be handled through official channels. Please do not share your PIN or OTP with anyone."
    if case_type in {"payment_failed", "duplicate_payment"}:
        return f"We have noted your concern about transaction {txid}. Our payments team will verify the case, and any eligible amount will be returned through official channels. Please do not share your PIN or OTP with anyone."
    if case_type == "merchant_settlement_delay":
        return f"We have noted your concern about settlement {txid}. Our merchant operations team will check the batch status and update you through official channels."
    return f"We have noted your concern about transaction {txid}. The relevant team will review the case and contact you through official support channels. Please do not share your PIN or OTP with anyone."


def summarize(case_type: str, verdict: str, txn: dict[str, Any] | None, ambiguous: bool, complaint: str) -> str:
    if case_type == "phishing_or_social_engineering":
        return "Customer reports a possible social engineering attempt involving sensitive credentials. Fraud review is required."
    if ambiguous:
        return "Customer complaint matches multiple possible transactions, so the relevant transaction cannot be identified without more detail."
    if not txn:
        return "Customer provided insufficient transaction detail to identify a relevant transaction from the supplied history."

    txid = txn.get("transaction_id")
    amount = txn.get("amount")
    counterparty = txn.get("counterparty")
    status = txn.get("status")
    return f"Customer complaint appears related to {txid}: {amount} BDT {txn.get('type')} with {counterparty}, currently {status}. Evidence verdict: {verdict}."


def next_action(case_type: str, verdict: str, txn: dict[str, Any] | None, ambiguous: bool) -> str:
    if case_type == "phishing_or_social_engineering":
        return "Escalate to fraud_risk immediately, log reported indicators, and remind the customer not to share sensitive credentials."
    if ambiguous or not txn:
        return "Ask the customer for transaction ID, amount, counterparty, and approximate time before taking financial action."

    txid = txn.get("transaction_id")
    if verdict == "inconsistent":
        return f"Flag {txid} for human review because transaction history does not fully support the complaint."
    if case_type == "wrong_transfer":
        return f"Verify {txid} details with the customer and start the wrong-transfer dispute review according to policy."
    if case_type == "payment_failed":
        return f"Investigate {txid} ledger status and start the standard reversal workflow only if the failed deduction is confirmed."
    if case_type == "duplicate_payment":
        return f"Verify suspected duplicate {txid} with payments_ops and the biller before any reversal action."
    if case_type == "merchant_settlement_delay":
        return f"Route {txid} to merchant_operations to verify settlement batch status and communicate an official ETA."
    if case_type == "agent_cash_in_issue":
        return f"Investigate {txid} with agent_operations and confirm the cash-in settlement state."
    if case_type == "refund_request":
        return f"Review {txid} against refund policy and guide the customer without promising a refund."
    return "Handle through customer_support and request more details if needed."


def human_review_required(case_type: str, verdict: str, severity: str, txn: dict[str, Any] | None, ambiguous: bool) -> bool:
    if case_type in {"phishing_or_social_engineering", "duplicate_payment", "agent_cash_in_issue"}:
        return True
    if case_type == "wrong_transfer" and (txn is not None or verdict == "inconsistent"):
        return True
    if severity in {"critical", "high"} and case_type not in {"payment_failed"}:
        return True
    return False


def analyze_ticket(payload: dict[str, Any]) -> dict[str, Any]:
    complaint = payload.get("complaint")
    if not isinstance(payload.get("ticket_id"), str) or not payload["ticket_id"].strip():
        raise BadRequest("ticket_id is required")
    if not isinstance(complaint, str):
        raise BadRequest("complaint is required")
    if not complaint.strip():
        raise SemanticInvalid("complaint must not be empty")

    history_raw = payload.get("transaction_history", [])
    history = history_raw if isinstance(history_raw, list) else []
    history = [txn for txn in history if isinstance(txn, dict)]
    user_type = str(payload.get("user_type") or "unknown")
    language = str(payload.get("language") or "en")

    case_type = classify_case(complaint, user_type, history)
    txn, ambiguous = choose_relevant_transaction(case_type, complaint, history)
    verdict = evidence_verdict(case_type, txn, ambiguous, complaint, history)
    severity = severity_for(case_type, verdict, txn, ambiguous)
    department = department_for(case_type)

    result = {
        "ticket_id": payload["ticket_id"],
        "relevant_transaction_id": txn.get("transaction_id") if txn else None,
        "evidence_verdict": verdict,
        "case_type": case_type if case_type in CASE_TYPES else "other",
        "severity": severity,
        "department": department if department in DEPARTMENTS else "customer_support",
        "agent_summary": summarize(case_type, verdict, txn, ambiguous, complaint),
        "recommended_next_action": next_action(case_type, verdict, txn, ambiguous),
        "customer_reply": safe_reply(case_type, language, txn, ambiguous),
        "human_review_required": human_review_required(case_type, verdict, severity, txn, ambiguous),
        "confidence": confidence_for(case_type, verdict, ambiguous, txn),
        "reason_codes": reason_codes_for(case_type, verdict, ambiguous, txn),
    }
    return result


class Handler(BaseHTTPRequestHandler):
    server_version = "QueueStormInvestigator/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        print("%s - %s" % (self.address_string(), fmt % args))

    def send_json(self, status: int, body: dict[str, Any]) -> None:
        data = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if urlparse(self.path).path == "/health":
            self.send_json(200, {"status": "ok"})
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/analyze-ticket":
            self.send_json(404, {"error": "not found"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(payload, dict):
                raise BadRequest("JSON body must be an object")
        except json.JSONDecodeError:
            self.send_json(400, {"error": "invalid JSON body"})
            return
        except BadRequest as exc:
            self.send_json(400, {"error": str(exc)})
            return
        except Exception:
            self.send_json(400, {"error": "malformed request body"})
            return

        try:
            self.send_json(200, analyze_ticket(payload))
        except BadRequest as exc:
            self.send_json(400, {"error": str(exc)})
        except SemanticInvalid as exc:
            self.send_json(422, {"error": str(exc)})
        except Exception:
            self.send_json(500, {"error": "internal analysis error"})


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"QueueStorm Investigator listening on 0.0.0.0:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("QueueStorm Investigator stopped")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
