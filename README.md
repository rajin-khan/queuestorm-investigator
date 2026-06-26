# QueueStorm Investigator

API solution for the SUST CSE Carnival 2026 Codex Community Hackathon preliminary round.

QueueStorm Investigator analyzes a customer support complaint against the supplied synthetic transaction history. It returns a strict JSON decision object with the relevant transaction, evidence verdict, case type, severity, routing department, agent summary, recommended next action, safe customer reply, and human-review flag.

The implementation is intentionally small: one Python service, no database, no external API key, and no frontend.

## API Contract

### `GET /health`

Returns service availability.

```json
{"status":"ok"}
```

### `POST /analyze-ticket`

Accepts the official QueueStorm ticket payload.

```json
{
  "ticket_id": "TKT-001",
  "complaint": "I sent 5000 taka to a wrong number around 2pm today...",
  "language": "en",
  "channel": "in_app_chat",
  "user_type": "customer",
  "transaction_history": [
    {
      "transaction_id": "TXN-9101",
      "timestamp": "2026-04-14T14:08:22Z",
      "type": "transfer",
      "amount": 5000,
      "counterparty": "+8801719876543",
      "status": "completed"
    }
  ]
}
```

The response includes the required fields:

- `ticket_id`
- `relevant_transaction_id`
- `evidence_verdict`
- `case_type`
- `severity`
- `department`
- `agent_summary`
- `recommended_next_action`
- `customer_reply`
- `human_review_required`
- `confidence`
- `reason_codes`

Example request and response files are in `samples/`.

## Quick Start

Requires Python 3.11+.

```bash
python3 app.py
```

The service listens on `0.0.0.0:8000` by default. Override the port when needed:

```bash
PORT=8080 python3 app.py
```

Test locally:

```bash
curl http://127.0.0.1:8000/health
curl -sS http://127.0.0.1:8000/analyze-ticket \
  -H 'Content-Type: application/json' \
  --data-binary @samples/sample_request.json
```

## Docker

```bash
docker build -t queuestorm-investigator .
docker run --rm -p 8000:8000 queuestorm-investigator
```

## Deployment

This repository is ready to deploy as a backend service. Railway can build and run it directly from the included Dockerfile.

No required environment variables are needed. The optional `PORT` variable is supported for hosted platforms that inject a runtime port.

The public endpoint URL was submitted through the official hackathon form. It is not hardcoded in this repository; judges can call the submitted base URL with:

```bash
curl https://SUBMITTED-BASE-URL/health
curl -sS https://SUBMITTED-BASE-URL/analyze-ticket \
  -H 'Content-Type: application/json' \
  --data-binary @samples/sample_request.json
```

## Tests

The public sample pack is stored at `samples/SUST_Preli_Sample_Cases.json`.

```bash
python3 tests/test_samples.py
python3 tests/test_contract.py
```

The tests cover sample-case matching, response schema, safety wording, malformed JSON, missing fields, invalid values, phishing escalation, amount parsing, and ambiguity handling.

## Evidence Reasoning

The service uses deterministic rules instead of an LLM. It evaluates complaint text and transaction history using:

- case-taxonomy keywords and transaction type
- mentioned amounts and explicit transaction IDs
- transaction status, counterparty, and timestamp hints
- duplicate-payment patterns by amount, recipient, and timing
- ambiguity checks that return `insufficient_data` instead of guessing

This keeps behavior reproducible and makes each decision traceable through `reason_codes`.

## Safety Logic

The customer-facing reply is deliberately constrained.

The service does not ask for PIN, OTP, password, CVV, full card number, or other secrets. It does not promise refunds, reversals, account unblocks, or guaranteed recovery. It routes phishing and social-engineering complaints to `fraud_risk` with human review.

Prompt-injection style text inside a complaint cannot alter the schema, routing rules, or safety wording because customer text is treated only as evidence.

## AI/Model Usage

No AI or machine-learning model is used.

Reason: the preliminary task can be handled with deterministic evidence matching and safety guardrails, avoiding latency, quota, cost, API-key exposure, and non-deterministic outputs during judging.

## Environment Variables

Only one optional variable is read:

```bash
PORT=8000
```

See `.env.example`.

## Limitations

- Bangla and Banglish support is keyword-based, not full semantic translation.
- The service only reasons over the supplied synthetic transaction history.
- Ambiguous or under-specified complaints may return `insufficient_data`.
- The API intentionally avoids autonomous financial commitments.
