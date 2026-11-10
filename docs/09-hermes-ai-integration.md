# 09 — Hermes AI Integration and HMAC-SHA256 Authentication

| Item | Value |
|---|---|
| Document | Hermes / Laya decision integration and authentication status |
| Version | 1.0 |
| Date | 2026-11-10 |
| Status | **Hermes and HMAC-SHA256 were not found in the export or on the audited system** |

> **Read this first.** The audit request asked for "the separate Hermes AI integration and
> its HMAC-SHA256 authentication" and instructed that missing details must not be
> invented. This document reports what was searched, what was found, what was observed,
> and what is **not** implemented. No canonical string, header name, secret, signature
> algorithm or verification code is presented as existing.

---

## 1. What was requested vs. what exists

| Requested item | Found in the export? | Found locally? | Found in the live service? |
|---|---|---|---|
| A "Hermes" AI integration | **No** (0 matches) | **No** (only unrelated `hermes-parser`/`hermes-estree` npm packages in a different project) | **No** (console title is `Laya - SOC Decision Console`) |
| HMAC-SHA256 authentication | **No** (0 matches for `hmac`, `HMAC-SHA256`, `sha256` signing) | **No** in any SOC-related file | **No** HMAC headers observed in health/stats responses or console API calls |
| A Laya decision engine client | **Yes** — `Laya Decision Gate` Code node | A second YAML export of the same workflow exists | **Yes** — engine reachable at port 9999 |

The workflow contains a **Laya** integration. There is no separate Hermes component in the
workflow, in the audited local files, or in the reachable console. The three `sha256`
occurrences in the raw export are hash-length validation (`/^[a-f0-9]{64}$/`) and
candidate hash field names — not HMAC, not signing, not authentication.

---

## 2. Search methodology and evidence

### 2.1 Workflow export

| Search term | Matches in `Enterprise SOC SOAR Pipeline.json` |
|---|---:|
| `hermes` (case-insensitive) | 0 |
| `hmac` (case-insensitive) | 0 |
| `laya` (case-insensitive) | 11 |
| `9999` | 1 |
| `api/triage` | 1 |
| `sha256` | 3 (hash validation / field names only) |

The 11 `laya` matches are comments, field names (`laya_gate`, `laya_primary`,
`laya_verification`, `laya_model_used`) and the endpoint. None contain a signature or HMAC.

### 2.2 Local filesystem search

Searched `C:\Users\devas\Desktop`, `Downloads`, `Documents`, `source`, `projects` for
`hermes`, `HMAC-SHA256`, `hmac.new`, `api/triage`, and the engine address, restricted to
source, config and document file types.

Results:

| Match | Why it is unrelated |
|---|---|
| `cctf-platform/.../server.py` — `hmac.new(SIGNING_KEY, ...)` | A different project (CTF platform), not this workflow |
| `cctf-platform/SECURITY.md` — HMAC-SHA256 flag hashing | Documentation for a different project |
| `cctf-platform/package-lock.json` — `hermes-parser`, `hermes-estree` | Babel/React Native parser packages, unrelated to AI |
| `Downloads/complete-doc.md` — HMAC in a Cashfree webhook and lab token | A different system's documentation |
| `Downloads/enterprise_soc_soar_pipeline.yaml` | A second export of the **same** n8n workflow, with redacted values |
| `ai-soc-copilot-audit/code/13-Laya-Decision-Gate.js` | The Laya client in this workflow |

No Hermes implementation, HMAC signing helper, canonicalisation function or shared secret
was found in any SOC-related file.

### 2.3 GitHub search

Read-only repository search under the account `DevaSaiNandiniMandapalli` for `hermes` and
`laya` returned `total_count: 0` for public repositories. A private repository, if any,
is not visible without authentication and was not searched.

### 2.4 Live service probes (read-only, no credentials)

| Probe | Result |
|---|---|
| `GET /` on port 9999 | HTTP 200, HTML SPA, title `Laya - SOC Decision Console` |
| Keyword counts in the console HTML | `laya` 12, `triage` 4, `hermes` 0, `hmac` 0, `token` 0, `csrf` 0 |
| `GET /api/health` | `{"engine":"online","engine_version":"6.2","model":"online","model_name":"convaiinnovations/laya", ...}` |
| `GET /api/stats` | Aggregate counters: `total_triaged`, `suppressed`, `escalated`, `tp`, `fp`, `tn`, `fn_prevented`, `canary_checks`, `overrides_count`, latency metrics, `laya_model_calls`, `fast_path_calls`, `layer_counts`, `verdict_counts` |
| Response header | `Server: Laya-Triage/5.1` |
| `GET /api/triage` | 404 |
| `OPTIONS /api/triage` | 501 |
| `HEAD /api/triage` | 501 |
| `POST /api/triage` | **Not sent** — the audit did not modify or trigger the engine |

Observed console `fetch()` calls: `POST /api/override` with a JSON body and
`Content-Type: application/json`, plus `GET /api/vulnerabilities`, `GET /api/assets` and
other read endpoints. **No Authorization, signature or HMAC header appears in the console
JavaScript.** This is evidence about the console only; it does not prove the `/api/triage`
server-side contract.

The n8n editor at `http://192.168.3.55:5678/workflow/ORQ4n82CacFdx45s` returned only an
SPA shell. `/rest/workflows/...` and `/api/v1/workflows/...` returned `401 Unauthorized`.
No login attempt was made, no credentials were used, and no write operation was performed.

### 2.5 Evidence conclusion

| Claim | Status |
|---|---|
| A Laya engine is running and reachable | Supported by read-only health/stats responses |
| The workflow calls `POST /api/triage` from a Code node | Directly visible in `jsCode` |
| The engine uses a model named `convaiinnovations/laya` | Supported by `/api/health` |
| The engine implements HMAC-SHA256 verification | **Not evidenced** |
| A separate Hermes AI service exists | **Not evidenced** |
| The n8n workflow authenticates to the engine | **Not evidenced** — no auth headers in the code |

---

## 3. What the Laya integration actually is

### 3.1 Client location

`Laya Decision Gate`, a Code node (136 lines), not an HTTP Request node and not an n8n AI
node. There are **no native AI/LLM nodes** anywhere in the 31-node workflow.

### 3.2 Observed request contract (from the client code)

The client builds a JSON body with 14 fields:

| Field | Source |
|---|---|
| `timestamp` | `new Date().toISOString()` (processing time) |
| `host` | agent name |
| `vendor` | `incident.vendor ?? report.vendor ?? 'Wazuh'` |
| `rule_id` | report → incident → data → `'N/A'` |
| `rule_level` | report → incident → data → `data.rule.level` |
| `description` | report → incident → data → `'Security Event'` |
| `source_ip` | report → incident → data → `candidate_ip` → `original_alert.data.srcip` |
| `srcuser` | report → internal analysis → original alert → data |
| `severity` | report → data → incident → `'MEDIUM'`, upper-cased |
| `risk_score` | report → incident → data |
| `threat_intelligence` | report → incident → `{}` |
| `assessment` | report → incident → `{}` |
| `groups` | `report.raw_alert.rule.groups` → `incident.original_alert.rule.groups` → `[]` |
| `raw_alert` | full report raw alert or incident original alert |

The only header is `Content-Type: application/json`. The URL is plain HTTP on port 9999.
In the raw export the host was the Docker bridge address `172.17.0.1`; the sanitized
export uses `REPLACE_WITH_LAYA_HOST`.

### 3.3 Response fields consumed by the client

| Field | Used for |
|---|---|
| `action` or `decision` | Escalation decision; anything other than `ESCALATED` stops the workflow |
| `verdict` | IRIS title/tags/description, Discord embed |
| `confidence` | `laya_gate.confidence`, Discord percentage |
| `layer` | `L{layer}` tag and IRIS tag |
| `stage` | IRIS decision record, Discord field |
| `reason` | IRIS decision record |
| `laya_model_used` | `laya_gate.laya_model_used`, "Decided by" text |
| `latency_ms` | IRIS decision record, `laya_gate.latency_ms` |
| `model_latency_ms` | `laya_gate.model_latency_ms` |
| `correlation_id` | IRIS source ref/tags, Discord/Telegram/Slack ID lines |
| `policy_version` | `laya_gate.policy_version` (defaults to `'5.0'`) |

These are the fields the **client** reads. They are not a verified server response schema,
because no POST was sent and the engine source was not available.

### 3.4 Fail-safe

```text
action         = ESCALATED if ruleLevel >= 8 or severity HIGH/CRITICAL, else CLOSED_NO_IMPACT
verdict        = ENGINE_UNAVAILABLE
confidence     = 0.50
layer          = 4
stage          = "L4 Fail-Safe (engine unreachable)"
reason         = "Laya engine unreachable: <error>"
laya_model_used= false
correlation_id = "lay-offline"
```

The fail-safe escalates rather than drops, which is the right safety posture. But it means
a broken integration silently escalates all material alerts with a synthetic correlation
ID.

---

## 4. Why the integration is likely non-functional

n8n's official Code node documentation states:

> "You can't access the file system or make HTTP requests. Use the following nodes
> instead: Read/Write File From Disk, HTTP Request."

The Laya gate tries two unsupported mechanisms:

```js
if (typeof fetch === 'function') {
  const res = await fetch('http://REPLACE_WITH_LAYA_HOST:9999/api/triage', {...});
} else if (this.helpers && this.helpers.httpRequest) {
  layaDecision = await this.helpers.httpRequest({...});
}
```

- `fetch` is not a documented Code node capability.
- `this.helpers.httpRequest` is not a documented Code node API.
- Top-level `await` fails `node --check` in CommonJS mode (verified).
- No timeout is set, despite `LAYA_REQUEST_TIMEOUT_MS` in `.env.example`.
- If neither branch executes, `layaDecision` stays `null` and line 86 defaults the action
  to `ESCALATED` without even producing `ENGINE_UNAVAILABLE`.

**Assessment.** Unless the deployment has explicitly enabled an undocumented capability,
the engine is not consulted and the fail-safe path runs for every alert. This is a
critical architectural defect (C-02). It was determined from code and documentation, not
from a live execution.

---

## 5. HMAC-SHA256 status

### 5.1 Finding

**HMAC-SHA256 authentication is not implemented in this export.**

| Check | Result |
|---|---|
| `hmac` in the raw export | 0 matches |
| `HMAC-SHA256` in the raw export | 0 matches |
| Signature header in the Laya request | None |
| Timestamp/nonce header | None |
| Shared secret referenced in the workflow | None |
| `crypto.createHmac` or equivalent in Code nodes | None |
| Signature verification in the workflow | None |
| HMAC in the reachable console JavaScript | None observed |
| `WWW-Authenticate` on `/api/triage` HEAD/OPTIONS | None (both returned 501) |

The `.env.example` file includes `LAYA_HMAC_SECRET` and `LAYA_API_TOKEN` **placeholders**
with an explicit comment that they are **not used by this export**. Those entries exist so
the configuration contract is documented; they are not evidence of an implementation.

### 5.2 What this means

- The engine endpoint, if reachable, accepts an unsigned plain-HTTP JSON body from the
  workflow as far as the workflow is concerned.
- There is no replay protection, no request authenticity check and no integrity check.
- Any process that can reach the engine's `/api/triage` could submit triage payloads,
  subject to whatever server-side controls exist (unknown).
- The audit cannot say whether the **server** enforces HMAC; it can only say the **client**
  does not send one and no server-side implementation was available for review.

### 5.3 Verification checklist for the engine owner

To establish the real contract, obtain the engine source or its OpenAPI specification and
confirm:

1. Does `/api/triage` require authentication? Which header(s)?
2. Is there an HMAC-SHA256 signature? What is the exact canonical string (field order,
   separators, newline policy, body hash)?
3. Which key is used, and how is it rotated?
4. Is a timestamp or nonce included, and what is the replay window?
5. Is the comparison constant-time?
6. Is the transport TLS?
7. What response does a valid request return, and which of the fields in §3.3 are real?
8. What are the rate limits and error codes?
9. Is there a `/api/override` contract similar to the console's call, and does it require
   the same signature?
10. Is the `policy_version` value `6.2` (engine health) or `5.1` (HTTP server header)?
    The workflow defaults to `'5.0'`.

Until these are answered, do not document or claim an HMAC implementation.

---

## 6. Proposed HMAC design (not implemented)

The following is a **design proposal** for future work. It is not present in the workflow,
not observed in the engine, and not a statement of existing behaviour.

```mermaid
sequenceDiagram
    participant N as n8n HTTP Request node
    participant E as Laya engine
    N->>N: body = canonical JSON (stable key order)
    N->>N: ts = unix seconds; nonce = random
    N->>N: sig = HMAC_SHA256(secret, ts + "." + nonce + "." + sha256(body))
    N->>E: POST /api/triage<br/>X-Laya-Key-Id, X-Laya-Timestamp,<br/>X-Laya-Nonce, X-Laya-Signature
    E->>E: reject if |now - ts| > 300 s
    E->>E: reject if nonce seen before
    E->>E: recompute signature and constant-time compare
    E-->>N: decision JSON
```

| Element | Proposal |
|---|---|
| Algorithm | HMAC-SHA256, hex or base64 (must be agreed with the engine owner) |
| Canonical string | `timestamp + "." + nonce + "." + SHA256(raw_request_body)` |
| Key | Per-client secret referenced by a key ID; stored in n8n credentials, never inline |
| Headers | `X-Laya-Key-Id`, `X-Laya-Timestamp`, `X-Laya-Nonce`, `X-Laya-Signature` |
| Replay window | 300 seconds plus a nonce cache |
| Transport | HTTPS with certificate verification |
| Comparison | Constant-time on the server |
| Rotation | Overlapping key IDs with a defined cutover |

**Implementation in n8n:** compute the signature in a Code node using the `crypto`
module (available in n8n Cloud Code nodes), then perform the request with an **HTTP
Request node** that carries the headers, timeout, retry and TLS settings. Do not attempt
the HTTP call inside the Code node.

---

## 7. Hermes: what to do next

If a separate Hermes service exists in the user's environment, the audit needs one of:

- the repository or source path,
- the container image or service definition,
- the OpenAPI/Swagger specification,
- or a sanitized export of its configuration.

With that, the following can be documented accurately:

1. Hermes' role relative to Laya (is it the model server, a wrapper, or a different
   product?).
2. Its authentication mechanism, including HMAC-SHA256 if present.
3. The canonical string, headers, timestamp/nonce policy and key rotation.
4. Request/response schemas and error codes.
5. How n8n should call it (HTTP Request node, credentials, TLS).

None of that can be inferred from the current export. The `Laya - SOC Decision Console`
title, `/api/health` model name `convaiinnovations/laya`, and `Laya-Triage/5.1` server
header are the only identity evidence available.

---

## 8. Honesty statement

This document deliberately does **not**:

- invent an HMAC canonical string and present it as real,
- invent header names or a shared secret,
- claim the engine verifies signatures,
- claim a Hermes service exists,
- claim a POST to `/api/triage` was tested,
- claim the workflow's Laya call works,
- or present aggregate health/stats values as audit test results.

Everything labelled "observed" comes from a read-only probe. Everything labelled
"proposed" is future design work. Everything labelled "found" comes from the exported
workflow.

---

## 9. Related documents

- [02 — Architecture](02-architecture.md) for the sequence diagram.
- [04 — Code audit](04-code-audit.md) for the Laya Code node line review.
- [05 — Data flow](05-data-flow.md) for the triage payload shape.
- [11 — Installation](11-installation.md) for placeholder configuration.
- [14 — Security](14-security.md) for authentication hardening.
- [15 — Limitations and roadmap](15-limitations-and-roadmap.md).
- [16 — Audit report](16-audit-report.md) for findings C-02 and M-07.
