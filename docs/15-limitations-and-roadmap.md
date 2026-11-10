# 15 — Limitations and Future Improvements

| Item | Value |
|---|---|
| Document | Known limitations, unverified behaviour and roadmap |
| Version | 1.0 |
| Date | 2026-11-10 |
| Basis | Static audit only |

---

## 1. Audit limitations

These are limitations of **this audit**, not necessarily of the live system.

| # | Limitation | Consequence |
|---|---|---|
| A1 | The live n8n workflow could not be read. The editor returned an SPA shell; `/rest/workflows/...` and `/api/v1/workflows/...` returned `401`. | The audit used a local export whose `id` matched `ORQ4n82CacFdx45s`. Live configuration parity is **unverified**. |
| A2 | No live execution was performed. | No runtime behaviour, provider response or notification delivery was tested. |
| A3 | No POST was sent to `/api/triage`. | The Laya response schema in [09](09-hermes-ai-integration.md) is the *client's expectation*, not a verified server contract. |
| A4 | The Laya/Hermes engine source was not available locally. | Server-side authentication, model behaviour and HMAC status cannot be confirmed. |
| A5 | No authenticated n8n screenshots were available. | No screenshots are included; none were fabricated. |
| A6 | No load, performance or penetration test was run. | Throughput, quota cost and resilience are unknown. |
| A7 | The referenced `errorWorkflow` was not exported. | Global error handling cannot be verified. |
| A8 | The Wazuh manager configuration was not inspected. | The exact integration block, filters and retry behaviour are unknown. |

---

## 2. Functional limitations of the workflow

### 2.1 Decision engine

| ID | Limitation |
|---|---|
| F1 | The Laya call is inside a Code node, which n8n documents as unable to make HTTP requests (C-02). |
| F2 | No HMAC, authentication, nonce, timestamp or replay protection on the Laya request. |
| F3 | No timeout; `LAYA_REQUEST_TIMEOUT_MS` exists only in `.env.example`. |
| F4 | The fail-safe escalates all rule-level-8+ alerts when the engine is unavailable, producing synthetic `lay-offline` correlation IDs. |
| F5 | No separate Hermes integration exists in the export or on the audited system. |

### 2.2 Detection and enrichment

| ID | Limitation |
|---|---|
| F6 | `Final Report` throws a `ReferenceError` when `source_ip` is falsy (C-03). |
| F7 | Hash, URL and domain IOCs are not enriched by hash/domain/URL-specific endpoints (H-06). |
| F8 | TLD allowlist has 26 entries; IPv6 is unsupported (M-01). |
| F9 | The first public IP may be a destination, not the source (M-02). |
| F10 | Local-host detection suppresses TI for many internet-facing authentication alerts. |
| F11 | Provider identification relies on response shape rather than an explicit tag. |
| F12 | ThreatFox errors can force CRITICAL severity (H-05). |
| F13 | `provider_coverage` counts unavailable providers as checked; `provider_failures` holds indices (M-03). |

### 2.3 Scoring and reporting

| ID | Limitation |
|---|---|
| F14 | Four nodes compute risk/severity with different thresholds (H-03). |
| F15 | IRIS severity IDs are non-monotonic; customer/status IDs are hard-coded (H-07). |
| F16 | `alert_source_ref` has no timestamp; duplicate cases can collide. |
| F17 | Duplicate object keys in `Incident Summary` discard fallbacks (M-05). |
| F18 | `severity_factors` is computed but never recorded in IRIS or chat. |

### 2.4 Response

| ID | Limitation |
|---|---|
| F19 | FortiGate node defaults to GET and only creates an address object; no policy, no block, no rollback (H-01). |
| F20 | `Severity Confirmation` and `Is Public IP?` false outputs are unconnected (H-02). |
| F21 | Telegram internal branch has a literal `' + idLine + '` (M-06). |
| F22 | Notification failures are hidden by `continueRegularOutput`. |
| F23 | Chat nodes may read the IRIS case ID before IRIS completes. |
| F24 | No output escaping for Slack mrkdwn or Telegram HTML (L-03). |

### 2.5 Operations

| ID | Limitation |
|---|---|
| F25 | Dedup uses per-workflow static data, is not atomic, and is unreliable in test/multi-instance deployments (H-04). |
| F26 | High-volume regex bugs (`235\d`, `8661[123]`) (H-04). |
| F27 | Suppressed alerts leave no record (M-08). |
| F28 | No queue, throttle, budget guard or circuit breaker. |
| F29 | No structured metrics, no error workflow, no node notes, no runbook in the original workflow. |
| F30 | Execution history may retain full Wazuh payloads (H-08). |

---

## 3. Unverified behaviour requiring runtime confirmation

These are **not** recorded as confirmed findings because static analysis cannot settle
them. They must be checked in the deployed n8n version.

| # | Question | Why it matters |
|---|---|---|
| U1 | Does `Merge2` emit an item when only one IF branch executes? | n8n Merge v3 Append "waits for the execution of all connected inputs"; `alwaysOutputData` is not set. |
| U2 | Is `fetch` available in this n8n Code node runtime? | Determines whether the Laya call throws or returns a response. |
| U3 | Does the Code node accept top-level `await`? | `node --check` fails in CommonJS mode; n8n may wrap code in an async function. |
| U4 | What exact shape do provider error items have? | Determines whether `TI Aggregator`'s `data.error` branch ever fires. |
| U5 | What does `POST /api/triage` actually return? | The client reads 11 response fields; none were verified. |
| U6 | Does the Laya server enforce authentication or HMAC? | Not evidenced client-side; server source unavailable. |
| U7 | What are the IRIS severity ID semantics? | The mapping CRITICAL 6 / HIGH 5 / MEDIUM 1 / LOW 4 looks non-monotonic. |
| U8 | Does the deployed Wazuh integration add authentication or filtering? | Not visible in the export. |
| U9 | What is the real LeakIX `/host/` response shape? | Determines whether M-04 is a live defect. |
| U10 | Does `groups` survive the Set node's `string` type declaration? | Downstream Code nodes read the original alert instead. |

---

## 4. Claims that must not be made

- "HMAC-SHA256 authentication is implemented." It is not.
- "Hermes AI is integrated." It was not found.
- "FortiGate blocks malicious IPs." The node creates an address object with a GET request.
- "The Laya engine is the authoritative decision-maker in production." The transport is
  unsupported.
- "The workflow was tested end to end." It was not.
- "All 31 nodes were executed successfully." No execution was performed.
- "Screenshots are included." They are not.
- "Secrets were securely erased." Sanitisation is not forensic erasure.
- "The workflow is production ready." It is a prototype with 4 critical findings.

---

## 5. Roadmap

### Phase 0 — Contain and correct (P0)

| Task | Addresses |
|---|---|
| Rotate all 13 exposed credentials; move to n8n credentials | C-01 |
| Authenticate the webhook; add IP allowlist, rate limit, size limit and schema validation | C-04 |
| Fix `Final Report` `alert_source_ref` fallback | C-03 |
| Replace the Laya Code node with HTTP Request + interpreter nodes, with timeout and TLS | C-02 |
| Obtain the engine contract; implement HMAC only after verification | F2, F5 |
| Enable execution-data pruning and redaction | H-08 |

**Exit criteria:** no inline secrets; webhook rejects unauthenticated requests; a synthetic
alert with a missing source IP produces a valid report; the Laya call succeeds or fails
with a visible, non-silent error.

### Phase 1 — Correctness (P1)

| Task | Addresses |
|---|---|
| Implement one `assess()` function and remove competing severity logic | H-03, F14 |
| Explicit ThreatFox status mapping and provider error mapping | H-05, M-09 |
| Provider tagging before Merge1; named `provider_failures`; accurate coverage | M-03 |
| Hash/domain/URL-specific enrichment paths | H-06 |
| Fix dedup regexes; add atomic TTL dedup and suppression records | H-04, M-08 |
| Fix IRIS IDs, customer ID and idempotent `alert_source_ref` | H-07 |
| Remove duplicate keys in `Incident Summary` | M-05 |
| Fix Telegram `idLine`; escape HTML and mrkdwn | M-06, L-03 |
| Widen TLD list; validate and encode IOCs | M-01, M-09 |
| Verify Merge2 semantics and `fetch`/top-level-`await` behaviour | U1–U4 |

**Exit criteria:** the scenario matrix in [08](08-correlation-and-severity.md) passes; a
ThreatFox auth error does not produce CRITICAL; a hash-only alert is enriched correctly.

### Phase 2 — Response and containment (P2)

| Task | Addresses |
|---|---|
| Set FortiGate method; create a deny policy with approval and rollback | H-01 |
| Connect dead-end IF outputs to explicit closure/audit nodes | H-02 |
| Serialise IRIS before chat nodes; propagate one correlation ID | F23 |
| Escape all output formats; structured body builders | F24 |
| Add an error workflow, structured metrics and notification-failure alerting | F22, F29 |
| Add provider caching, budget guards and a circuit breaker | F28 |
| Verify IRIS severity semantics and Laya response contract | U5–U7 |

**Exit criteria:** a CRITICAL public-IP incident creates one IRIS case, three chat messages
and one verified firewall policy; a MEDIUM incident produces an explicit "no containment"
record.

### Phase 3 — Platform quality (P3)

| Task | Addresses |
|---|---|
| Extract Code node logic into tested modules or sub-workflows | F29 |
| Add unit tests for every Code node and finding | [12](12-testing-and-validation.md) |
| Add integration tests with mocked provider responses | F11 |
| Add load tests and quota-cost measurement | A6 |
| Add a runbook, dashboards and alerting | F29 |
| Document actual retention behaviour for n8n, IRIS, chat and engine | F30 |
| Re-audit against the live workflow with authorised read access | A1 |

---

## 6. Acceptance criteria for a production release

| # | Criterion |
|---|---|
| 1 | Zero critical and zero high findings open |
| 2 | No credential inline in any node parameter |
| 3 | Webhook authenticated, allowlisted, rate-limited and schema-validated |
| 4 | Laya (and Hermes, if it exists) called over HTTPS with verified signing |
| 5 | One severity/verdict function with a published decision table |
| 6 | Containment performs a verified, reversible policy change with approval |
| 7 | Every IF output connected or explicitly logged |
| 8 | Provider errors cannot escalate severity |
| 9 | Synthetic and live-like regression tests passing in CI |
| 10 | Execution retention and redaction configured and documented |
| 11 | Rotation of all previously exposed credentials recorded |
| 12 | Audit re-run against the live workflow with authorised access |

---

## 7. Related documents

- [01 — Project overview](01-project-overview.md)
- [04 — Code audit](04-code-audit.md)
- [09 — Hermes AI integration](09-hermes-ai-integration.md)
- [12 — Testing and validation](12-testing-and-validation.md)
- [14 — Security](14-security.md)
- [16 — Audit report](16-audit-report.md)
