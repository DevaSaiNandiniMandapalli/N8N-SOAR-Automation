# 16 — Audit Report

| Item | Value |
|---|---|
| Document | Complete technical audit report and findings register |
| Version | 1.0 |
| Date | 2026-11-10 |
| Workflow | `Enterprise SOC SOAR Pipeline` (`ORQ4n82CacFdx45s` in the raw export) |
| Scope | 31 nodes, 36 connections, 13 Code nodes (~2,960 lines) |
| Method | Static analysis + read-only service probes |
| Live execution | Not performed |
| Live workflow modified | No |
| Findings | 4 critical, 8 high, 9 medium, 6 low (27 total) |

---

## 1. Executive summary

The workflow is a substantial, well-structured SOAR prototype. It covers the full
detection-to-response lifecycle: Wazuh ingestion, field normalisation, IOC extraction,
deduplication, six-provider threat-intelligence enrichment, external/internal incident
assembly, correlation, a report with an unusually detailed "alert scene", a decision
gate, case creation and multi-channel notification.

The audit found **27 issues**, four of them critical:

- **C-01** Ten credential-like values plus three workflow identifiers were embedded in
  the raw export. They are removed from this repository but must be rotated at source.
- **C-02** The authoritative Laya decision call is made from a Code node, which n8n
  documents as unable to make HTTP requests. The integration is therefore likely
  non-functional and the fail-safe escalates everything.
- **C-03** `Final Report` throws a `ReferenceError` whenever `source_ip` is falsy.
- **C-04** The webhook is unauthenticated, unthrottled and unvalidated.

Eight high findings concern incomplete containment, dead-end branches, three competing
severity calculations, unreliable deduplication, ThreatFox error handling that can force
CRITICAL, broken hash enrichment, non-monotonic IRIS mapping, and retention/error-handling
gaps. Nine medium and six low findings cover extraction coverage, provider parsing,
message formatting, trust assumptions and maintainability.

**No Hermes AI integration and no HMAC-SHA256 implementation were found.** The workflow
contains a Laya client only. This is documented in [09](09-hermes-ai-integration.md)
without inventing missing details.

The sanitized repository is safe to store privately. The workflow should **not** be
activated in production until the P0 items in the roadmap are complete.

---

## 2. Scope and methodology

### 2.1 In scope

- All 31 nodes and 36 connections.
- All 13 Code nodes, line by line.
- Every non-code node parameter, expression, header, body and condition.
- External and internal analysis branches, including unconnected outputs.
- Threat-intelligence request construction, response parsing and scoring.
- Deduplication, IOC extraction, aggregation and normalisation.
- Correlation, severity derivation, report generation and IRIS payload mapping.
- Notification and containment integrations.
- Secret handling, sanitisation and structural validation.

### 2.2 Out of scope

See [15 — Limitations](15-limitations-and-roadmap.md), items A1–A8. In brief: no live
execution, no authenticated n8n access, no engine source, no POST to `/api/triage`, no
screenshots, no load/penetration test.

### 2.3 Evidence

| Evidence | Status |
|---|---|
| Raw n8n export | Authoritative; **never published** |
| Sanitized export | `workflows/enterprise-soc-soar-pipeline.sanitized.json` |
| Exact Code extracts | 13 `.js` files, ~2,960 lines, in the audit workspace |
| Non-code node dump | All parameters, secrets masked |
| Sanitisation report | `docs/sanitization-report.json` |
| Validation scripts | `scripts/*.py` |
| Unit tests | `tests/test_workflow.py` |
| Service probes | Read-only GET/HEAD/OPTIONS to the Laya engine; 401 on n8n REST |

### 2.4 Method

```text
1. Verify access to the live workflow and the local export (IDs match).
2. Parse the export; enumerate nodes, connections and flags.
3. Extract all jsCode verbatim; run node --check; review line by line.
4. Map every expression, condition, branch and integration.
5. Trace one synthetic alert through every path.
6. Search for Hermes/HMAC locally, in the export, on GitHub and in the live console.
7. Sanitize, verify 0 survivors, write documentation and validation tooling.
8. Run validation, syntax checks, secret scan and unit tests; fix failures.
9. Review Git status/diff, commit, then publish privately.
```

---

## 3. Inventory and metrics

| Metric | Value |
|---|---|
| Nodes | 31 |
| Connections | 36 |
| Code nodes | 13 |
| Code lines | ~2,960 |
| Code size | ~78 KB |
| HTTP Request nodes | 9 |
| IF nodes | 3 |
| Merge nodes | 2 |
| Webhook triggers | 1 |
| Code nodes with `retryOnFail: true, maxTries: 3` | 13 |
| HTTP/notification nodes with `continueRegularOutput` | 11 |
| Unconnected IF outputs | 2 |
| TI providers | 6 |
| Chat channels | 3 |
| Case-management integrations | 1 |
| Containment integrations | 1 (incomplete) |
| Native AI/LLM nodes | 0 |
| Tracked values removed by sanitisation | 13 |
| Findings | 27 |

---

## 4. Findings register

Severity is based on impact on confidentiality, integrity of the triage decision, and
availability of the response pipeline. Status is **Open** for all findings in the
exported workflow; the sanitized repository mitigates only the publication risk (C-01).

### 4.1 Critical (4)

| ID | Title | Evidence | Impact | Remediation | Status |
|---|---|---|---|---|---|
| C-01 | Hard-coded credentials and identifiers in the raw export | 6 TI API keys, 2 bearer tokens, Discord webhook URL, Telegram chat ID, 3 workflow identifiers; plus private/public hosts, credential IDs and `webhookId` | Disclosure enables quota theft, case injection, chat posting and firewall config access | Rotate all values; use n8n credentials; keep raw export out of Git | **Open — rotation required** (publication risk mitigated) |
| C-02 | Laya HTTP call inside a Code node | `Laya Decision Gate` lines 63–74 use `fetch` / `this.helpers.httpRequest`; n8n docs: Code nodes cannot make HTTP requests | Authoritative engine never consulted; fail-safe escalates every level-8+ alert; no HMAC; top-level `await` fails plain CJS check | Replace with HTTP Request node + interpreter; add timeout, TLS and signing once the contract is known | Open |
| C-03 | `ReferenceError` in `Final Report` | Line 231: `sourceIp \|\| (d.srcuser \|\| 'local')` — `d` is undefined | Alerts with a falsy source IP fail report generation after 3 retries; no IRIS case or notifications | Replace `d.srcuser` with a resolved `srcuser`; add timestamp to the ref; add a unit test with `source_ip: null` | Open |
| C-04 | Unauthenticated, unthrottled webhook | `Webhook` `options: {}`; no auth, allowlist, rate limit, size limit or schema validation | Anyone who can reach n8n can inject alerts, burn six paid API calls per request, create cases/chat messages and trigger FortiGate attempts; `"test": true` bypasses dedup | Header Auth/JWT/mTLS, IP allowlist, rate limit, body limit, schema validation, explicit `202` | Open |

### 4.2 High (8)

| ID | Title | Evidence | Impact | Remediation |
|---|---|---|---|---|
| H-01 | FortiGate containment not implemented | No `method` set → GET; body only creates `SOC_<ip>` address object; `allowUnauthorizedCerts: true` | No traffic is blocked; bearer token exposed to MITM; no rollback or verification | POST/PUT + deny policy, approval gate, verification, rollback, TLS verification |
| H-02 | Dead-end response branches | `Severity Confirmation` has no false output; `Is Public IP?` false output is `[]` | MEDIUM/LOW and private/missing-IP incidents skip containment with no audit record | Connect both outputs to explicit closure/log nodes |
| H-03 | Competing severity calculations | TI Aggregator, Internal Incident, Corroboration and `Severity` disagree; `Severity` overwrites corroboration | Internal level 10–11 → MEDIUM not HIGH; 12–14 → HIGH not CRITICAL; three different values for one alert | One `assess()` function; published decision table |
| H-04 | Unreliable deduplication | `$getWorkflowStaticData('global')`, 3-min window, non-atomic, per workflow; regex `235\d` matches `2350`–`2359`, `8661[123]` matches `86611`–`86613` | Duplicate work under bursts; high-volume families not collapsed; test/multi-instance executions bypass | Shared TTL store with atomic check-and-set; fix regexes; emit suppression metrics |
| H-05 | ThreatFox errors force CRITICAL | Aggregator maps any `query_status !== "no_result"` to `success`; `Severity` line 95 forces CRITICAL on `tf.status === "success"`; ThreatFox adds 0 risk | A bad key or rate limit makes every enriched alert CRITICAL, potentially triggering containment | Explicit status enum; `success` only for `ok` with non-empty data |
| H-06 | Hash/URL/domain enrichment broken | VT `/ip_addresses/<hash>`; OTX/GreyNoise/LeakIX use `source_ip`; ThreatFox searches `source_ip`; `ioc.public_ips` removed by IOC Routing | File-hash and domain IOCs are never correctly enriched | Provider routing by IOC type with hash/domain/URL endpoints |
| H-07 | IRIS payload mapping defects | CRITICAL 6, HIGH 5, MEDIUM 1, LOW 4; `alert_customer_id: 1`; `alert_source_ref` has no timestamp | LOW may outrank MEDIUM; wrong customer; repeated alerts collide | Verify IRIS IDs, make monotonic, configure IDs, add timestamp/alert ID |
| H-08 | Retention and error-handling gaps | No execution pruning in export; `errorWorkflow` not exported; all notification nodes `continueRegularOutput`; no structured metrics | Full Wazuh payloads retained; failures invisible; no global error handler | Enable pruning/redaction; add error workflow, metrics and delivery-failure alerting |

### 4.3 Medium (9)

| ID | Title | Evidence | Remediation |
|---|---|---|---|
| M-01 | Narrow IOC extraction coverage | 26-TLD allowlist; IPv4 only; file-extension denylist largely redundant | Use a maintained public suffix list; add IPv6; validate IOCs |
| M-02 | First public IP may be a destination; IOC priority public IP > URL/domain/hash | `publicIpList[0]`; `scan()` walks the whole alert; Routing takes first candidate | Distinguish `srcip`/`dstip`; choose IOC by type; preserve provenance |
| M-03 | Misleading provider coverage and failures | `provider_coverage` counts `unavailable` as checked; `provider_failures` maps to indices (line 522) | Count only successful checks; return provider names and status codes |
| M-04 | LeakIX shape and error handling | Success requires flat `services`/`summary`/`host`; only `data.error` with `ETIMEDOUT`/`leakix` text handled | Inspect real response; map all errors to `unavailable` |
| M-05 | Duplicate object keys in `Incident Summary` | `rule_id`, `original_alert`, `raw_log` declared at lines 580–582 and 609–611 | Remove duplicates; enable `no-dupe-keys` lint |
| M-06 | Telegram internal branch literal string | `` `SOC INCIDENT REPORT' + idLine + ' `` — ID line never rendered | Use `${idLine}` interpolation |
| M-07 | Laya payload data exposure and no timeout | Full `raw_alert` over plain HTTP; no `AbortSignal`/timeout despite `.env.example` | Minimise fields, use HTTPS, configure timeout |
| M-08 | Silent dedup suppression and broad test bypass | `return []`; `data.test`/`body.test`/`original_alert.test` bypass dedup | Emit a structured suppression record; restrict test bypass to non-production |
| M-09 | Unvalidated alert values in URLs and JSON strings | VT/OTX/GreyNoise/LeakIX URL expressions; FortiGate `jsonBody` string; ThreatFox body; chat messages | Strict IP validation, URL encoding, structured bodies, per-format escaping |

### 4.4 Low (6)

| ID | Title | Evidence | Remediation |
|---|---|---|---|
| L-01 | Trusted ISP substring matching | `isp.toLowerCase().includes(name)`; downgrades level-15 CRITICAL to HIGH | Use ASN allowlist; never downgrade maximum-severity rules |
| L-02 | Incomplete public-IP regex | CGNAT, documentation ranges, `198.18/15`, broadcast and `N/A` not excluded | Validate IPs with a library; explicit non-public range list |
| L-03 | No output escaping | Slack mrkdwn, Telegram HTML, FortiGate JSON string | Escape per format; build JSON as objects |
| L-04 | Maintainability | Unused variables, duplicate `laya_primary`/`gatekeeper`, 249-line inline ISO map, no linting/tests | Extract helpers, add linting and unit tests |
| L-05 | Inconsistent provider error semantics | `alwaysOutputData` only on VT/OTX; error items ignored by aggregator | Uniform `alwaysOutputData` and error mapping |
| L-06 | No operational documentation in the workflow | No node notes, sticky notes, structured logging, metrics or runbook | Add notes, metrics and a runbook |

---

## 5. Detailed critical and high analysis

### C-01 — Credential exposure

`find_secret_parameters` in the sanitizer tracked 13 values: eight credential-bearing
header/query values (six TI keys plus the FortiGate and IRIS bearer tokens), one Discord
webhook URL, one Telegram chat ID, and three workflow-level identifiers (`versionId`,
`meta.instanceId`, `settings.errorWorkflow`). Infrastructure addresses, credential IDs,
`webhookId` and the workflow `id` were also present and were removed.

The sanitized export contains `REPLACE_WITH_*` placeholders only. Verification:
`surviving_original_secrets = 0`, `unredacted_pattern_findings = 0`, and an independent
repository scan found `findings = 0` across 38 files.

**This does not revoke the values.** Rotation is mandatory and is recorded as an open
action in `SECURITY.md`.

### C-02 — Laya transport

`Laya Decision Gate` lines 63–74 attempt `fetch` or `this.helpers.httpRequest`. The
official n8n Code node documentation states Code nodes cannot make HTTP requests and
recommends an HTTP Request node. A plain CommonJS `node --check` fails at line 64 with
`await is only valid in async functions and the top level bodies of modules`; the
wrapped check passes, showing only that the source is syntactically valid in a
function context, not that the runtime capability exists.

If neither API exists, `layaDecision` remains `null` and line 86 defaults the action to
`ESCALATED` without even an `ENGINE_UNAVAILABLE` verdict. If either throws, the fail-safe
escalates any level-8+ or HIGH/CRITICAL alert. In both cases the engine is bypassed.

### C-03 — Report generation crash

`Final Report` line 231:

```js
alert_source_ref: `soar-${ruleId}-${agentName}-${sourceIp || (d.srcuser || 'local')}`,
```

`d` is a local variable inside `buildSceneLines` and is not in scope here. `||`
short-circuits only when `sourceIp` is truthy. Internal alerts and alerts without
`data.srcip` therefore throw. The node retries three times (9 seconds) before the
execution fails. No IRIS case or chat message is produced.

### C-04 — Ingress

`Webhook` has `httpMethod: POST`, `path: wazuh-alerts`, `options: {}`. No authentication,
IP allowlist, rate limit, body limit or schema validation. Combined with the six parallel
provider calls and four response calls, one unauthenticated request can consume
significant quota and generate notifications. The dedup test bypass (`"test": true`)
further guarantees enrichment on every request.

### H-01 / H-02 — Containment and dead ends

FortiGate defaults to GET, so the JSON body is not sent. Even corrected, only an address
object is created; no policy, no deny action, no verification, no rollback. Both IF false
outputs are dead ends (one missing, one empty), so MEDIUM/LOW and private-IP incidents
have no containment branch and no explicit closure record.

### H-03 — Severity divergence

See the worked scenarios in [08](08-correlation-and-severity.md). Four computations
produce up to three different severities for one alert. The final `Severity` node wins.

### H-05 — ThreatFox false CRITICAL

The aggregator maps `query_status === "no_result" ? "no_result" : "success"`. ThreatFox
error statuses are therefore "success". `Severity` then forces CRITICAL. A misconfigured
key can escalate every enriched alert.

---

## 6. Positive observations

| # | Observation |
|---|---|
| 1 | The workflow is complete and importable: 31 nodes, 36 edges, 0 broken references, no disabled nodes |
| 2 | `Final Report.buildSceneLines` produces genuinely useful analyst context from many Wazuh/Suricata/Windows/Office 365 fields |
| 3 | All six TI providers use `continueRegularOutput`, so one API failure does not abort the branch |
| 4 | The Laya fail-safe escalates rather than drops alerts — correct safety posture |
| 5 | `firstStr`/`firstNum` fallback helpers in the Laya gate are defensive |
| 6 | IOC Extraction has a recursion depth cap, JSON-string body parsing and Set-based deduplication of IOCs |
| 7 | Both incident branches converge on a shared `{ incident: ... }` schema |
| 8 | `severity_factors` in the `Severity` node is a good auditability artefact |
| 9 | Node `typeVersion` values are pinned, which helps reproducibility |
| 10 | No community/custom nodes and no npm imports reduce supply-chain surface |
| 11 | Laya correlation IDs are propagated into IRIS tags and source refs |
| 12 | The sanitization process is reproducible and verified |

---

## 7. Verification log

| Check | Command / source | Result |
|---|---|---|
| Sanitisation | `scripts/sanitize_workflow.py` | `nodes=31 edges=36`, `original_secret_count=13`, `surviving_original_secrets=0`, `unredacted_pattern_findings=0` |
| Structure + syntax | `scripts/validate_workflow.py` | `placeholders=17`, `code_nodes=13`, `syntax_cjs_ok=12/13`, `syntax_esm_ok=0/13`, `syntax_wrapped_ok=13/13`, `VALIDATION=PASS` |
| Code extracts | `node --check` (CommonJS) | 12 OK; Laya fails on top-level `await` (documented portability warning) |
| Secret scan (worktree) | `scripts/secret_scan.py --root .` | `files_scanned=38`, `findings=0` |
| Secret scan (Git history) | `scripts/secret_scan.py --root . --history` | `git_history_scanned=yes`, `findings=0` |
| Unit tests | `python -m unittest discover -s tests -v` | 19 tests, `OK` |
| Live workflow read | GET editor/REST/API | SPA shell; `401 Unauthorized`; no credentials used |
| Laya probes | GET health/stats; HEAD/OPTIONS triage | Engine v6.2 online; `/api/triage` 404/501; no POST sent |
| Hermes/HMAC search | Export, local files, GitHub, console | 0 Hermes matches; 0 HMAC matches; no signing implementation found |
| Screenshots | n8n UI | Unavailable (auth required); none fabricated |

---

## 8. Residual risk

| Risk | Level | Notes |
|---|---|---|
| Previously exposed credentials not yet rotated | High | Sanitisation does not revoke |
| Unauthenticated webhook reachable | Critical | Until C-04 is fixed |
| False CRITICAL from ThreatFox errors | High | Until H-05 is fixed |
| Silent Laya bypass / alert flood | High | Until C-02 is fixed |
| FortiGate believed to block traffic when it does not | High | Until H-01 is fixed and communicated |
| Severity inconsistency mis-triaging incidents | High | Until H-03 is fixed |
| Execution history containing sensitive Wazuh logs | Medium | Until H-08 retention settings are applied |
| Live configuration differs from the export | Medium | A1 — authenticated live read not available |
| Merge2 / `fetch` runtime behaviour | Medium | U1/U2 — requires runtime verification |

---

## 9. Remediation priority

| Priority | Findings |
|---|---|
| P0 | C-01 (rotation), C-02, C-03, C-04 |
| P1 | H-01, H-02, H-03, H-05, H-07, H-08, M-09 |
| P2 | H-04, H-06, M-01, M-02, M-03, M-04, M-05, M-06, M-07, M-08 |
| P3 | L-01 … L-06, U1–U10 verification |

Full roadmap and acceptance criteria are in
[15 — Limitations and roadmap](15-limitations-and-roadmap.md).

---

## 10. Attestation

This report is based on static analysis of the exported workflow and read-only service
probes performed on 2026-11-10. No live execution, no credential use and no write
operation against the n8n instance or the Laya engine occurred. Missing functionality
(Hermes, HMAC-SHA256, FortiGate blocking, screenshots) is reported as missing, not
inferred. Test results reported above were actually run; no result was invented.

---

## 11. Appendix A — Evidence file list

| File | Purpose |
|---|---|
| `workflows/enterprise-soc-soar-pipeline.sanitized.json` | Publishable workflow |
| `docs/sanitization-report.json` | Secret-removal verification |
| `scripts/sanitize_workflow.py` | Reproducible sanitisation |
| `scripts/validate_workflow.py` | Structure and syntax validation |
| `scripts/secret_scan.py` | Credential-pattern scanning |
| `tests/test_workflow.py` | 19 unit tests |
| `.github/workflows/validate.yml` | CI validation |
| `workflows/samples/*.json` | Synthetic fixtures |
| `docs/diagrams/*.mmd` | Mermaid diagram sources |
| `docs/03-node-reference.md` | All 31 nodes and 36 connections |
| `docs/04-code-audit.md` | All 13 Code nodes |
| `docs/09-hermes-ai-integration.md` | Hermes/HMAC search evidence |

The raw export and the audit workspace extracts are **not** part of this repository.

---

## 12. Appendix B — Documentation index

1. [Project overview](01-project-overview.md)
2. [System architecture](02-architecture.md)
3. [Node-by-node reference](03-node-reference.md)
4. [Code audit](04-code-audit.md)
5. [Data flow and execution](05-data-flow.md)
6. [Wazuh integration](06-wazuh-integration.md)
7. [IOC and threat intelligence](07-ioc-and-threat-intelligence.md)
8. [Correlation and severity](08-correlation-and-severity.md)
9. [Hermes AI and HMAC status](09-hermes-ai-integration.md)
10. [Notifications and response](10-notifications-and-response.md)
11. [Installation](11-installation.md)
12. [Testing and validation](12-testing-and-validation.md)
13. [Troubleshooting](13-troubleshooting.md)
14. [Security](14-security.md)
15. [Limitations and roadmap](15-limitations-and-roadmap.md)
16. This audit report
