# 04 — Code Node Audit

| Item | Value |
|---|---|
| Document | Line-by-line audit of all 13 Code nodes |
| Version | 1.0 |
| Date | 2026-11-10 |
| Method | Exact `jsCode` extracts, manual review, `node --check` (Node.js v24.21.0) |
| Execution | Not executed inside n8n |

---

## 1. Method and constraints

Each Code node's `jsCode` parameter was extracted verbatim from the workflow export into a
standalone `.js` file. The audit then:

1. Read every file in full.
2. Identified inputs (`$json`, `$input.first()`, `$input.all()`, `$('Node')` cross-node
   lookups, `$getWorkflowStaticData`), outputs and side effects.
3. Traced each conditional branch and fallback chain.
4. Checked for undefined identifiers, duplicate keys, unreachable code, type coercion,
   unvalidated input and unsupported runtime APIs.
5. Ran `node --check` on each file.

**Constraint.** `node --check` validates JavaScript syntax in a CommonJS context; it does
not emulate the n8n Code node sandbox. A passing check does not prove the node runs
correctly in n8n. Conversely, one file fails the check because it contains top-level
`await`; the n8n Code node may wrap code in an async function, so this is a **portability
warning**, not proof of an n8n error.

**No workflow execution was performed.** No runtime behaviour, provider response or
notification delivery was tested.

---

## 2. Inventory and verdict

| # | File / node | Lines | Mode | Reads | Returns | Syntax | Risk |
|---|---|---:|---|---|---|---|---|
| 1 | `01-Final-Report.js` / Final Report | 246 | all items | `$json` | `[{ json: {...} }]` | OK | **Critical** |
| 2 | `02-Severity.js` / Severity | 219 | all items | `$json` | `{ json: {...} }` | OK | High |
| 3 | `03-Incident-Summary.js` / Incident Summary | 641 | all items | `$input.first().json` | `[{ json: {...} }]` | OK | Medium |
| 4 | `04-TI-Aggregator.js` / TI Aggregator | 533 | all items | `$input.all()`, `$('IOC Extraction')` | `[{ json: result }]` | OK | High |
| 5 | `05-TI-Normalizer.js` / TI Normalizer | 96 | all items | `$input.first().json` | `[{ json: normalized }]` | OK | Low |
| 6 | `06-IOC-Extraction.js` / IOC Extraction | 659 | each item | `$json` | bare object | OK | Medium |
| 7 | `07-Internal-Analysis.js` / Internal Analysis | 52 | all items | `$json` | `[{ json: result }]` | OK | Low |
| 8 | `08-Internal-Incident.js` / Internal Incident | 51 | all items | `$input.first().json` | `[{ json: { incident } }]` | OK | Medium |
| 9 | `09-Dedup-Check.js` / Dedup Check | 55 | all items | `$input.first().json`, static data | `[{ json: data }]` or `[]` | OK | High |
| 10 | `10-TI-Corroboration-Scoring.js` / TI Corroboration & Scoring | 87 | all items | `$input.first().json` | `[{ json: { incident } }]` | OK | Medium |
| 11 | `11-External-Incident.js` / External Incident | 47 | all items | `$input.first().json` | `[{ json: { incident } }]` | OK | Low |
| 12 | `12-IOC-Routing.js` / IOC Routing | 138 | all items | `$input.first().json` | `[{ json: {...} }]` | OK | High |
| 13 | `13-Laya-Decision-Gate.js` / Laya Decision Gate | 136 | all items | `$input.first().json` | `[{ json: {...} }]` or `[]` | **CJS fail** | **Critical** |
| | **Total** | **2,960** | | | | **12 OK / 1 warning** | |

`node --check` output summary:

```text
OK   01-Final-Report.js
OK   02-Severity.js
OK   03-Incident-Summary.js
OK   04-TI-Aggregator.js
OK   05-TI-Normalizer.js
OK   06-IOC-Extraction.js
OK   07-Internal-Analysis.js
OK   08-Internal-Incident.js
OK   09-Dedup-Check.js
OK   10-TI-Corroboration-Scoring.js
OK   11-External-Incident.js
OK   12-IOC-Routing.js
FAIL 13-Laya-Decision-Gate.js: SyntaxError: await is only valid in async functions
                              and the top level bodies of modules (line 64)
```

The validator in this repository re-runs this check and additionally re-checks the Laya
file as an ES module (`--input-type=module`) so top-level `await` is accepted. Both
results are recorded rather than hidden.

---

## 3. Cross-cutting code findings

### 3.1 Runtime API assumptions

| Assumption | Where | Reality |
|---|---|---|
| `fetch` is available in the Code node sandbox | Laya Decision Gate line 63 | n8n documents that Code nodes cannot make HTTP requests |
| `this.helpers.httpRequest` is available | Laya Decision Gate line 69 | Helper is not a documented Code node API |
| `await` at top level is accepted | Laya Decision Gate line 64 | Works only if n8n wraps the code in an async module/function; unverified |
| `$getWorkflowStaticData('global')` is shared and durable | Dedup Check line 5 | Per-workflow static data; not shared across instances; unreliable in manual executions |
| `$('Node').first().json` always resolves | TI Aggregator, Discord, Telegram, Slack | Guarded with `try/catch` in some places, not all |

### 3.2 Input handling

- All nodes assume a **single input item** (`$input.first().json`) except TI Aggregator
  (`$input.all()`) and IOC Extraction (per-item mode). Extra items are silently dropped.
- Several nodes read both the flat mapped fields and the nested `body` object. IOC
  Extraction writes `original_alert`, but later nodes re-derive it; there are three
  different alert-resolution strategies across the codebase.
- No node validates that `rule.level` is a number, `srcip` is an IP, or `groups` is an
  array. `Number(null)` is `0`, `String(undefined)` is `'undefined'`.
- Defaults such as `'blusoc'`, `'127.0.0.1'`, `'N/A'` and `'n/a'` are mixed, so missing
  data appears differently in different outputs.

### 3.3 Output contract inconsistency

| Node | Emits |
|---|---|
| IOC Extraction | bare object (valid in Run Once for Each Item) |
| Severity | bare object `{ json: {...} }` |
| Others | array `[{ json: {...} }]` |

n8n accepts both forms, but the inconsistency makes unit testing and reuse harder. A
single helper (`return [{ json: ... }]`) would remove ambiguity.

### 3.4 Error handling

- All 13 Code nodes have `retryOnFail: true, maxTries: 3, waitBetweenTries: 3000` in the
  workflow. Deterministic bugs (undefined variable, shape mismatch) are retried three
  times with no change in input, adding latency and duplicate log entries.
- Only `TI Aggregator` and the notification expressions use `try/catch` around cross-node
  lookups. There is no `try/catch` around provider response parsing.
- No node emits a structured error object that a downstream node could route to a
  dead-letter path.

### 3.5 Maintainability

- No TypeScript, no JSDoc types, no linting, no unit tests in the original workflow.
- Four places compute severity or risk: TI Aggregator, TI Corroboration & Scoring,
  Incident Summary (fallback), and Severity. Their thresholds disagree.
- Duplicate object keys, unused variables (`greyNoise`, `leakixUnavailable`,
  `successfulProviders`), and a 249-entry inline ISO country map in TI Aggregator.
- String templates are used to build JSON bodies in notification expressions; no escaping
  helper is shared across nodes.

---

## 4. Node 1 — Final Report (246 lines)

### 4.1 Inputs and outputs

- **Reads:** `$json`, specifically `data.severity`, `data.incident` and nested
  `incident.original_alert`.
- **Returns:** one item with `report`, `severity`, `iris_description`, `iris_payload`.
- **Downstream:** Laya Decision Gate reads `data.report`, `data.iris_payload`.

### 4.2 Structure

| Lines | Function |
|---|---|
| 1–20 | Resolve severity, rule level, rule ID, agent, Wazuh alert ID, description, source IP, risk score, confidence, verdict, analysis type, TI, evidence and raw log |
| 24–101 | `buildSceneLines(a)` — analyst scene extractor |
| 103–105 | Resolve `sceneAlert` and `sceneLines` |
| 106–148 | Internal branch description template |
| 150–195 | External branch description template with TI scorecard |
| 197–225 | `report` object |
| 227–236 | `iris_payload` object |
| 238–245 | Return |

### 4.3 `buildSceneLines` coverage

The function is the strongest part of the codebase. It reads `agent`, `rule`, `data`,
`data.alert` (Suricata-style), `data.http`, `data.win.eventdata`, `data.flow`,
`data.office365`, `data.vulnerability`, `data.syscheck`, `r.mitre`, `a.location` and
`a.full_log`. It handles arrays with `one()` and truncates raw events to 1,400
characters. This produces genuinely useful analyst context.

### 4.4 Defects

**C-03 — undefined identifier `d` (line 231).**

```js
alert_source_ref: `soar-${ruleId}-${agentName}-${sourceIp || (d.srcuser || 'local')}`,
```

`d` is not declared anywhere in the file. `d` was a local variable inside
`buildSceneLines` (`const r = a.rule || {}, d = a.data || {}` on line 26), but that scope
is not visible here. Because `||` short-circuits, the expression is safe **only** when
`sourceIp` is truthy. Internal alerts and alerts with no `data.srcip` produce a falsy
`sourceIp`, evaluate the fallback, and throw `ReferenceError: d is not defined`.

Impact: report generation fails; the node retries three times; the execution ends in
error; no notifications or IRIS case are created for that alert.

Fix: remove the `d` reference or use the already-resolved report field:

```js
const sourceRef = sourceIp || String(srcuser ?? 'local');
alert_source_ref: `soar-${ruleId}-${agentName}-${sourceRef}-${Date.now()}`,
```

**H-07 — non-monotonic IRIS severity IDs (line 232).**

```js
alert_severity_id: (severity === 'CRITICAL') ? 6 : (severity === 'HIGH') ? 5
                 : (severity === 'MEDIUM') ? 1 : 4,
```

LOW maps to 4 while MEDIUM maps to 1. Unless IRIS uses exactly this non-obvious ID
scheme, LOW incidents will be triaged above MEDIUM ones. The mapping is undocumented and
should be verified against the IRIS instance's severity table.

**Also (line 234):** `alert_customer_id: 1` is hard-coded; `alert_source_ref` has no
timestamp, so repeated alerts for the same rule/agent/IP can collide or be deduplicated by
IRIS.

**M-06-adjacent:** `recommendationText` for non-`TRUE_POSITIVE_THREAT` external alerts
mentions "SOC training/reconnaissance alert" and "student analyst triage", assumptions
that are not valid for a production SOC.

### 4.5 Recommendations

- Add a unit test with `source_ip: null` to catch the `ReferenceError`.
- Move IRIS IDs and customer ID into configuration.
- Include a timestamp or Wazuh alert ID in `alert_source_ref`.
- Split the node into `buildSceneLines`, `renderReport` and `buildIrisPayload` helpers.

---

## 5. Node 2 — Severity (219 lines)

### 5.1 Structure

| Lines | Function |
|---|---|
| 1–34 | Read rule level, risk score and six provider objects; coerce numbers |
| 40–64 | Build `maliciousSignals` and `corroboratingSources` |
| 74–82 | Base severity from Wazuh rule level |
| 86–130 | Five escalation rules |
| 140–177 | Trusted ISP downgrade |
| 184–219 | Return `severity` and `severity_factors` |

### 5.2 Signals

```text
GreyNoise  classification === "malicious"
AbuseIPDB  score >= 80
VirusTotal malicious > 0
OTX        pulses > 0
ThreatFox  status === "success"
```

`greyMalicious`, `greyNoise`, `threatFoxHit` and `leakixUnavailable` are computed;
`greyNoise` and `leakixUnavailable` are only surfaced in `severity_factors` and do not
affect the score.

### 5.3 Defects

**H-03 — overrides corroboration.** The node starts from the Wazuh rule level, not from
`incident.severity`. Consequences:

| Incoming (from Corroboration) | Rule level | Final Severity |
|---|---|---|
| HIGH (internal level 10–11) | 10 | **MEDIUM** |
| CRITICAL (internal level 12–14) | 12 | **HIGH** |
| CRITICAL (external, risk ≥80) | 5 | CRITICAL only if risk ≥80 and ≥3 sources, or ThreatFox hit |
| HIGH (external, single AbuseIPDB ≥80) | 5 | HIGH via single strong signal |

**H-05 — ThreatFox error → CRITICAL.** `tf.status === "success"` is set by the aggregator
for any ThreatFox `query_status` other than `no_result`, including API errors. Line 95
then forces CRITICAL. A misconfigured or rate-limited ThreatFox key can therefore make
every enriched alert CRITICAL.

**L-01 — trusted ISP substring match.** `isp.toLowerCase().includes(name)` matches
`Cloudflare` inside any ISP string. It applies only when there is no malicious evidence,
but it can downgrade a rule-level-15 CRITICAL alert to HIGH (line 170).

**Unused variables:** `vtSuspicious`, `greyNoise`, `leakixUnavailable` are reported but
not used in decisions.

### 5.4 Recommendations

Create one `deriveSeverity(incident)` function used by all nodes; make IRIS mapping
monotonic; treat provider errors as `unavailable`, not `success`; test the severity matrix
in [08 — Correlation and severity](08-correlation-and-severity.md).

---

## 6. Node 3 — Incident Summary (641 lines)

### 6.1 Structure

The longest Code node. It is a defensive schema rebuild:

| Lines | Function |
|---|---|
| 19–46 | Input, `safeString`, `safeArray`, `safeNumber` |
| 52–91 | Basic context and IOC |
| 97–123 | Read six provider objects |
| 132–~280 | Rebuild `threat_intelligence` preserving both naming conventions |
| ~280–340 | Internal analysis and assessment rebuild |
| 381–429 | Preserve incoming severity or derive from rule level |
| ~430–570 | Build summary/evidence strings and confidence |
| 578–641 | Return object |

### 6.2 Defect

**M-05 — duplicate object keys.** The returned incident declares:

```js
// lines 580-582 (with fallbacks)
original_alert: incidentInput.original_alert ?? null,
rule_id: incidentInput.rule_id ?? incidentInput.internal_analysis?.rule_id ?? incidentInput.original_alert?.rule?.id ?? null,
raw_log: incidentInput.raw_log ?? incidentInput.original_alert?.full_log ?? null,

// lines 609-611 (overwrite)
rule_id: incidentInput.rule_id,
original_alert: incidentInput.original_alert,
raw_log: incidentInput.raw_log,
```

In JavaScript the later keys win. If `incidentInput.rule_id` is `undefined`, the fallback
that would have recovered it from `internal_analysis` or `original_alert` is discarded.
The same applies to `raw_log`. This can produce `null` rule IDs in the final report.

### 6.3 Other observations

- Lines 141–149 deliberately keep both `confidence_score` and `score` for AbuseIPDB so
  the Telegram expression works — good compatibility awareness.
- Severity is preserved if present (line 392 comment). This node therefore rarely
  changes severity.
- The node returns `[]` when the incident is not an object (line 22–24), which silently
  drops the alert with no audit record.

### 6.4 Recommendations

Remove the second set of keys, add a lint rule (`no-dupe-keys`), and add a unit test with
missing `rule_id` to prove the fallback works.

---

## 7. Node 4 — TI Aggregator (533 lines)

### 7.1 Structure

| Lines | Function |
|---|---|
| 1–13 | `$input.all()` and `$('IOC Extraction').first().json` in `try/catch` |
| 20–88 | Base result with six `not_checked` providers |
| 95–105 | `addSource`, `addEvidence` |
| 112–393 | Loop over provider items with shape detectors |
| 155–185 | 249-entry ISO country map |
| 400–404 | Clamp risk score to 0–100 |
| 411–439 | `provider_coverage` |
| 450–488 | `assessment_confidence` from malicious signals |
| 495–503 | Severity from risk score |
| 510–522 | Summary flags and `provider_failures` |
| 529–533 | Return |

### 7.2 Defects

**H-05 — ThreatFox status collapse (lines 306–327).**

```js
const status = data.query_status === "no_result" ? "no_result" : "success";
```

Error statuses become `success`. The aggregator adds an evidence string "ThreatFox
returned an IOC result" and adds zero risk points, but `Severity` later sees
`status === "success"` and forces CRITICAL. Fix: map explicit statuses, for example
`success` only when `query_status === "ok"` and `data` is non-empty; everything else
becomes `unavailable` or `no_result`.

**M-03 — `provider_failures` are indices (lines 516–522).**

```js
.map((provider, index) => index)
```

The array should contain provider names. Downstream, `Incident Summary` and
`External Incident` pass these numbers through, and `Final Report` prints nothing useful.
`provider_coverage` also counts `unavailable` providers as "checked" (lines 419–425),
inflating coverage when a provider is down.

**M-04 — LeakIX shape and error handling (lines 334–392).** Success requires a top-level
`services`, `summary` or `host`. The LeakIX `/host/` endpoint may return an array or a
nested object, in which case the node stays `not_checked`. Error detection only handles
`data.error` with `ETIMEDOUT` or a message containing "leakix"; other HTTP failures are
not mapped.

**M-09 — provider error items.** Because provider nodes use `continueRegularOutput`, HTTP
errors usually arrive as n8n error items (with `error`, `message`, `statusCode` fields),
not as `data.error`. The aggregator's error branch rarely fires.

**Unused `successfulProviders`** (lines 427–432) is computed and never used.

**Hard-coded ISO map** is 249 lines of data inside business logic; move to a lookup table
or use `Intl.DisplayNames` where available.

### 7.3 Provider shape detector risk

There is no provider identifier in merged items. If a provider changes its response
shape, or if an error response happens to contain a field such as `pulse_info`, parsing
silently misattributes data. A robust design would tag each item with its provider name
before Merge1 (for example with a Set node) and dispatch on that tag.

---

## 8. Node 5 — TI Normalizer (96 lines)

Pure reshape with `??` fallbacks; the lowest-risk Code node. It creates `alert`,
`threat_intelligence` and `assessment` objects and passes `sources` through.

Notable renames:

| Aggregator field | Normalized field |
|---|---|
| `abuseipdb.confidence` | `abuseipdb.confidence_score` |
| `abuseipdb.reports` | `abuseipdb.total_reports` |
| `assessment_confidence` | `assessment.confidence` |

**Minor issues.** `status` defaults to `not_checked` for all providers but `severity` and
`risk_score` default independently; there is no consistency check. No validation that
`threat_intelligence` is an object. No defect found that changes a decision.

---

## 9. Node 6 — IOC Extraction (659 lines)

### 9.1 Structure

| Lines | Function |
|---|---|
| 19–54 | Resolve alert from `input.body` (object or JSON string) with a safe fallback |
| 61–107 | `isValidIPv4`, `isPrivateIPv4`, `addString` |
| 114–118 | Five Sets for IOCs |
| ~120–244 | `processIP`, `processURL`, `processHash` and known-field scans |
| 254–281 | `VALID_TLDS` (26 entries) |
| 284–357 | `isPlausibleDomain` with a 30-entry file-extension denylist |
| 360–386 | `processDomain`, known domain fields |
| 393–453 | `scanText` regexes |
| 456–~568 | `scan(value, depth)` recursive traversal with depth cap 10 |
| 569–616 | Primary IOC priority |
| 623–631 | `ti_required` and `internal_analysis_required` |
| 638–659 | Return |

### 9.2 Defects

**M-01 — TLD allowlist.** Only 26 TLDs are accepted:
`com, net, org, io, co, in, uk, de, fr, us, ca, au, info, biz, xyz, online, site, app,
dev, cloud, me, tv, tech, pro, gov, edu`. Domains using `.ru`, `.cn`, `.br`, `.jp`, `.tk`,
`.top`, `.cc`, `.su` and most new gTLDs are discarded. The file-extension denylist is
largely redundant because those extensions are not in `VALID_TLDS`.

**M-01 — IPv4 only.** `isValidIPv4` requires exactly four numeric parts. IPv6 addresses
are ignored even though `Is Public IP?` has IPv6 exclusions.

**M-02 — first public IP wins.** `publicIpList[0]` is chosen regardless of whether the
address came from `srcip`, `dstip` or a URL. An outbound connection to a malicious IP can
be classified as an inbound attack from that IP.

**M-02 — priority ordering.** Public IP outranks URL, domain and hash. A hash-only alert
with any public IP in `full_log` will be enriched as an IP, not as the hash. IOC Routing
then also prefers a public IP over a hash.

**M-09 — unvalidated values flow into URLs.** Extracted values are used in provider URL
expressions without URL encoding. An IOC containing `/`, `?` or `#` can alter the request
path/query.

**Redundancy.** `ti_required` here is overwritten by IOC Routing. The two nodes disagree
on CGNAT `100.64/10` (extraction treats it as public, routing treats it as private).

### 9.3 Positive observations

- Depth cap prevents unbounded recursion.
- JSON-string `body` is parsed defensively.
- Sets prevent duplicate IOCs.
- `processHash` validates 32/40/64 hex lengths.
- Fallback object for non-object input prevents a crash.

---

## 10. Node 7 — Internal Analysis (52 lines)

Reads `data.body` / `original_alert` / `data`, then `alert.rule` and `alert.data`.
Extracts `user`, `target_user`, `command` and MITRE arrays. Coerces single MITRE values to
arrays (lines 11–13). Sets `analysis_type: "internal"` and builds the `alert` and
`internal_analysis` objects.

**Issues.**

- `source_ip` defaults to `'127.0.0.1'` and `agent_name` to `'blusoc'` (lines 21–23).
  These literals can reach the report and the Laya payload.
- `internal_analysis.required: true` is set but never read downstream.
- The `ioc` fallback object is only used when `data.ioc` is missing, but IOC Extraction
  always sets it.

No crash paths found.

---

## 11. Node 8 — Internal Incident (51 lines)

Builds `{ incident: {...} }`. Severity and risk score from rule level:
`>=15 CRITICAL/90`, `>=12 HIGH/70`, `>=8 MEDIUM/40`, else `LOW/10`. Builds a summary and
a least-privilege recommendation. Sets `assessment.verdict: 'INTERNAL_SECURITY_EVENT'`.

**Issues.**

- The verdict and severity are overwritten by `TI Corroboration & Scoring` and
  `Severity`. This node's work is largely discarded.
- User and target user default to `'system'` and `'root'` (lines 11–12), which may be
  misleading in the report.
- `raw_log` falls back through several paths but can still be `null`.

---

## 12. Node 9 — Dedup Check (55 lines)

### 12.1 Line-level notes

| Lines | Function |
|---|---|
| 4 | `DEDUP_WINDOW_MS = 180 * 1000` |
| 5–6 | `staticData = $getWorkflowStaticData('global')`; initialise `seenAlerts` |
| 8 | `$input.first().json` |
| 11–13 | Test bypass |
| 16–21 | Sweep expired keys |
| 24 | Alert resolution: `body` → `original_alert` → `data` |
| 25–29 | Identity fields |
| 35 | `HIGH_VOLUME` regex |
| 36–45 | Fingerprint selection |
| 48–50 | Suppress with `return []` |
| 53–54 | Mark seen and pass through |

### 12.2 Defects

**H-04 — regex bugs.**

```js
const HIGH_VOLUME = /^(235\d|19\d{3}|915\d{2}|8661[123])$/.test(ruleId);
```

- `235\d` matches exactly four characters: `2350`–`2359`. The comment says "vulnerability
  findings 235xx", which requires `235\d{2}`.
- `8661[123]` matches `86611`, `86612`, `86613`. The comment says "Suricata decode noise
  8661x", which requires `8661\d`.
- `19\d{3}` and `915\d{2}` are correct for five-digit IDs.

**H-04 — state durability.** Static workflow data is per workflow, not shared across n8n
instances, and manual/test executions do not persist it. The 3-minute window is swept
only when a new alert arrives, so `seenAlerts` can grow between bursts. There is no
atomic check-and-set, so two concurrent executions can both pass dedup.

**M-08 — silent suppression.** `return []` ends the branch with no record. Suppressed
alerts are invisible to IRIS, the Laya engine and any metric.

**Test bypass width.** `data.test`, `data.body.test` or `data.original_alert.test` bypass
dedup. A malicious caller who can reach the unauthenticated webhook can simply include
`"test": true` to guarantee enrichment on every request.

### 12.3 Recommendations

Use a shared store with TTL and atomic `SET NX` semantics (or an n8n-level queue), emit a
structured suppression record, log a counter, and fix the regexes to `235\d{2}` and
`8661\d`.

---

## 13. Node 10 — TI Corroboration & Scoring (87 lines)

### 13.1 Branch table

| Order | Condition | Verdict | Severity | Confidence |
|---|---|---|---|---|
| 1 | `ruleLevel < 7 && !hasMaliciousEvidence` | `BENIGN_TELEMETRY` | LOW | HIGH |
| 2 | `analysis_type === 'internal'` | `INTERNAL_SECURITY_EVENT` if level ≥10 else `BENIGN_INTERNAL_EVENT` | ≥12 CRITICAL, ≥10 HIGH, ≥8 MEDIUM, else LOW | HIGH / MEDIUM |
| 3 | external and (`hasMaliciousEvidence` or risk ≥50) | `TRUE_POSITIVE_THREAT` | CRITICAL if risk ≥80 or level ≥12, else HIGH | HIGH if ≥2 sources |
| 4 | otherwise | `UNCORROBORATED_OR_TRAINING` | ≥12 HIGH, ≥8 MEDIUM, else LOW | LOW |

All branches set `incident.laya_verification` with stage `"Secondary Verification"`.

### 13.2 Issues

- The header comment calls this "LAYA - METRIC & THREAT VERIFICATION" but it never calls
  Laya or any model. It is deterministic logic with a misleading name.
- Step 1 returns before `analysis_type` is considered, so a level-5 internal event with a
  real command is labelled benign telemetry.
- Step 3 writes `incident.assessment.verdict` without ensuring `incident.assessment`
  exists (step 2 creates it, step 1 does not reach here, step 4 assumes it exists). In the
  external path `External Incident` always creates `assessment`, so this is safe today but
  fragile.
- Severity output is overwritten by `Severity` (H-03).

---

## 14. Node 11 — External Incident (47 lines)

Pure wrapper. Builds `{ incident }` from the normalized `alert`, `threat_intelligence`
and `assessment`. Sets `analysis_type: 'external'`, `internal_analysis: null`,
`summary: null`, `recommendation: null`.

**Issue.** `assessment.verdict` is not copied from the aggregator (which does not set one),
so the first verdict in the external path comes from Corroboration. This is intentional
per the comment but worth documenting. `severity` defaults to `'LOW'` even though the
aggregator computed a severity; it reads `alert.severity`, which TI Normalizer set from
`data.severity`, so the value is passed through correctly.

---

## 15. Node 12 — IOC Routing (138 lines)

### 15.1 Structure

| Lines | Function |
|---|---|
| 12–36 | `isPrivateOrLocalIP` |
| 38–42 | `isValidHash` |
| 45–61 | Candidate IPs and first public IP |
| 64–84 | Candidate hashes and first valid hash |
| 87–94 | Local host event detection |
| 96–114 | Decision |
| 116–137 | Return |

### 15.2 Defects

**H-06 — hash path is never enriched correctly.** When `verifiedHash` triggers TI, all six
provider nodes still receive `source_ip` (routing line 134 sets
`source_ip = verifiedPublicIP ?? candidateIps[0] ?? null`) and
`ioc = { type: 'hash', value: hash }`. VirusTotal builds
`/ip_addresses/{{$json.ioc.value}}` — an IP endpoint with a hash. AbuseIPDB, OTX,
GreyNoise and Leakix use `source_ip`. ThreatFox searches `source_ip`, not the hash. A
hash-only alert therefore produces meaningless enrichment.

**M-02 — first candidate IP.** The loop takes the first non-private candidate from a list
that includes `data.srcip`, `src_ip`, `source_ip`, `srcip`, mapped `source_ip` and
`ioc.value`. It does not distinguish source from destination. Suricata alerts can carry
both.

**M-09 — no IP validation in `candidateIps`.** `isPrivateOrLocalIP` returns `true` for
non-strings and non-4-part strings, so an arbitrary string is treated as private and
skipped; but a crafted `100.64/10` value is rejected here while `IOC Extraction` would
call it public.

**Local host suppression.** `isLocalHostEvent` checks for groups `sudo`, `pam`, `syslog`,
`location === 'journald'`, or `data.srcuser`/`data.command`. A genuine external attack
logged with a `srcuser` field (for example an SSH brute force with a username) will have
TI bypassed entirely unless a hash is present.

**Two sources of truth.** `ti_required` from IOC Extraction is overwritten here. The
`laya_primary` and `gatekeeper` objects are near-duplicates.

### 15.3 Positive observations

- `isPrivateOrLocalIP` is more complete than IOC Extraction's version: it handles
  `localhost`, `::1`, `0.0.0.0`, CGNAT `100.64/10` and multicast.
- `isValidHash` validates length and hex characters.
- `firstStr`/`firstNum`-style fallback resolution is used consistently for IPs.

---

## 16. Node 13 — Laya Decision Gate (136 lines)

### 16.1 Structure

| Lines | Function |
|---|---|
| 1–8 | Header comment (v3.3, fail-safe description) |
| 10–12 | Read `report`, `incident` |
| 14–29 | `firstStr`, `firstNum` |
| 31–42 | Resolve rule level, ID, description, source IP, agent, severity, risk, srcuser |
| 44–59 | `triagePayload` (14 fields) |
| 61–84 | `fetch` / `this.helpers.httpRequest` call and fail-safe |
| 86–91 | Stop if not escalated |
| 93–112 | Enrich `iris_payload` with the decision record |
| 114–135 | Return `laya_gate` |

### 16.2 Critical defect — unsupported HTTP transport

n8n's official Code node documentation states explicitly:

> "You can't access the file system or make HTTP requests. Use the following nodes
> instead: Read/Write File From Disk, HTTP Request."

The node attempts both unsupported options:

```js
if (typeof fetch === 'function') {
  const res = await fetch('http://REPLACE_WITH_LAYA_HOST:9999/api/triage', {...});
  layaDecision = await res.json();
} else if (this.helpers && this.helpers.httpRequest) {
  layaDecision = await this.helpers.httpRequest({...});
}
```

If neither is available, `layaDecision` stays `null`; line 86 then evaluates
`layaDecision?.action ?? layaDecision?.decision ?? 'ESCALATED'` and the gate escalates
**without even producing an `ENGINE_UNAVAILABLE` verdict**. If either call throws, the
fail-safe runs. In both cases the authoritative engine is not consulted.

**Second problem:** `this` at the top level of a Code node is not the documented way to
access helpers, and top-level `await` is not valid in a plain CommonJS module. A
`node --check` confirms the syntax failure.

**Third problem:** no timeout. `LAYA_REQUEST_TIMEOUT_MS` appears in `.env.example` but is
not used by the code. A hung engine call could stall the execution until n8n's own
timeout.

**Correct design.** Replace this Code node with an **HTTP Request node** for
`POST /api/triage`, then a small Code node (or IF) to interpret the response. That gives
credentials, TLS, timeout, retry and error handling as first-class n8n features.

### 16.3 Fail-safe behaviour

```text
action = (ruleLevel >= 8 || severity HIGH/CRITICAL) ? ESCALATED : CLOSED_NO_IMPACT
verdict = ENGINE_UNAVAILABLE, confidence 0.50, layer 4
stage = "L4 Fail-Safe (engine unreachable)"
reason = "Laya engine unreachable: <error message>"
correlation_id = "lay-offline"
```

The fail-safe is sensible from a safety perspective (never drop a material alert), but it
means a broken integration silently converts every level-8+ alert into an escalated case
with a synthetic `lay-offline` correlation ID. Operators may not notice that the engine
is not actually deciding anything.

### 16.4 Authentication

**No HMAC.** No `Authorization`, `X-Signature`, `X-Timestamp`, nonce, digest or signature
computation appears anywhere in the 136 lines. The request is plain HTTP with only
`Content-Type: application/json`. See [09 — Hermes AI integration](09-hermes-ai-integration.md).

### 16.5 Data exposure

`raw_alert` is the full Wazuh event, which can include usernames, commands, file paths,
hostnames and raw log lines. It is sent over unencrypted HTTP to the engine. `groups` is
read from `report.raw_alert.rule.groups` or `incident.original_alert.rule.groups`.

### 16.6 Other observations

- `severity` is upper-cased here and used in the response, so `Severity Confirmation`'s
  strict comparison is consistent.
- `irisPayload.alert_source_ref` joins the original ref with `cid` using `|`, which is a
  reasonable correlation mechanism.
- `policy_version` defaults to `'5.0'` while the observed engine health reports version
  `6.2` and the HTTP server header says `Laya-Triage/5.1` — the default is stale and
  should come from the response.

---

## 17. Line-level defect register

| ID | Node | Lines | Defect | Severity |
|---|---|---|---|---|
| C-02 | Laya Decision Gate | 63–74, 86 | Unsupported HTTP call in Code node; engine never consulted | Critical |
| C-03 | Final Report | 231 | Undefined `d` in `alert_source_ref` fallback | Critical |
| H-03 | Severity | 74–130 | Recomputes severity, overriding corroboration | High |
| H-04 | Dedup Check | 35 | `235\d`, `8661[123]` regex bugs; static-data durability | High |
| H-05 | TI Aggregator / Severity | 306–310 / 95 | Any ThreatFox non-`no_result` status → CRITICAL | High |
| H-06 | IOC Routing | 100–113, 134 | Hash IOCs still routed to IP endpoints | High |
| H-07 | Final Report | 232–235 | Non-monotonic IRIS severity IDs, hard-coded customer, no timestamp | High |
| M-01 | IOC Extraction | 254–281 | 26-TLD allowlist, IPv4-only | Medium |
| M-02 | IOC Extraction / IOC Routing | 592–616 / 45–61 | First public IP may be a destination | Medium |
| M-03 | TI Aggregator | 419–439, 516–522 | Coverage counts `unavailable`; failures are indices | Medium |
| M-04 | TI Aggregator | 334–392 | LeakIX shape and error detection | Medium |
| M-05 | Incident Summary | 580–582, 609–611 | Duplicate object keys discard fallbacks | Medium |
| M-06 | Telegram expression | internal branch | Literal `' + idLine + '` instead of interpolation | Medium |
| M-07 | Laya Decision Gate | 44–59, 64–74 | Full raw alert over HTTP, no timeout | Medium |
| M-08 | Dedup Check | 48–50 | Silent suppression, no audit record | Medium |
| M-09 | Multiple | various | Unvalidated alert values interpolated into URLs and JSON bodies | Medium |
| L-01 | Severity | 140–177 | Trusted ISP substring matching | Low |
| L-02 | Is Public IP? (IF) | regex | Incomplete non-public range coverage | Low |
| L-03 | FortiGate / Slack / Telegram | bodies | No output escaping in JSON/Markdown/HTML | Low |
| L-04 | Multiple | various | Unused variables, duplicate logic, no linting | Low |
| L-05 | virus total / OTX | flags | `alwaysOutputData` may emit empty items | Low |
| L-06 | All nodes | — | No notes, structured logging, metrics or runbook | Low |

---

## 18. Recommended code-quality baseline

1. **One severity function.** Extract `deriveSeverity(incident)` and call it once.
2. **Typed provider adapters.** One function per provider with explicit status mapping:
   `ok | no_result | unavailable | error`.
3. **Tag provider items** before Merge1 so the aggregator dispatches by name, not shape.
4. **Replace the Laya Code node** with HTTP Request + interpreter nodes.
5. **Add unit tests** for every Code node using synthetic items (see
   [12 — Testing and validation](12-testing-and-validation.md)).
6. **Enable linting** (`no-undef`, `no-dupe-keys`, `no-unused-vars`) in CI.
7. **Centralise configuration** (IRIS IDs, customer ID, thresholds, TLD list, trusted
   ISPs, timeouts) in environment variables or n8n workflow static data.
8. **Never interpolate unescaped alert data** into URLs or JSON strings; use structured
   body builders.

---

## 19. Related documents

- [03 — Node reference](03-node-reference.md)
- [07 — IOC and threat intelligence](07-ioc-and-threat-intelligence.md)
- [08 — Correlation and severity](08-correlation-and-severity.md)
- [09 — Hermes AI integration](09-hermes-ai-integration.md)
- [12 — Testing and validation](12-testing-and-validation.md)
- [16 — Audit report](16-audit-report.md)
