#!/usr/bin/env python3
"""Structural and syntax validation for the sanitized n8n workflow.

Checks performed:
  * workflow-level metadata is free of instance identifiers
  * the workflow is inactive and has the expected 31 nodes / 36 connections
  * node names and IDs are unique; every connection target exists
  * no credential IDs, webhookId or known private infrastructure addresses
  * every Code node has jsCode and is syntactically valid JavaScript

Code node syntax is checked three ways because n8n wraps Code node source in a
function context:
  1. plain CommonJS `node --check` (top-level `return` is legal)
  2. ES module `node --check` (top-level `await` is legal)
  3. wrapped in `async function ... { ... }` (both are legal; closest to n8n)

Only the wrapped check is authoritative. Results 1 and 2 are reported for
transparency. This script never prints secret values.

Usage:
    python scripts/validate_workflow.py \
        --workflow workflows/enterprise-soc-soar-pipeline.sanitized.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

EXPECTED_NODES = 31
EXPECTED_EDGES = 36
EXPECTED_CODE_NODES = 13

REQUIRED_NODE_NAMES = {
    "Webhook", "Edit Fields", "IOC Extraction", "Dedup Check", "IOC Routing",
    "TI required?", "Threat Fox", "Grey Noise", "AbuseIPDB", "OTX",
    "virus total", "Leakix", "Merge1", "TI Aggregator", "TI Normalizer",
    "External Incident", "Internal Analysis", "Internal Incident", "Merge2",
    "TI Corroboration & Scoring", "Incident Summary", "Severity",
    "Final Report", "Laya Decision Gate", "DFIR-IRIS Alert", "Discord Alert",
    "Severity Confirmation", "Is Public IP?", "FortiGate HTTP Request node",
    "Send a text message", "Slack",
}

FORBIDDEN_LITERALS = (
    "192.168.3.55",
    "172.17.0.1",
    "124.123.14.2",
    "127.0.0.1/alerts/add",
    "authCookie",
)

SECRET_PATTERNS = [
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"),
    re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{30,}\b"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
]

CODE_PREFIX = "async function __n8n_check() {\n"
CODE_SUFFIX = "\n}\n"


def collect_edges(workflow: dict[str, Any]) -> list[tuple[str, int, str]]:
    edges: list[tuple[str, int, str]] = []
    for source, value in (workflow.get("connections") or {}).items():
        for index, outputs in enumerate(value.get("main", []) or []):
            for connection in outputs or []:
                if connection and connection.get("node"):
                    edges.append((source, index, connection["node"]))
    return edges


def find_credential_ids(workflow: dict[str, Any]) -> list[str]:
    found: list[str] = []
    for node in workflow.get("nodes", []):
        for credential in (node.get("credentials") or {}).values():
            if "id" in credential:
                found.append(node.get("name", "<unnamed>"))
        if "webhookId" in node:
            found.append(node.get("name", "<unnamed>") + " (webhookId)")
    return found


def run_node_check(node_path: str, file_path: Path) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            [node_path, "--check", str(file_path)],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    message = (result.stderr or result.stdout or "").strip().splitlines()
    return result.returncode == 0, (message[0] if message else "ok")


def check_code_nodes(code_sources: dict[str, str], temp_dir: Path) -> dict[str, Any]:
    node_path = os.environ.get("NODE_BINARY", "node")
    results: dict[str, Any] = {}
    for name, source in code_sources.items():
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
        cjs = temp_dir / f"{safe}.js"
        esm = temp_dir / f"{safe}.mjs"
        wrapped = temp_dir / f"{safe}.wrapped.js"

        cjs.write_text(source, encoding="utf-8")
        esm.write_text(source, encoding="utf-8")
        wrapped.write_text(CODE_PREFIX + source + CODE_SUFFIX, encoding="utf-8")

        results[name] = {
            "cjs_ok": run_node_check(node_path, cjs)[0],
            "esm_ok": run_node_check(node_path, esm)[0],
            "wrapped_ok": run_node_check(node_path, wrapped)[0],
            "cjs_note": run_node_check(node_path, cjs)[1],
            "esm_note": run_node_check(node_path, esm)[1],
            "wrapped_note": run_node_check(node_path, wrapped)[1],
        }
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workflow", required=True, type=Path)
    parser.add_argument("--skip-node-check", action="store_true")
    args = parser.parse_args()

    raw = args.workflow.read_text(encoding="utf-8")
    workflow = json.loads(raw)
    failures: list[str] = []

    # --- Workflow metadata -------------------------------------------------
    if workflow.get("active") is not False:
        failures.append("workflow.active must be false")
    for key in ("id", "versionId"):
        if key in workflow:
            failures.append(f"workflow.{key} must be removed")
    if "instanceId" in (workflow.get("meta") or {}):
        failures.append("workflow.meta.instanceId must be removed")
    if "errorWorkflow" in (workflow.get("settings") or {}):
        failures.append("workflow.settings.errorWorkflow must be removed")

    # --- Structure ----------------------------------------------------------
    nodes = workflow.get("nodes", [])
    names = [n.get("name") for n in nodes]
    node_ids = [n.get("id") for n in nodes]
    edges = collect_edges(workflow)

    print(f"nodes={len(nodes)} edges={len(edges)}")
    if len(nodes) != EXPECTED_NODES:
        failures.append(f"expected {EXPECTED_NODES} nodes, found {len(nodes)}")
    if len(edges) != EXPECTED_EDGES:
        failures.append(f"expected {EXPECTED_EDGES} edges, found {len(edges)}")
    if len(set(names)) != len(names):
        failures.append("duplicate node names")
    if len(set(node_ids)) != len(node_ids):
        failures.append("duplicate node IDs")
    missing = REQUIRED_NODE_NAMES - set(names)
    if missing:
        failures.append("missing nodes: " + ", ".join(sorted(missing)))
    for source, _index, target in edges:
        if source not in names:
            failures.append(f"connection source not found: {source}")
        if target not in names:
            failures.append(f"connection target not found: {target}")

    # --- Secret / identifier hygiene ---------------------------------------
    credential_ids = find_credential_ids(workflow)
    if credential_ids:
        failures.append("credential/webhook IDs present: " + ", ".join(sorted(set(credential_ids))))
    for literal in FORBIDDEN_LITERALS:
        if literal in raw:
            failures.append(f"forbidden literal present: {literal}")
    for pattern in SECRET_PATTERNS:
        for match in pattern.finditer(raw):
            value = match.group(0)
            if "REPLACE_WITH" in value or "REDACTED" in value:
                continue
            failures.append(f"secret pattern matched: {pattern.pattern[:40]}")
            break
    placeholders = raw.count("REPLACE_WITH")
    print(f"placeholders={placeholders}")
    if placeholders < 10:
        failures.append(f"expected at least 10 REPLACE_WITH placeholders, found {placeholders}")

    # --- Code nodes ---------------------------------------------------------
    code_sources = {
        n["name"]: n["parameters"]["jsCode"]
        for n in nodes
        if n.get("type") == "n8n-nodes-base.code"
    }
    print(f"code_nodes={len(code_sources)}")
    if len(code_sources) != EXPECTED_CODE_NODES:
        failures.append(f"expected {EXPECTED_CODE_NODES} Code nodes, found {len(code_sources)}")
    for name, source in code_sources.items():
        if not isinstance(source, str) or not source.strip():
            failures.append(f"empty jsCode in {name}")

    syntax: dict[str, Any] = {}
    if not args.skip_node_check and code_sources:
        with tempfile.TemporaryDirectory(prefix="apos-validate-") as tmp:
            syntax = check_code_nodes(code_sources, Path(tmp))
        cjs_ok = sum(1 for r in syntax.values() if r["cjs_ok"])
        esm_ok = sum(1 for r in syntax.values() if r["esm_ok"])
        wrapped_ok = sum(1 for r in syntax.values() if r["wrapped_ok"])
        print(f"syntax_cjs_ok={cjs_ok}/{len(code_sources)}")
        print(f"syntax_esm_ok={esm_ok}/{len(code_sources)}")
        print(f"syntax_wrapped_ok={wrapped_ok}/{len(code_sources)}")
        if wrapped_ok != len(code_sources):
            for name, result in syntax.items():
                if not result["wrapped_ok"]:
                    failures.append(f"Code node syntax failed (wrapped): {name}: {result['wrapped_note']}")
        for name, result in syntax.items():
            if not result["cjs_ok"]:
                print(f"  note: {name} uses n8n wrapper syntax ({result['cjs_note']})")
    else:
        print("syntax_check=skipped")

    # --- Result -------------------------------------------------------------
    if failures:
        print(f"FAILURES={len(failures)}")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("VALIDATION=PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
