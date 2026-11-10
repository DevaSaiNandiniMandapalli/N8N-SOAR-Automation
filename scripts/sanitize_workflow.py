#!/usr/bin/env python3
"""Create a publishable n8n workflow export from a raw export.

This script never prints secret values. It replaces credentials, webhook URLs,
host addresses and instance metadata with explicit placeholders, then verifies
that none of the original secret strings survive in the output.

Usage:
    python scripts/sanitize_workflow.py \
        --source "C:/path/to/raw-export.json" \
        --output workflows/enterprise-soc-soar-pipeline.sanitized.json \
        --report docs/sanitization-report.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

# Credential-bearing parameters, keyed by node name and header/query name.
SECRET_PARAMETERS: dict[str, dict[str, str]] = {
    "virus total": {"x-apikey": "REPLACE_WITH_VIRUSTOTAL_API_KEY"},
    "AbuseIPDB": {"key": "REPLACE_WITH_ABUSEIPDB_API_KEY"},
    "OTX": {"X-OTX-API-KEY": "REPLACE_WITH_OTX_API_KEY"},
    "Grey Noise": {"key": "REPLACE_WITH_GREYNOISE_API_KEY"},
    "Threat Fox": {"auth-key": "REPLACE_WITH_THREATFOX_AUTH_KEY"},
    "Leakix": {"api-Key": "REPLACE_WITH_LEAKIX_API_KEY"},
    "FortiGate HTTP Request node": {
        "Authorization": "Bearer REPLACE_WITH_FORTIGATE_API_TOKEN"
    },
    "DFIR-IRIS Alert": {
        "Authorization": "Bearer REPLACE_WITH_DFIR_IRIS_API_TOKEN"
    },
}

# Global textual substitutions. Ordered longest-first where prefixes overlap.
URL_SUBSTITUTIONS = [
    ("https://192.168.3.55", "https://REPLACE_WITH_IRIS_HOST"),
    ("http://172.17.0.1:9999", "http://REPLACE_WITH_LAYA_HOST:9999"),
    ("https://127.0.0.1/alerts/add", "https://REPLACE_WITH_IRIS_HOST/alerts/add"),
    ("https://124.123.14.2:11443", "https://REPLACE_WITH_FORTIGATE_HOST:11443"),
]

SECRET_PATTERNS = [
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"),
    re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{30,}\b"),
    re.compile(r"\b[0-9a-fA-F]{64}\b"),
    re.compile(r"\b[0-9a-fA-F]{80}\b"),
    re.compile(r"Bearer\s+[A-Za-z0-9._\-]{20,}"),
]


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def find_secret_parameters(workflow: dict[str, Any]) -> set[str]:
    """Collect credential-like values from the raw export for verification."""
    values: set[str] = set()
    for node in workflow.get("nodes", []):
        params = node.get("parameters", {})
        for section in ("headerParameters", "queryParameters"):
            for entry in params.get(section, {}).get("parameters", []) or []:
                name = str(entry.get("name", ""))
                value = str(entry.get("value", ""))
                if re.search(r"auth|key|token|secret|apikey", name, re.I) and len(value) >= 8:
                    values.add(value)
        url = str(params.get("url", ""))
        if "discord" in url.lower() and "/api/webhooks/" in url:
            values.add(url)
        chat_id = params.get("chatId")
        if chat_id:
            values.add(str(chat_id))
    for value in (
        workflow.get("versionId"),
        workflow.get("meta", {}).get("instanceId"),
        workflow.get("settings", {}).get("errorWorkflow"),
    ):
        if value:
            values.add(str(value))
    return values


def sanitize(workflow: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, str]]]:
    report: list[dict[str, str]] = []

    def note(node: str, kind: str) -> None:
        report.append({"node": node, "change": kind})

    for node in workflow.get("nodes", []):
        name = node.get("name", "")
        params = node.get("parameters", {})

        # Remove instance-specific webhook identifier.
        if "webhookId" in node:
            del node["webhookId"]
            note(name, "removed webhookId")

        # Remove credential database IDs; keep human-readable names.
        for credential in (node.get("credentials") or {}).values():
            if "id" in credential:
                del credential["id"]
                note(name, "removed credential id")

        # Replace provider credentials.
        replacements = SECRET_PARAMETERS.get(name, {})
        for section in ("headerParameters", "queryParameters"):
            entries = params.get(section, {}).get("parameters", []) or []
            for entry in entries:
                header = str(entry.get("name", ""))
                if header not in replacements:
                    continue
                entry["value"] = replacements[header]
                note(name, f"replaced {section} {header}")

        # Discord webhook URL.
        if name == "Discord Alert":
            params["url"] = (
                "https://discord.com/api/webhooks/"
                "REPLACE_WITH_DISCORD_WEBHOOK_ID/REPLACE_WITH_DISCORD_WEBHOOK_TOKEN"
            )
            note(name, "replaced Discord webhook URL")

        # Telegram chat ID.
        if params.get("chatId"):
            params["chatId"] = "REPLACE_WITH_TELEGRAM_CHAT_ID"
            note(name, "replaced Telegram chat id")

        # FortiGate management address.
        if name == "FortiGate HTTP Request node":
            params["url"] = (
                "https://REPLACE_WITH_FORTIGATE_HOST:11443"
                "/api/v2/cmdb/firewall/address?vdom=root"
            )
            note(name, "replaced FortiGate host")

        # Replace infrastructure URLs inside expressions and code.
        for key, value in list(params.items()):
            if isinstance(value, str):
                updated = value
                for old, new in URL_SUBSTITUTIONS:
                    updated = updated.replace(old, new)
                if updated != value:
                    params[key] = updated
                    note(name, f"rewrote infrastructure URL in {key}")

    # Workflow-level metadata.
    for key in ("id", "versionId"):
        if key in workflow:
            del workflow[key]
            note("workflow", f"removed {key}")

    meta = workflow.get("meta", {})
    if "instanceId" in meta:
        del meta["instanceId"]
        note("workflow", "removed meta.instanceId")

    settings = workflow.get("settings", {})
    if "errorWorkflow" in settings:
        del settings["errorWorkflow"]
        note("workflow", "removed settings.errorWorkflow")

    if workflow.get("active") is not False:
        workflow["active"] = False
        note("workflow", "set active=false")

    return workflow, report


def scan_text(text: str) -> list[str]:
    findings: list[str] = []
    for pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            # Deliberate placeholders are not secrets.
            if "REPLACE_WITH" in value or "REDACTED" in value:
                continue
            digest = hashlib.sha256(value.encode()).hexdigest()[:12]
            findings.append(f"{pattern.pattern[:38]}... sha256:{digest}")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()

    raw_text = args.source.read_text(encoding="utf-8")
    workflow = load(args.source)
    original_secrets = find_secret_parameters(workflow)

    sanitized, changes = sanitize(workflow)

    # Verification 1: no original credential survives anywhere.
    serialized = json.dumps(sanitized, indent=2, ensure_ascii=False)
    survivors = [value for value in original_secrets if value and value in serialized]

    # Verification 2: structural integrity.
    node_count = len(sanitized.get("nodes", []))
    edge_count = 0
    for source in (sanitized.get("connections") or {}).values():
        for output in source.get("main", []) or []:
            edge_count += len([c for c in (output or []) if c])

    # Verification 3: no unredacted secret-like literals.
    findings = scan_text(serialized)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(serialized + "\n", encoding="utf-8")

    report = {
        "source_sha256": hashlib.sha256(raw_text.encode()).hexdigest(),
        "output_sha256": hashlib.sha256(serialized.encode()).hexdigest(),
        "nodes": node_count,
        "edges": edge_count,
        "original_secret_count": len(original_secrets),
        "surviving_original_secrets": len(survivors),
        "unredacted_pattern_findings": findings,
        "changes": changes,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print(f"nodes={node_count} edges={edge_count}")
    print(f"original_secret_count={len(original_secrets)}")
    print(f"surviving_original_secrets={len(survivors)}")
    print(f"unredacted_pattern_findings={len(findings)}")
    print(f"output={args.output}")
    return 1 if survivors or findings else 0


if __name__ == "__main__":
    sys.exit(main())
