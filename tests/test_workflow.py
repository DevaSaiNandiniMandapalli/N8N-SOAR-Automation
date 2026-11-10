"""Unit tests for the sanitized workflow and repository artefacts.

These are static tests. They do not execute the n8n workflow, call external
services, or require credentials.

Run with:
    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / "workflows" / "enterprise-soc-soar-pipeline.sanitized.json"
REPORT = ROOT / "docs" / "sanitization-report.json"
SAMPLES = ROOT / "workflows" / "samples"

EXPECTED_NODES = 31
EXPECTED_EDGES = 36
EXPECTED_CODE_NODES = 13

EXPECTED_PLACEHOLDER_NODES = {
    "virus total": "REPLACE_WITH_VIRUSTOTAL_API_KEY",
    "AbuseIPDB": "REPLACE_WITH_ABUSEIPDB_API_KEY",
    "OTX": "REPLACE_WITH_OTX_API_KEY",
    "Grey Noise": "REPLACE_WITH_GREYNOISE_API_KEY",
    "Threat Fox": "REPLACE_WITH_THREATFOX_AUTH_KEY",
    "Leakix": "REPLACE_WITH_LEAKIX_API_KEY",
    "FortiGate HTTP Request node": "Bearer REPLACE_WITH_FORTIGATE_API_TOKEN",
    "DFIR-IRIS Alert": "Bearer REPLACE_WITH_DFIR_IRIS_API_TOKEN",
}

FORBIDDEN = ("192.168.3.55", "172.17.0.1", "124.123.14.2",
             "127.0.0.1/alerts/add", "authCookie")


def load_workflow() -> dict:
    return json.loads(WORKFLOW.read_text(encoding="utf-8"))


def nodes_by_name(workflow: dict) -> dict[str, dict]:
    return {n["name"]: n for n in workflow["nodes"]}


def edges(workflow: dict) -> list[tuple[str, str]]:
    result = []
    for source, value in workflow["connections"].items():
        for outputs in value.get("main", []) or []:
            for connection in outputs or []:
                if connection and connection.get("node"):
                    result.append((source, connection["node"]))
    return result


class WorkflowStructureTests(unittest.TestCase):
    def setUp(self):
        self.workflow = load_workflow()
        self.nodes = nodes_by_name(self.workflow)

    def test_node_count(self):
        self.assertEqual(len(self.workflow["nodes"]), EXPECTED_NODES)

    def test_edge_count(self):
        self.assertEqual(len(edges(self.workflow)), EXPECTED_EDGES)

    def test_unique_names_and_ids(self):
        names = [n["name"] for n in self.workflow["nodes"]]
        ids = [n["id"] for n in self.workflow["nodes"]]
        self.assertEqual(len(set(names)), len(names))
        self.assertEqual(len(set(ids)), len(ids))

    def test_every_connection_target_exists(self):
        names = set(self.nodes)
        for source, target in edges(self.workflow):
            self.assertIn(source, names)
            self.assertIn(target, names)

    def test_required_nodes_present(self):
        required = {
            "Webhook", "Edit Fields", "IOC Extraction", "Dedup Check",
            "IOC Routing", "TI required?", "Merge1", "Merge2",
            "TI Aggregator", "TI Normalizer", "External Incident",
            "Internal Analysis", "Internal Incident",
            "TI Corroboration & Scoring", "Incident Summary", "Severity",
            "Final Report", "Laya Decision Gate", "DFIR-IRIS Alert",
            "Discord Alert", "Severity Confirmation", "Is Public IP?",
            "FortiGate HTTP Request node", "Send a text message", "Slack",
        }
        self.assertTrue(required.issubset(set(self.nodes)), required - set(self.nodes))

    def test_expected_branch_connections(self):
        pairs = set(edges(self.workflow))
        self.assertIn(("TI required?", "Internal Analysis"), pairs)
        self.assertIn(("TI required?", "virus total"), pairs)
        self.assertIn(("Final Report", "Laya Decision Gate"), pairs)
        self.assertIn(("Laya Decision Gate", "DFIR-IRIS Alert"), pairs)
        self.assertIn(("DFIR-IRIS Alert", "Discord Alert"), pairs)
        self.assertIn(("Is Public IP?", "FortiGate HTTP Request node"), pairs)

    def test_known_dead_ends_are_documented(self):
        # Severity Confirmation has no false output at all; Is Public IP? has an
        # empty false output. Both are dead ends documented in docs/03 and docs/10.
        wf = self.workflow["connections"]
        sc = wf["Severity Confirmation"]["main"]
        self.assertEqual(len(sc), 1)
        self.assertTrue(sc[0])
        ip = wf["Is Public IP?"]["main"]
        self.assertEqual(len(ip), 2)
        self.assertTrue(ip[0])
        self.assertEqual(ip[1], [])


class SanitizationTests(unittest.TestCase):
    def setUp(self):
        self.workflow = load_workflow()
        self.raw = WORKFLOW.read_text(encoding="utf-8")

    def test_inactive_and_no_instance_metadata(self):
        self.assertIs(self.workflow.get("active"), False)
        self.assertNotIn("id", self.workflow)
        self.assertNotIn("versionId", self.workflow)
        self.assertNotIn("instanceId", self.workflow.get("meta", {}))
        self.assertNotIn("errorWorkflow", self.workflow.get("settings", {}))

    def test_no_credential_or_webhook_ids(self):
        for node in self.workflow["nodes"]:
            self.assertNotIn("webhookId", node)
            for credential in (node.get("credentials") or {}).values():
                self.assertNotIn("id", credential)

    def test_no_forbidden_infrastructure_literals(self):
        for literal in FORBIDDEN:
            self.assertNotIn(literal, self.raw)

    def test_provider_placeholders(self):
        nodes = nodes_by_name(self.workflow)
        for node_name, expected in EXPECTED_PLACEHOLDER_NODES.items():
            params = nodes[node_name].get("parameters", {})
            headers = params.get("headerParameters", {}).get("parameters", []) or []
            values = [str(h.get("value", "")) for h in headers]
            self.assertIn(expected, values, node_name)

    def test_discord_and_telegram_placeholders(self):
        nodes = nodes_by_name(self.workflow)
        discord = nodes["Discord Alert"]["parameters"]["url"]
        self.assertIn("REPLACE_WITH_DISCORD_WEBHOOK_ID", discord)
        self.assertIn("REPLACE_WITH_DISCORD_WEBHOOK_TOKEN", discord)
        telegram = nodes["Send a text message"]["parameters"]["chatId"]
        self.assertEqual(telegram, "REPLACE_WITH_TELEGRAM_CHAT_ID")

    def test_sanitization_report(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertEqual(report["surviving_original_secrets"], 0)
        self.assertEqual(report["unredacted_pattern_findings"], [])
        self.assertEqual(report["nodes"], EXPECTED_NODES)
        self.assertEqual(report["edges"], EXPECTED_EDGES)


class CodeNodeTests(unittest.TestCase):
    def setUp(self):
        self.workflow = load_workflow()

    def test_code_node_count_and_nonempty_source(self):
        code_nodes = [n for n in self.workflow["nodes"]
                      if n.get("type") == "n8n-nodes-base.code"]
        self.assertEqual(len(code_nodes), EXPECTED_CODE_NODES)
        for node in code_nodes:
            self.assertIsInstance(node["parameters"].get("jsCode"), str)
            self.assertTrue(node["parameters"]["jsCode"].strip())

    def test_laya_code_has_no_hmac(self):
        nodes = nodes_by_name(self.workflow)
        source = nodes["Laya Decision Gate"]["parameters"]["jsCode"]
        lowered = source.lower()
        self.assertNotIn("hmac", lowered)
        self.assertNotIn("hermes", lowered)
        self.assertIn("/api/triage", source)

    def test_validator_passes_when_node_available(self):
        if not shutil.which("node"):
            self.skipTest("node not on PATH")
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "validate_workflow.py"),
             "--workflow", str(WORKFLOW)],
            capture_output=True, text=True, timeout=180,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("VALIDATION=PASS", result.stdout)


class SampleTests(unittest.TestCase):
    def test_samples_are_valid_json(self):
        for name in ("wazuh-alert.sample.json", "n8n-webhook-item.sample.json"):
            data = json.loads((SAMPLES / name).read_text(encoding="utf-8"))
            self.assertIsInstance(data, dict)

    def test_webhook_sample_wraps_body(self):
        item = json.loads((SAMPLES / "n8n-webhook-item.sample.json").read_text(encoding="utf-8"))
        self.assertIn("body", item)
        self.assertEqual(item["body"]["rule"]["id"], "5710")
        self.assertEqual(item["body"]["data"]["srcip"], "203.0.113.45")

    def test_samples_use_documentation_ranges_only(self):
        for name in ("wazuh-alert.sample.json", "n8n-webhook-item.sample.json"):
            text = (SAMPLES / name).read_text(encoding="utf-8")
            self.assertIn("203.0.113.45", text)
            self.assertNotIn("192.168.3.55", text)
            for literal in FORBIDDEN:
                self.assertNotIn(literal, text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
