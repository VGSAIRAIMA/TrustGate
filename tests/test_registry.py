"""Tests for Stage 11 Registry Identity Check."""

import unittest
from trustgate.mechanisms.registry import (
    KNOWN_REGISTRY,
    RegistryEntry,
    compute_name_similarity,
    registry_check,
)


class TestRegistry(unittest.TestCase):
    def test_stage_11_definition_of_done(self):
        """DoD: fireb4se-mcp-server against known firebase-mcp-server scores similarity > 0.90

        with a mismatched publisher and is flagged. A genuinely new, non-similar name is not.
        """
        # 1. Typosquatted server with unverified publisher
        result_typosquat = registry_check("fireb4se-mcp-server", publisher="unverified")
        self.assertTrue(result_typosquat.flagged)
        self.assertGreater(result_typosquat.similarity, 0.90)
        self.assertEqual(result_typosquat.matched_name, "firebase-mcp-server")
        self.assertEqual(result_typosquat.matched_publisher, "firebase")
        self.assertIn("Typosquatting detected", result_typosquat.reason)

        # 2. Genuinely new, non-similar name
        result_new = registry_check("my-unique-custom-accounting-tool", publisher="finance-corp")
        self.assertFalse(result_new.flagged)
        self.assertLess(result_new.similarity, 0.85)
        self.assertIn("New unique server name", result_new.reason)

    def test_authentic_known_server(self):
        # Official server with correct publisher should NOT be flagged
        res = registry_check("firebase-mcp-server", publisher="firebase")
        self.assertFalse(res.flagged)
        self.assertEqual(res.similarity, 1.0)
        self.assertEqual(res.matched_name, "firebase-mcp-server")

    def test_impersonation_exact_name_mismatched_publisher(self):
        # Exact official name published by attacker should be flagged
        res = registry_check("firebase-mcp-server", publisher="attacker-org")
        self.assertTrue(res.flagged)
        self.assertEqual(res.similarity, 1.0)
        self.assertIn("Impersonation alert", res.reason)

    def test_demo_servers_authentic(self):
        for demo_name in ("calculator", "docs_search", "email_tool"):
            res = registry_check(demo_name, publisher="trustgate-demo")
            self.assertFalse(res.flagged)
            self.assertEqual(res.similarity, 1.0)

    def test_custom_registry_and_threshold(self):
        custom_registry = {
            "payment-gateway": RegistryEntry(
                name="payment-gateway",
                publisher="stripe",
                verified=True,
            )
        }
        # Exact match
        res_auth = registry_check("payment-gateway", publisher="stripe", registry=custom_registry)
        self.assertFalse(res_auth.flagged)

        # Typosquat
        res_squat = registry_check("p4yment-gateway", publisher="unknown", registry=custom_registry)
        self.assertTrue(res_squat.flagged)
        self.assertGreater(res_squat.similarity, 0.90)

    def test_compute_name_similarity(self):
        self.assertEqual(compute_name_similarity("calculator", "calculator"), 1.0)
        self.assertGreater(compute_name_similarity("fireb4se-mcp-server", "firebase-mcp-server"), 0.90)
        self.assertLess(compute_name_similarity("calculator", "postgres-mcp-server"), 0.40)


if __name__ == "__main__":
    unittest.main()
