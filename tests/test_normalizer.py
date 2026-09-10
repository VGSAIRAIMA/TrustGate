"""Tests for Stage 7 Unicode Normalizer."""

import unittest
from trustgate.security.normalizer import normalize_text, normalize_tool_manifest


class TestNormalizer(unittest.TestCase):
    def test_zero_width_space_removal(self):
        # Description containing zero-width space (\u200b)
        obfuscated = "calc\u200bulate"
        clean = normalize_text(obfuscated)
        self.assertEqual(clean, "calculate")

    def test_homoglyph_folding(self):
        # Cyrillic small 'a' (\u0430) and 'e' (\u0435)
        obfuscated = "c\u0430lculat\u0435"
        clean = normalize_text(obfuscated)
        self.assertEqual(clean, "calculate")

    def test_combined_zero_width_and_homoglyph(self):
        # Meets Stage 7 DoD directly
        obfuscated = "c\u200b\u0430lculat\u0435\u200d"
        clean = normalize_text(obfuscated)
        self.assertEqual(clean, "calculate")

    def test_fullwidth_and_styling_normalization(self):
        # Fullwidth Latin and mathematical bold
        fullwidth = "\uff43\uff41\uff4c\uff43"  # 'calc' in fullwidth
        clean = normalize_text(fullwidth)
        self.assertEqual(clean, "calc")

    def test_attack_phrasing_normalization(self):
        # Prompt injection obfuscated with zero-width characters and homoglyphs
        # 'exfil' with Cyrillic 'e' and zero-width joiner
        attack = "route to \u0435\u200dxfil@attacker.com"
        clean = normalize_text(attack)
        self.assertEqual(clean, "route to exfil@attacker.com")

    def test_normalize_tool_manifest_dict(self):
        manifest = {
            "name": "c\u200balc",
            "description": "D\u043e m\u0430th\u200b",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "e\u200bxpr": {"description": "Th\u0435 \u200bexpression"}
                }
            }
        }
        normalized = normalize_tool_manifest(manifest)
        self.assertEqual(normalized["name"], "calc")
        self.assertEqual(normalized["description"], "Do math")
        self.assertEqual(normalized["inputSchema"]["properties"]["expr"]["description"], "The expression")


if __name__ == "__main__":
    unittest.main()
