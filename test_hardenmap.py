"""
Unit tests for HardenMap core modules and rules configuration.
Run with: python3 -m unittest test_hardenmap.py
"""

import unittest
from engine import load_rules
from linker import load_path_rules, link_paths
from report import calculate_score, build_report_data


class TestHardenMap(unittest.TestCase):

    def test_load_rules_structure(self):
        """Verify checks.yaml contains valid rule definitions with required keys."""
        rules = load_rules("rules")
        self.assertGreater(len(rules), 0, "No rules loaded from rules directory")
        for rule in rules:
            self.assertIn("id", rule)
            self.assertIn("title", rule)
            self.assertIn("type", rule)
            self.assertIn("severity", rule)

    def test_load_path_rules(self):
        """Verify paths.yaml contains valid attack path configurations."""
        paths = load_path_rules("rules")
        self.assertGreater(len(paths), 0, "No path rules loaded from rules directory")
        for p in paths:
            self.assertIn("id", p)
            self.assertIn("name", p)
            self.assertIn("requires", p)
            self.assertIn("severity", p)

    def test_calculate_score(self):
        """Verify risk scoring logic."""
        mock_findings = [
            {"status": "fail", "severity": "critical"},
            {"status": "fail", "severity": "high"},
            {"status": "pass", "severity": "critical"},
        ]
        mock_paths = [
            {"severity": "high"}
        ]
        score, level = calculate_score(mock_findings, mock_paths)
        self.assertEqual(score, 24)
        self.assertEqual(level, "HIGH")

    def test_build_report_data(self):
        """Verify report summary structure."""
        mock_findings = [{"status": "pass", "severity": "low"}]
        data = build_report_data(mock_findings, [], "1.0.0")
        self.assertEqual(data["tool"], "HardenMap")
        self.assertEqual(data["summary"]["total"], 1)
        self.assertEqual(data["summary"]["pass"], 1)
        self.assertIn("host_ip", data)


if __name__ == "__main__":
    unittest.main()
