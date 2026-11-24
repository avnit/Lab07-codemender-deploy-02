import json
import pathlib
import unittest
from unittest.mock import MagicMock

from codemender import sarif
from services.bigquery_service import BigQueryService, serialize_finding
from services.runner.store import FINDING_SCHEMA
from services.severity import (
    normalize_severity,
    severity_for_finding,
    severity_from_score,
    severity_sql,
)

_CM_SAMPLE = (pathlib.Path(__file__).resolve().parent.parent
              / "codemender/runner/commands/testdata/cm_finding.json")


def _doc(level="warning", rule_score=None, result_score=None, by_index=False):
    result = {"level": level, "message": {"text": "m"}}
    result.update({"ruleIndex": 0} if by_index else {"ruleId": "R1"})
    if result_score is not None:
        result["properties"] = {"security-severity": result_score}
    rule = {"id": "R1"}
    if rule_score is not None:
        rule["properties"] = {"security-severity": rule_score}
    return {"version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "cm", "rules": [rule]}}, "results": [result]}]}


class TestSeverityMapping(unittest.TestCase):
    def test_score_bands(self):
        cases = {"10.0": "CRITICAL", 9.0: "CRITICAL", "8.9": "HIGH", 7: "HIGH",
                 "6.9": "MEDIUM", 4.0: "MEDIUM", "3.9": "LOW", 0: "LOW"}
        for score, expected in cases.items():
            self.assertEqual(severity_from_score(score), expected, score)

    def test_invalid_scores_are_ignored(self):
        for score in (None, "", "high", "11", -1):
            self.assertIsNone(severity_from_score(score), score)

    def test_level_fallback(self):
        cases = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "LOW"}
        for level, expected in cases.items():
            self.assertEqual(severity_for_finding(_doc(level), level), expected)
        self.assertEqual(severity_for_finding(None, ""), "MEDIUM")

    def test_score_wins_over_level(self):
        self.assertEqual(severity_for_finding(_doc("warning", rule_score="9.8"), "warning"), "CRITICAL")
        self.assertEqual(severity_for_finding(_doc("error", rule_score="2.0"), "error"), "LOW")
        self.assertEqual(
            severity_for_finding(_doc("error", rule_score="5.0", by_index=True), "error"), "MEDIUM")

    def test_result_score_wins_over_rule_score(self):
        doc = _doc("error", rule_score="2.0", result_score="9.5")
        self.assertEqual(severity_for_finding(doc, "error"), "CRITICAL")

    def test_invalid_score_falls_back_to_level(self):
        self.assertEqual(severity_for_finding(_doc("error", rule_score="n/a"), "error"), "HIGH")

    def test_real_cm_output_maps_to_critical(self):
        findings = sarif.SarifDocument.from_json(_CM_SAMPLE.read_text()).to_findings()
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.level, "error")  # score 10.0 on the rule outranks it
        self.assertEqual(severity_for_finding(finding.document, finding.level), "CRITICAL")

    def test_normalize_severity(self):
        cases = {"error": "HIGH", "WARNING": "MEDIUM", " note ": "LOW", "critical": "CRITICAL",
                 "High": "HIGH", None: "", "": ""}
        for value, expected in cases.items():
            self.assertEqual(normalize_severity(value), expected, value)

    def test_sql_expression_matches_python_mapping(self):
        expr = severity_sql()
        for level, severity in (("ERROR", "HIGH"), ("WARNING", "MEDIUM"), ("NOTE", "LOW"), ("NONE", "LOW")):
            self.assertIn(f"WHEN '{level}' THEN '{severity}'", expr)
        self.assertIn("ELSE UPPER(CAST(severity AS STRING))", expr)


class TestReaderAppliesMapping(unittest.TestCase):
    def setUp(self):
        self.client = MagicMock()
        self.client.project = "p"
        fields = []
        for name in FINDING_SCHEMA:
            field = MagicMock()
            field.name = name
            fields.append(field)
        self.client.get_table.return_value.schema = fields
        self.service = BigQueryService(project_id="p", dataset="codemender", table="findings")
        self.service._client = self.client

    def test_rows_stored_with_sarif_level_are_returned_mapped(self):
        self.assertEqual(
            serialize_finding({"finding_id": "a", "severity": "ERROR"}),
            {"finding_id": "a", "severity": "HIGH", "sarif_level": "ERROR"})
        self.assertEqual(
            serialize_finding({"finding_id": "b", "severity": "CRITICAL"}),
            {"finding_id": "b", "severity": "CRITICAL"})

    def test_filter_matches_mapped_and_legacy_rows(self):
        self.client.query.return_value.result.return_value = [{"total": 0}]
        for requested in ("HIGH", "high", "ERROR"):
            self.client.query.reset_mock()
            self.service.list_issues(severity=requested)
            call = self.client.query.call_args_list[0]
            self.assertIn(f"{severity_sql()} = @severity", call.args[0])
            params = {p.name: p.value for p in call.kwargs["job_config"].query_parameters}
            self.assertEqual(params["severity"], "HIGH", requested)

    def test_summary_counts_legacy_levels_under_mapped_severity(self):
        totals, severities, top = MagicMock(), MagicMock(), MagicMock()
        totals.result.return_value = [{"total_issues": 3, "resolved_count": 0, "open_count": 3}]
        severities.result.return_value = [
            {"severity": "CRITICAL", "count": 1}, {"severity": "HIGH", "count": 2}]
        top.result.return_value = []
        self.client.query.side_effect = [totals, severities, top]

        res = self.service.get_issues_summary()

        self.assertEqual(res["severity_breakdown"],
                         {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 0, "LOW": 0})
        self.assertIn(severity_sql(), self.client.query.call_args_list[1].args[0])


if __name__ == "__main__":
    unittest.main()
