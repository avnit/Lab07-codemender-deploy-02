import datetime
import decimal
import re
import unittest
from unittest.mock import MagicMock, patch

from starlette.testclient import TestClient

from services.bigquery_service import BigQueryService, serialize_bq_val
from services.runner.store import FINDING_SCHEMA
from services.logging_service import LoggingService, format_log_entry
from services.runner_service import runner_manager
from services.runner.service import ServiceError
from server import (
    app,
    cm_find,
    cm_validate,
    cm_fix,
    cm_apply_patch,
    cm_job_status,
    cm_list_findings,
    cm_get_finding,
)


class TestSerialization(unittest.TestCase):
    def test_serialize_datetime(self):
        dt = datetime.datetime(2026, 9, 10, 12, 0, 0, tzinfo=datetime.timezone.utc)
        self.assertEqual(serialize_bq_val(dt), "2026-09-10T12:00:00+00:00")

    def test_serialize_decimal(self):
        dec = decimal.Decimal("123.45")
        self.assertEqual(serialize_bq_val(dec), 123.45)

    def test_serialize_nested_dict(self):
        data = {
            "time": datetime.date(2026, 9, 10),
            "amount": decimal.Decimal("99.9"),
            "bytes_val": b"hello",
            "list_val": [decimal.Decimal("1.2")],
        }
        serialized = serialize_bq_val(data)
        self.assertEqual(serialized["time"], "2026-09-10")
        self.assertEqual(serialized["amount"], 99.9)
        self.assertEqual(serialized["bytes_val"], "hello")
        self.assertEqual(serialized["list_val"], [1.2])


class TestBigQueryService(unittest.TestCase):
    @patch("services.bigquery_service.bigquery.Client")
    def test_list_issues_filter_construction(self, mock_bq_client):
        mock_instance = MagicMock()
        mock_bq_client.return_value = mock_instance
        mock_instance.project = "test-project"

        # Mock count and data results
        mock_count_job = MagicMock()
        mock_count_job.result.return_value = [{"total": 1}]
        
        mock_data_job = MagicMock()
        mock_data_job.result.return_value = [
            {"finding_id": "FINDING-123", "severity": "HIGH", "status": "OPEN"}
        ]
        mock_instance.query.side_effect = [mock_count_job, mock_data_job]

        service = BigQueryService(project_id="test-project", dataset="test_ds", table="test_tb")
        res = service.list_issues(
            severity="HIGH",
            status="OPEN",
            repository="org/repo",
            vulnerability_type="CWE-89",
            limit=10,
        )

        self.assertIn("issues", res)
        self.assertEqual(res["total_issues"], 1)
        self.assertEqual(len(res["issues"]), 1)
        self.assertEqual(res["issues"][0]["finding_id"], "FINDING-123")

    # -- reader vs. the table cm_find writes (services/runner/store.py) ---------
    @staticmethod
    def _service_with_columns(columns):
        """BigQueryService whose table schema is `columns`; records issued SQL."""
        client = MagicMock()
        client.project = "test-project"
        fields = []
        for name in columns:
            field = MagicMock()
            field.name = name
            fields.append(field)
        client.get_table.return_value.schema = fields
        service = BigQueryService(project_id="test-project", dataset="codemender", table="findings")
        service._client = client
        return service, client

    @staticmethod
    def _sql(client):
        return [call.args[0] for call in client.query.call_args_list]

    def _assert_only_known_columns(self, sql, columns):
        for name in re.findall(r"CAST\((\w+) AS STRING\)", sql):
            self.assertIn(name, columns, f"query references missing column {name!r}: {sql}")

    def test_list_issues_uses_columns_written_by_cm_find(self):
        service, client = self._service_with_columns(FINDING_SCHEMA)
        job = MagicMock()
        job.result.return_value = [{"total": 0}]
        client.query.return_value = job

        res = service.list_issues(
            repository="org/repo", vulnerability_type="sql-injection",
            session_id="find-abc", search_query="db.py", severity="ERROR", status="OPEN",
        )

        self.assertNotIn("error", res)
        for sql in self._sql(client):
            self._assert_only_known_columns(sql, FINDING_SCHEMA)
            for column in ("repo", "rule_id", "scan_job_id", "message", "file_path"):
                self.assertIn(f"CAST({column} AS STRING)", sql)

    def test_get_issue_details_uses_finding_id_only(self):
        service, client = self._service_with_columns(FINDING_SCHEMA)
        client.query.return_value.result.return_value = [{"finding_id": "abc-001"}]

        res = service.get_issue_details("abc-001")

        self.assertEqual(res["finding_id"], "abc-001")
        sql = self._sql(client)[0]
        self._assert_only_known_columns(sql, FINDING_SCHEMA)
        self.assertIn("CAST(finding_id AS STRING) = @issue_id", sql)

    def test_summary_matches_cm_find_columns_and_status_values(self):
        service, client = self._service_with_columns(FINDING_SCHEMA)
        totals, severities, top = MagicMock(), MagicMock(), MagicMock()
        totals.result.return_value = [{"total_issues": 3, "resolved_count": 1, "open_count": 2}]
        severities.result.return_value = [
            {"severity": "HIGH", "count": 2}, {"severity": "MEDIUM", "count": 1}]
        top.result.return_value = [{"vuln_type": "py/sql-injection", "count": 2}]
        client.query.side_effect = [totals, severities, top]

        res = service.get_issues_summary(days=30)

        self.assertNotIn("error", res)
        self.assertEqual(res["total_issues"], 3)
        self.assertEqual(res["severity_breakdown"],
                         {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 1, "LOW": 0})
        self.assertEqual(res["top_vulnerabilities"], [{"type": "py/sql-injection", "count": 2}])
        summary_sql, _, top_sql = self._sql(client)
        for sql in self._sql(client):
            self._assert_only_known_columns(sql, FINDING_SCHEMA)
        # VERIFIED means "confirmed exploitable" in cm_find output: not resolved.
        self.assertIn("IN ('FIXED', 'PATCHED', 'APPLIED')", summary_sql)
        self.assertNotIn("'VERIFIED'", summary_sql)
        self.assertIn("CAST(rule_id AS STRING)", top_sql)

    def test_issue_style_table_is_still_queryable(self):
        legacy = ["issue_id", "title", "description", "repository", "cwe_id",
                  "vulnerability_type", "session_id", "severity", "status",
                  "file_path", "created_at"]
        service, client = self._service_with_columns(legacy)
        client.query.return_value.result.return_value = [{"total": 0}]

        self.assertNotIn("error", service.list_issues(
            repository="r", vulnerability_type="CWE-89", session_id="s", search_query="q"))
        service.get_issue_details("CM-0001")
        for sql in self._sql(client):
            self._assert_only_known_columns(sql, legacy)

    def test_filter_on_absent_column_reports_schema_mismatch(self):
        service, client = self._service_with_columns(["finding_id", "severity", "status", "created_at"])

        res = service.list_issues(repository="org/repo")

        self.assertIn("Cannot filter by 'repository'", res["error"])
        client.query.assert_not_called()

    def test_execute_read_query_safety(self):
        service = BigQueryService(project_id="test-project")
        
        # Disallowed statements
        res_delete = service.execute_read_query("DELETE FROM `test.table` WHERE 1=1")
        self.assertIn("error", res_delete)
        self.assertIn("SELECT or WITH", res_delete["error"])

        res_drop = service.execute_read_query("SELECT 1; DROP TABLE `test.table`")
        self.assertIn("error", res_drop)
        self.assertIn("disallowed", res_drop["error"])

        res_update = service.execute_read_query("UPDATE `test.table` SET status='CLOSED'")
        self.assertIn("error", res_update)

        # Allowed statements with keywords inside string literals (false positive prevention)
        mock_client = MagicMock()
        mock_job = MagicMock()
        mock_job.result.return_value = []
        mock_client.query.return_value = mock_job
        service._client = mock_client
        
        res_safe_str = service.execute_read_query("SELECT * FROM `test.table` WHERE title = 'This is an UPDATE vulnerability'")
        self.assertNotIn("error", res_safe_str)
        
        res_safe_comment = service.execute_read_query("SELECT * FROM `test.table` -- checking drops")
        self.assertNotIn("error", res_safe_comment)
        
        res_semicolon = service.execute_read_query("SELECT * FROM `test.table`;")
        self.assertNotIn("error", res_semicolon)


class TestLoggingService(unittest.TestCase):
    @patch("services.logging_service.logging_v2.Client")
    def test_get_issue_logs_filter(self, mock_logging_client):
        mock_instance = MagicMock()
        mock_logging_client.return_value = mock_instance
        mock_instance.list_entries.return_value = []

        service = LoggingService(project_id="test-project")
        res = service.get_issue_logs(issue_id="ISSUE-456", min_severity="WARNING")

        self.assertIn("filter_used", res)
        self.assertIn('jsonPayload.finding_id="ISSUE-456"', res["filter_used"])
        self.assertIn("severity >= WARNING", res["filter_used"])

    def test_format_log_entry(self):
        mock_entry = MagicMock()
        mock_entry.timestamp = datetime.datetime(2026, 9, 10, 10, 0, 0, tzinfo=datetime.timezone.utc)
        mock_entry.severity = "ERROR"
        mock_entry.log_name = "projects/test-project/logs/codemender"
        mock_entry.resource.type = "cloud_run_job"
        mock_entry.resource.labels = {"job_name": "codemender-worker"}
        mock_entry.payload = {"message": "Failed to verify patch", "exit_code": 1}
        mock_entry.labels = {"session_id": "sess-123"}
        mock_entry.trace = "projects/test/traces/abc"
        mock_entry.span_id = "span-1"
        mock_entry.insert_id = "ins-1"

        formatted = format_log_entry(mock_entry)
        self.assertEqual(formatted["severity"], "ERROR")
        self.assertEqual(formatted["log_name"], "codemender")
        self.assertEqual(formatted["payload"]["message"], "Failed to verify patch")
        self.assertEqual(formatted["labels"]["session_id"], "sess-123")


class TestHttpEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client_context = TestClient(app)
        cls.client = cls.client_context.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client_context.__exit__(None, None, None)

    def test_health_check(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["service"], "codemender-mcp-server")
        self.assertIn("runner_configured", data)

    def test_root_endpoint(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["service"], "Code Mender MCP Server")
        self.assertIn("/mcp", data["mcp_streamable_endpoint"])
        self.assertIn("cm_find", data["tools"])
        self.assertIn("cm_fix", data["tools"])

    def test_mcp_streamable_http(self):
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "gemini-enterprise", "version": "1.0"},
            },
        }
        # Test /mcp (endpoint used by Gemini Enterprise)
        res_mcp = self.client.post("/mcp", json=payload)
        self.assertEqual(res_mcp.status_code, 200)
        self.assertIn("protocolVersion", res_mcp.text)

        # Test POST / (root)
        res_root = self.client.post("/", json=payload)
        self.assertEqual(res_root.status_code, 200)

        # Test POST /sse (fallback)
        res_sse = self.client.post("/sse", json=payload)
        self.assertEqual(res_sse.status_code, 200)

    def test_http_methods_compatibility_no_405(self):
        """Verify Gemini Enterprise preflight and lifecycle requests (OPTIONS, DELETE, HEAD) do not 405."""
        for path in ["/mcp", "/"]:
            # Preflight OPTIONS
            res_options = self.client.options(path)
            self.assertEqual(res_options.status_code, 204)
            self.assertEqual(res_options.headers.get("access-control-allow-origin"), "*")

            # Session termination DELETE
            res_delete = self.client.delete(path)
            self.assertEqual(res_delete.status_code, 200)
            self.assertEqual(res_delete.json(), {"status": "session terminated"})

            # Liveness / probe HEAD
            res_head = self.client.head(path)
            self.assertEqual(res_head.status_code, 200)

    def test_mcp_tools_list(self):
        """Verify tools/list works over /mcp with standard JSON Accept header."""
        payload = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        }
        res = self.client.post(
            "/mcp",
            json=payload,
            headers={"Accept": "application/json"},
        )
        self.assertEqual(res.status_code, 200)
        self.assertIn("list_codemender_issues", res.text)
        self.assertNotIn("wiz", res.text.lower())
        self.assertIn("cm_find", res.text)
        self.assertIn("cm_validate", res.text)
        self.assertIn("cm_fix", res.text)
        self.assertIn("cm_apply_patch", res.text)
        self.assertIn("cm_job_status", res.text)
        self.assertIn("cm_list_findings", res.text)
        self.assertIn("cm_get_finding", res.text)


class TestRunnerTools(unittest.TestCase):
    def setUp(self):
        self.mock_service = MagicMock()
        runner_manager.set_service(self.mock_service)

    def tearDown(self):
        runner_manager._service = None

    def test_cm_find(self):
        self.mock_service.start_find.return_value = {"job_id": "find-123", "status": "STAGING"}
        res = cm_find(repo="owner/repo", ref="main")
        self.mock_service.start_find.assert_called_once_with("owner/repo", "main")
        self.assertEqual(res["job_id"], "find-123")

    def test_cm_find_with_wait(self):
        self.mock_service.start_find.return_value = {"job_id": "find-123", "status": "STAGING"}
        self.mock_service.job_status.return_value = {"job_id": "find-123", "status": "SUCCEEDED"}
        res = cm_find(repo="owner/repo", ref="main", wait_seconds=30)
        self.mock_service.start_find.assert_called_once_with("owner/repo", "main")
        self.mock_service.job_status.assert_called_once_with("find-123", 30)
        self.assertEqual(res["status"], "SUCCEEDED")

    def test_cm_validate(self):
        self.mock_service.start_validate.return_value = {"job_id": "validate-456", "status": "STAGING"}
        res = cm_validate(finding_id="f-001")
        self.mock_service.start_validate.assert_called_once_with("f-001")
        self.assertEqual(res["job_id"], "validate-456")

    def test_cm_fix(self):
        self.mock_service.start_fix.return_value = {"job_id": "fix-789", "status": "STAGING"}
        res = cm_fix(finding_id="f-001", patch_mode="pr")
        self.mock_service.start_fix.assert_called_once_with("f-001", "pr")
        self.assertEqual(res["job_id"], "fix-789")

    def test_cm_apply_patch(self):
        self.mock_service.apply_patch.return_value = {"pr_url": "https://github.com/owner/repo/pull/1"}
        res = cm_apply_patch(finding_id="f-001", patch_mode="pr")
        self.mock_service.apply_patch.assert_called_once_with("f-001", "pr")
        self.assertEqual(res["pr_url"], "https://github.com/owner/repo/pull/1")

    def test_cm_job_status(self):
        self.mock_service.job_status.return_value = {"job_id": "fix-789", "status": "SUCCEEDED"}
        res = cm_job_status(job_id="fix-789", wait_seconds=10)
        self.mock_service.job_status.assert_called_once_with("fix-789", 10)
        self.assertEqual(res["status"], "SUCCEEDED")

    def test_cm_list_findings(self):
        self.mock_service.list_findings.return_value = [{"finding_id": "f-001", "title": "SQLi"}]
        res = cm_list_findings(repo="owner/repo", status="OPEN", scan_job_id="find-123", limit=50)
        self.mock_service.list_findings.assert_called_once_with(
            repo="owner/repo", status="OPEN", scan_job_id="find-123", limit=50
        )
        self.assertEqual(len(res["findings"]), 1)
        self.assertEqual(res["findings"][0]["finding_id"], "f-001")

    def test_cm_get_finding(self):
        self.mock_service.get_finding.return_value = {"finding_id": "f-001", "title": "SQLi"}
        res = cm_get_finding(finding_id="f-001", include_sarif=True)
        self.mock_service.get_finding.assert_called_once_with("f-001", True)
        self.assertEqual(res["finding_id"], "f-001")

    def test_error_handling(self):
        self.mock_service.start_find.side_effect = ServiceError("Service failed")
        res = cm_find(repo="bad/repo")
        self.assertEqual(res, {"error": "Service failed"})


if __name__ == "__main__":
    unittest.main()
