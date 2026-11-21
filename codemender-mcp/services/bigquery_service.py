import datetime
import decimal
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from google.cloud import bigquery
from google.cloud.exceptions import NotFound, GoogleCloudError

from config import settings
from services.runner.store import FINDING_SCHEMA

logger = logging.getLogger(__name__)

# Logical field -> candidate column names, in preference order. The first names
# are the columns of the `findings` table that `cm_find` writes
# (services/runner/store.py: FINDING_SCHEMA). The later names are accepted so a
# table created with the older issue-style layout can still be queried.
FIELD_COLUMNS: Dict[str, Tuple[str, ...]] = {
    "id": ("finding_id", "issue_id", "id"),
    "repository": ("repo", "repository"),
    "vulnerability_type": ("rule_id", "vulnerability_type", "cwe_id"),
    "session_id": ("scan_job_id", "last_job_id", "session_id"),
    "search": ("message", "title", "description", "file_path", "rule_id"),
}

# Statuses that mean a finding needs no further work. In the table `cm_find`
# writes, VERIFIED means "confirmed exploitable", so it counts as open.
RESOLVED_STATUSES = ("FIXED", "PATCHED", "APPLIED")
NOT_OPEN_STATUSES = RESOLVED_STATUSES + ("FALSE_POSITIVE",)
STANDARD_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


class SchemaMismatchError(ValueError):
    """A filter was requested on a field the target table has no column for."""


def serialize_bq_val(val: Any) -> Any:
    """Convert BigQuery data types to JSON-serializable Python types."""
    if val is None:
        return None
    if isinstance(val, (datetime.datetime, datetime.date, datetime.time)):
        return val.isoformat()
    if isinstance(val, decimal.Decimal):
        return float(val)
    if isinstance(val, bytes):
        try:
            return val.decode("utf-8")
        except UnicodeDecodeError:
            return val.hex()
    if isinstance(val, dict):
        return {k: serialize_bq_val(v) for k, v in val.items()}
    if isinstance(val, (list, tuple)):
        return [serialize_bq_val(v) for v in val]
    return val


def serialize_row(row: bigquery.Row) -> Dict[str, Any]:
    """Convert a BigQuery Row to a serializable dictionary."""
    return {key: serialize_bq_val(val) for key, val in row.items()}


class BigQueryService:
    """Service for querying and analyzing Code Mender issues in BigQuery."""

    def __init__(
        self,
        project_id: Optional[str] = None,
        dataset: Optional[str] = None,
        table: Optional[str] = None,
    ):
        self.project_id = project_id or settings.gcp_project_id
        self.dataset = dataset or settings.bq_dataset
        self.table = table or settings.bq_table
        self._client: Optional[bigquery.Client] = None
        self._columns_cache: Dict[str, List[str]] = {}

    @property
    def client(self) -> bigquery.Client:
        """Lazy initialization of BigQuery client using Application Default Credentials."""
        if self._client is None:
            logger.info("Initializing BigQuery client for project: %s", self.project_id)
            self._client = bigquery.Client(project=self.project_id)
        return self._client

    @property
    def full_table_id(self) -> str:
        """Returns the fully qualified table name `project.dataset.table`."""
        project = self.client.project
        return f"`{project}.{self.dataset}.{self.table}`"

    def _table_columns(self, ds: str, tb: str) -> List[str]:
        """Column names of the target table, cached per table.

        Raises NotFound if the table does not exist. If the schema cannot be
        read for any other reason, assumes the layout `cm_find` writes.
        """
        key = f"{self.client.project}.{ds}.{tb}"
        cached = self._columns_cache.get(key)
        if cached is not None:
            return cached
        try:
            columns = [str(field.name) for field in self.client.get_table(key).schema]
        except NotFound:
            raise
        except Exception as e:  # pylint: disable=broad-except
            logger.warning("Could not read schema of %s (%s); assuming the cm_find layout.", key, e)
            return list(FINDING_SCHEMA)
        if not columns:
            return list(FINDING_SCHEMA)
        self._columns_cache[key] = columns
        return columns

    @staticmethod
    def _field_exprs(field: str, columns: List[str]) -> List[str]:
        """SQL string expressions for the columns that back a logical field."""
        present = [c for c in FIELD_COLUMNS[field] if c in columns]
        if not present:
            raise SchemaMismatchError(
                f"Cannot filter by '{field}': the table has none of the columns "
                f"{list(FIELD_COLUMNS[field])}. Available columns: {sorted(columns)}."
            )
        return [f"CAST({c} AS STRING)" for c in present]

    def get_table_schema(
        self, dataset: Optional[str] = None, table: Optional[str] = None
    ) -> Dict[str, Any]:
        """Fetch schema information for the specified BigQuery table."""
        ds = dataset or self.dataset
        tb = table or self.table
        project = self.client.project
        table_ref = f"{project}.{ds}.{tb}"

        try:
            table_obj = self.client.get_table(table_ref)
            columns = [
                {
                    "name": field.name,
                    "type": field.field_type,
                    "mode": field.mode,
                    "description": field.description or "",
                }
                for field in table_obj.schema
            ]
            return {
                "table_ref": table_ref,
                "num_rows": table_obj.num_rows,
                "num_bytes": table_obj.num_bytes,
                "created": table_obj.created.isoformat() if table_obj.created else None,
                "modified": table_obj.modified.isoformat() if table_obj.modified else None,
                "columns": columns,
            }
        except NotFound:
            return {"error": f"Table '{table_ref}' not found."}
        except Exception as e:
            logger.exception("Failed to get table schema: %s", e)
            return {"error": str(e)}

    def list_issues(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        repository: Optional[str] = None,
        vulnerability_type: Optional[str] = None,
        session_id: Optional[str] = None,
        search_query: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        limit: int = 25,
        offset: int = 0,
        dataset: Optional[str] = None,
        table: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List Code Mender issues from BigQuery with flexible filtering.

        Args:
            severity: Filter by severity. Findings from `cm_find` carry the SARIF level
                (ERROR, WARNING, NOTE); other tables may use CRITICAL, HIGH, MEDIUM, LOW.
            status: Filter by status (OPEN, VERIFIED, FALSE_POSITIVE, INCONCLUSIVE, FIXED, PATCHED).
            repository: Filter by repository name or path (column `repo`).
            vulnerability_type: Filter by rule ID / vulnerability type / CWE (column `rule_id`).
            session_id: Filter by the scan job ID that produced the finding (column `scan_job_id`).
            search_query: Search string within message, file_path, or rule_id.
            start_date: Filter for issues created on or after this ISO date/timestamp.
            end_date: Filter for issues created on or before this ISO date/timestamp.
            limit: Maximum number of records to return (capped at settings.max_query_limit).
            offset: Offset for pagination.
            dataset: Optional dataset override.
            table: Optional table override.
        """
        limit = min(max(1, limit), settings.max_query_limit)
        offset = max(0, offset)

        ds = dataset or self.dataset
        tb = table or self.table
        target_table = f"`{self.client.project}.{ds}.{tb}`"

        where_clauses: List[str] = []
        query_params: List[bigquery.ScalarQueryParameter] = []

        try:
            columns = self._table_columns(ds, tb)
            repo_exprs = self._field_exprs("repository", columns) if repository else []
            vuln_exprs = self._field_exprs("vulnerability_type", columns) if vulnerability_type else []
            session_exprs = self._field_exprs("session_id", columns) if session_id else []
            search_exprs = self._field_exprs("search", columns) if search_query else []
        except NotFound:
            return {"error": f"Table {target_table} does not exist in project '{self.client.project}'."}
        except SchemaMismatchError as e:
            return {"error": str(e)}

        if severity:
            where_clauses.append("UPPER(CAST(severity AS STRING)) = UPPER(@severity)")
            query_params.append(bigquery.ScalarQueryParameter("severity", "STRING", severity))

        if status:
            where_clauses.append("UPPER(CAST(status AS STRING)) = UPPER(@status)")
            query_params.append(bigquery.ScalarQueryParameter("status", "STRING", status))

        def any_of(exprs: List[str], template: str) -> str:
            return "(" + " OR ".join(template.format(e) for e in exprs) + ")"

        if repository:
            where_clauses.append(any_of(repo_exprs, "LOWER({}) LIKE LOWER(@repository)"))
            query_params.append(bigquery.ScalarQueryParameter("repository", "STRING", f"%{repository}%"))

        if vulnerability_type:
            where_clauses.append(any_of(vuln_exprs, "LOWER({}) LIKE LOWER(@vuln_type)"))
            query_params.append(bigquery.ScalarQueryParameter("vuln_type", "STRING", f"%{vulnerability_type}%"))

        if session_id:
            where_clauses.append(any_of(session_exprs, "{} = @session_id"))
            query_params.append(bigquery.ScalarQueryParameter("session_id", "STRING", session_id))

        if search_query:
            where_clauses.append(any_of(search_exprs, "LOWER({}) LIKE LOWER(@search)"))
            query_params.append(bigquery.ScalarQueryParameter("search", "STRING", f"%{search_query}%"))

        if start_date:
            where_clauses.append("created_at >= TIMESTAMP(@start_date)")
            query_params.append(bigquery.ScalarQueryParameter("start_date", "STRING", start_date))

        if end_date:
            where_clauses.append("created_at <= TIMESTAMP(@end_date)")
            query_params.append(bigquery.ScalarQueryParameter("end_date", "STRING", end_date))

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        # Query total count for pagination metadata
        count_sql = f"SELECT COUNT(*) AS total FROM {target_table} {where_sql}"
        
        # Main issue selection
        data_sql = f"""
            SELECT *
            FROM {target_table}
            {where_sql}
            ORDER BY created_at DESC
            LIMIT @limit OFFSET @offset
        """

        query_params_with_paging = query_params + [
            bigquery.ScalarQueryParameter("limit", "INT64", limit),
            bigquery.ScalarQueryParameter("offset", "INT64", offset),
        ]

        try:
            # Execute count
            count_job_config = bigquery.QueryJobConfig(query_parameters=query_params)
            count_job = self.client.query(count_sql, job_config=count_job_config)
            count_rows = list(count_job.result())
            total_count = count_rows[0]["total"] if count_rows else 0

            # Execute data query
            data_job_config = bigquery.QueryJobConfig(query_parameters=query_params_with_paging)
            data_job = self.client.query(data_sql, job_config=data_job_config)
            rows = [serialize_row(row) for row in data_job.result()]

            return {
                "total_issues": total_count,
                "returned_issues": len(rows),
                "limit": limit,
                "offset": offset,
                "issues": rows,
            }
        except NotFound:
            return {"error": f"Table {target_table} does not exist in project '{self.client.project}'."}
        except GoogleCloudError as gce:
            logger.exception("BigQuery query error: %s", gce)
            return {"error": f"BigQuery error: {gce.message}"}
        except Exception as e:
            logger.exception("Unexpected error querying BigQuery: %s", e)
            return {"error": str(e)}

    def get_issue_details(
        self,
        issue_id: str,
        dataset: Optional[str] = None,
        table: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Fetch detailed information for a specific Code Mender issue by finding/issue ID."""
        ds = dataset or self.dataset
        tb = table or self.table
        target_table = f"`{self.client.project}.{ds}.{tb}`"

        # Look up by whichever ID column(s) the table has (finding_id for cm_find output).
        try:
            id_exprs = self._field_exprs("id", self._table_columns(ds, tb))
        except NotFound:
            return {"error": f"Table {target_table} does not exist."}
        except SchemaMismatchError as e:
            return {"error": str(e)}
        id_match = " OR ".join(f"{e} = @issue_id" for e in id_exprs)
        sql = f"""
            SELECT *
            FROM {target_table}
            WHERE {id_match}
            LIMIT 1
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[bigquery.ScalarQueryParameter("issue_id", "STRING", issue_id)]
        )

        try:
            job = self.client.query(sql, job_config=job_config)
            results = list(job.result())
            if not results:
                return {"error": f"Issue with ID '{issue_id}' not found in {target_table}."}
            return serialize_row(results[0])
        except NotFound:
            return {"error": f"Table {target_table} does not exist."}
        except Exception as e:
            logger.exception("Error getting issue details: %s", e)
            return {"error": str(e)}

    def get_issues_summary(
        self,
        repository: Optional[str] = None,
        days: int = 30,
        dataset: Optional[str] = None,
        table: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate aggregated summary statistics on Code Mender findings."""
        ds = dataset or self.dataset
        tb = table or self.table
        target_table = f"`{self.client.project}.{ds}.{tb}`"

        where_clauses = ["created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)"]
        params = [bigquery.ScalarQueryParameter("days", "INT64", max(1, days))]

        try:
            columns = self._table_columns(ds, tb)
            repo_exprs = self._field_exprs("repository", columns) if repository else []
            vuln_exprs = self._field_exprs("vulnerability_type", columns)
        except NotFound:
            return {"error": f"Table {target_table} does not exist."}
        except SchemaMismatchError as e:
            return {"error": str(e)}

        if repository:
            where_clauses.append(
                "(" + " OR ".join(f"LOWER({e}) LIKE LOWER(@repo)" for e in repo_exprs) + ")"
            )
            params.append(bigquery.ScalarQueryParameter("repo", "STRING", f"%{repository}%"))

        where_sql = f"WHERE {' AND '.join(where_clauses)}"
        resolved_sql = ", ".join(f"'{st}'" for st in RESOLVED_STATUSES)
        not_open_sql = ", ".join(f"'{st}'" for st in NOT_OPEN_STATUSES)
        vuln_sql = f"COALESCE({', '.join(vuln_exprs)}, 'Unknown')"

        sql = f"""
            WITH base AS (
                SELECT * FROM {target_table} {where_sql}
            )
            SELECT
                (SELECT COUNT(*) FROM base) AS total_issues,
                (SELECT COUNTIF(UPPER(CAST(status AS STRING)) IN ({resolved_sql})) FROM base) AS resolved_count,
                (SELECT COUNTIF(UPPER(IFNULL(CAST(status AS STRING), 'OPEN')) NOT IN ({not_open_sql})) FROM base) AS open_count
        """

        # Severity values differ by producer (cm_find stores the SARIF level:
        # ERROR / WARNING / NOTE), so count whatever is present.
        severity_sql = f"""
            SELECT
                UPPER(IFNULL(NULLIF(CAST(severity AS STRING), ''), 'UNKNOWN')) AS severity,
                COUNT(*) AS count
            FROM {target_table}
            {where_sql}
            GROUP BY 1
        """

        top_vulns_sql = f"""
            SELECT
                {vuln_sql} AS vuln_type,
                COUNT(*) AS count
            FROM {target_table}
            {where_sql}
            GROUP BY 1
            ORDER BY count DESC
            LIMIT 5
        """

        try:
            job_config = bigquery.QueryJobConfig(query_parameters=params)
            summary_res_list = list(self.client.query(sql, job_config=job_config).result())
            if not summary_res_list:
                return {"error": "No data returned for summary."}
            summary_res = summary_res_list[0]
            severity_res = list(self.client.query(severity_sql, job_config=job_config).result())
            top_vulns_res = list(self.client.query(top_vulns_sql, job_config=job_config).result())

            severity_breakdown: Dict[str, int] = {sev: 0 for sev in STANDARD_SEVERITIES}
            for row in severity_res:
                severity_breakdown[str(row["severity"])] = int(row["count"])

            return {
                "period_days": days,
                "repository_filter": repository,
                "total_issues": summary_res["total_issues"],
                "open_issues": summary_res["open_count"],
                "resolved_issues": summary_res["resolved_count"],
                "severity_breakdown": severity_breakdown,
                "top_vulnerabilities": [
                    {"type": row["vuln_type"], "count": row["count"]} for row in top_vulns_res
                ],
            }
        except Exception as e:
            logger.exception("Error generating summary: %s", e)
            return {"error": str(e)}

    def execute_read_query(self, query: str, limit: int = 50) -> Dict[str, Any]:
        """Execute a safe, custom read-only SQL query against BigQuery.
        
        Enforces read-only safety by validating statements and restricting row output.
        """
        limit = min(max(1, limit), settings.max_query_limit)
        cleaned = query.strip()

        # Security check: must start with SELECT or WITH (ignoring comments)
        # Strip comments first to find the actual starting statement
        starting_check = re.sub(r"--.*$", "", cleaned, flags=re.MULTILINE)
        starting_check = re.sub(r"/\*.*?\*/", "", starting_check, flags=re.DOTALL).strip()
        if not re.match(r"^(SELECT|WITH)\b", starting_check, re.IGNORECASE):
            return {
                "error": "Only read-only SELECT or WITH statements are permitted."
            }

        # Safe keyword parsing: Strip comments and string literals first to prevent
        # false positives (keywords inside strings/comments) and prevent bypasses.
        # -- single line comments
        no_comments = re.sub(r"--.*$", "", cleaned, flags=re.MULTILINE)
        # /* multi-line comments */
        no_comments = re.sub(r"/\*.*?\*/", "", no_comments, flags=re.DOTALL)
        
        # Strip string literals (both single and double quotes, handling escaped quotes)
        no_strings = re.sub(r"'(?:[^'\\]|\\.)*'", " ", no_comments)
        no_strings = re.sub(r'"(?:[^"\\]|\\.)*"', " ", no_strings)

        # Check for disallowed DML/DDL keywords on the stripped SQL text
        disallowed_keywords = [
            r"\bDELETE\b", r"\bUPDATE\b", r"\bINSERT\b", r"\bDROP\b",
            r"\bALTER\b", r"\bCREATE\b", r"\bTRUNCATE\b", r"\bMERGE\b", r"\bGRANT\b"
        ]
        for pattern in disallowed_keywords:
            if re.search(pattern, no_strings, re.IGNORECASE):
                return {"error": f"Query contains disallowed keyword matching {pattern}."}

        # Remove trailing semicolon safely before appending LIMIT
        cleaned = re.sub(r";\s*$", "", cleaned)

        # Enforce limit if not already present (checking no_strings to be safe)
        if not re.search(r"\bLIMIT\s+\d+", no_strings, re.IGNORECASE):
            cleaned = f"{cleaned}\nLIMIT {limit}"

        try:
            job = self.client.query(cleaned)
            rows = [serialize_row(row) for row in job.result()]
            return {
                "row_count": len(rows),
                "data": rows,
                "total_bytes_processed": job.total_bytes_processed,
            }
        except Exception as e:
            logger.exception("Failed custom query: %s", e)
            return {"error": str(e)}
