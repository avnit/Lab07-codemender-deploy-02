"""Persistence for jobs and findings: BigQuery in production, memory in tests.

BigQuery rows are written with DML `INSERT` / load jobs rather than the
streaming API, because rows in the streaming buffer cannot be `UPDATE`d for up
to ~90 minutes and validate/fix update findings soon after the scan.
"""

from __future__ import annotations

import copy
import datetime
import threading
from typing import Any, Iterable, Optional, Protocol

# Column name -> BigQuery type. Order defines the table schema.
JOB_SCHEMA: dict[str, str] = {
    "job_id": "STRING",
    "kind": "STRING",  # find | validate | fix
    "status": "STRING",  # RUNNING | INGESTING | SUCCEEDED | FAILED
    "repo": "STRING",
    "ref": "STRING",
    "commit_sha": "STRING",
    "finding_id": "STRING",
    "patch_mode": "STRING",
    "execution": "STRING",
    "gcs_prefix": "STRING",
    "payload_uri": "STRING",
    "finding_count": "INT64",
    "error": "STRING",
    "result": "STRING",  # JSON summary
    "created_at": "TIMESTAMP",
    "updated_at": "TIMESTAMP",
    "completed_at": "TIMESTAMP",
}

FINDING_SCHEMA: dict[str, str] = {
    "finding_id": "STRING",
    "issue_id": "STRING",
    "event_type": "STRING",
    "session_id": "STRING",
    "scan_job_id": "STRING",
    "repo": "STRING",
    "repository": "STRING",
    "ref": "STRING",
    "commit_sha": "STRING",
    "payload_uri": "STRING",
    "fingerprint": "STRING",
    "rule_id": "STRING",
    "cwe_id": "STRING",
    "vulnerability_type": "STRING",
    "severity": "STRING",
    "title": "STRING",
    "description": "STRING",
    "message": "STRING",
    "file_path": "STRING",
    "line_number": "INT64",
    "start_line": "INT64",
    "end_line": "INT64",
    # OPEN | VERIFIED | FALSE_POSITIVE | INCONCLUSIVE | FIXED | PATCHED
    "status": "STRING",
    "verify_status": "STRING",  # VERIFIED | DISMISSED | OPEN | FAILED
    "dismiss_reason": "STRING",
    "fix_status": "STRING",  # FIXED | NO_PATCH | FAILED | PATCHED
    "sarif": "STRING",  # single-result SARIF document
    "verified_sarif": "STRING",
    "patch": "STRING",  # unified diff from cm fix
    "patch_ref": "STRING",
    "patch_branch": "STRING",
    "patch_commit": "STRING",
    "pr_url": "STRING",
    "wiz_issue_id": "STRING",
    "last_job_id": "STRING",
    "created_at": "TIMESTAMP",
    "updated_at": "TIMESTAMP",
}

# Columns returned by list_findings (large blobs omitted).
FINDING_SUMMARY_COLUMNS = (
    "finding_id", "scan_job_id", "repo", "ref", "commit_sha", "fingerprint", "rule_id", "severity",
    "message", "file_path", "start_line", "end_line", "status",
    "verify_status", "fix_status", "pr_url", "updated_at",
)


def utc_now() -> str:
  return datetime.datetime.now(datetime.timezone.utc).isoformat()


class Store(Protocol):
  def ensure_schema(self) -> None: ...
  def insert_job(self, row: dict[str, Any]) -> None: ...
  def update_job(self, job_id: str, fields: dict[str, Any]) -> None: ...
  def get_job(self, job_id: str) -> Optional[dict[str, Any]]: ...
  def list_jobs(self, status: str, limit: int = 100) -> list[dict[str, Any]]: ...
  def insert_findings(self, rows: list[dict[str, Any]]) -> None: ...
  def get_finding(self, finding_id: str) -> Optional[dict[str, Any]]: ...
  def list_findings(
      self,
      repo: str = "",
      status: str = "",
      scan_job_id: str = "",
      limit: int = 100,
  ) -> list[dict[str, Any]]: ...
  def update_finding(self, finding_id: str, fields: dict[str, Any]) -> None: ...


def _check_columns(fields: Iterable[str], schema: dict[str, str]) -> None:
  unknown = [f for f in fields if f not in schema]
  if unknown:
    raise ValueError(f"Unknown column(s): {unknown}")


class InMemoryStore:
  """Thread-safe in-memory `Store` for tests and local development."""

  def __init__(self) -> None:
    self._lock = threading.Lock()
    self.jobs: dict[str, dict[str, Any]] = {}
    self.findings: dict[str, dict[str, Any]] = {}

  def ensure_schema(self) -> None:
    return None

  def insert_job(self, row: dict[str, Any]) -> None:
    _check_columns(row, JOB_SCHEMA)
    with self._lock:
      self.jobs[row["job_id"]] = copy.deepcopy(row)

  def update_job(self, job_id: str, fields: dict[str, Any]) -> None:
    _check_columns(fields, JOB_SCHEMA)
    with self._lock:
      self.jobs[job_id].update(copy.deepcopy(fields))

  def get_job(self, job_id: str) -> Optional[dict[str, Any]]:
    with self._lock:
      row = self.jobs.get(job_id)
      return copy.deepcopy(row) if row else None

  def list_jobs(self, status: str, limit: int = 100) -> list[dict[str, Any]]:
    with self._lock:
      return [copy.deepcopy(j) for j in self.jobs.values()
              if j.get("status") == status][:limit]

  def insert_findings(self, rows: list[dict[str, Any]]) -> None:
    with self._lock:
      for row in rows:
        _check_columns(row, FINDING_SCHEMA)
        self.findings[row["finding_id"]] = copy.deepcopy(row)

  def get_finding(self, finding_id: str) -> Optional[dict[str, Any]]:
    with self._lock:
      row = self.findings.get(finding_id)
      if not row:
        return None
      out = copy.deepcopy(row)
      if not out.get("repo") and out.get("repository"):
        out["repo"] = out["repository"]
      return out

  def list_findings(self, repo="", status="", scan_job_id="", limit=100):
    with self._lock:
      rows = []
      for f in self.findings.values():
        eff_repo = f.get("repo") or f.get("repository") or ""
        if repo and eff_repo != repo:
          continue
        if status and f.get("status") != status:
          continue
        if scan_job_id and f.get("scan_job_id") != scan_job_id:
          continue
        summary = {k: f.get(k) for k in FINDING_SUMMARY_COLUMNS}
        if not summary.get("repo") and eff_repo:
          summary["repo"] = eff_repo
        if not summary.get("rule_id"):
          summary["rule_id"] = f.get("cwe_id") or f.get("vulnerability_type")
        if summary.get("start_line") is None and f.get("line_number") is not None:
          summary["start_line"] = f.get("line_number")
        rows.append(summary)
    return rows[:limit]

  def update_finding(self, finding_id: str, fields: dict[str, Any]) -> None:
    _check_columns(fields, FINDING_SCHEMA)
    with self._lock:
      self.findings[finding_id].update(copy.deepcopy(fields))


class BigQueryStore:
  """`Store` backed by two BigQuery tables: `jobs` and `findings`."""

  def __init__(self, project: str, dataset: str, location: str = "US") -> None:
    from google.cloud import bigquery  # pylint: disable=import-outside-toplevel

    self._bq = bigquery
    self._client = bigquery.Client(project=project)
    self._dataset = f"{project}.{dataset}"
    self._location = location
    self._jobs_table = f"{self._dataset}.jobs"
    self._findings_table = f"{self._dataset}.findings"

  # -- schema --------------------------------------------------------------
  def ensure_schema(self) -> None:
    ds = self._bq.Dataset(self._dataset)
    ds.location = self._location
    self._client.create_dataset(ds, exists_ok=True)
    for table_id, schema in (
        (self._jobs_table, JOB_SCHEMA),
        (self._findings_table, FINDING_SCHEMA),
    ):
      desired_fields = [self._bq.SchemaField(n, t) for n, t in schema.items()]
      table = self._bq.Table(table_id, schema=desired_fields)
      table.time_partitioning = self._bq.TimePartitioning(field="created_at")
      created = self._client.create_table(table, exists_ok=True)
      existing_names = {f.name.lower() for f in created.schema}
      missing = [f for f in desired_fields if f.name.lower() not in existing_names]
      if missing:
        created.schema = list(created.schema) + missing
        self._client.update_table(created, ["schema"])

  # -- helpers -------------------------------------------------------------
  def _param(self, name: str, bq_type: str, value: Any):
    return self._bq.ScalarQueryParameter(name, bq_type, value)

  def _query(self, sql: str, params: list) -> list[dict[str, Any]]:
    job = self._client.query(
        sql, job_config=self._bq.QueryJobConfig(query_parameters=params)
    )
    return [dict(row.items()) for row in job.result()]

  def _insert(self, table: str, schema: dict[str, str], row: dict[str, Any]) -> None:
    _check_columns(row, schema)
    cols = list(row)
    sql = (
        f"INSERT INTO `{table}` ({', '.join(cols)}) "
        f"VALUES ({', '.join('@' + c for c in cols)})"
    )
    self._query(sql, [self._param(c, schema[c], row[c]) for c in cols])

  def _update(
      self, table: str, schema: dict[str, str], key: str, key_value: str,
      fields: dict[str, Any],
  ) -> None:
    _check_columns(fields, schema)
    if not fields:
      return
    sets = ", ".join(f"{c} = @{c}" for c in fields)
    sql = f"UPDATE `{table}` SET {sets} WHERE {key} = @pk_value"
    params = [self._param(c, schema[c], v) for c, v in fields.items()]
    params.append(self._param("pk_value", "STRING", key_value))
    self._query(sql, params)

  @staticmethod
  def _normalize(row: dict[str, Any]) -> dict[str, Any]:
    out = {
        k: (v.isoformat() if isinstance(v, datetime.datetime) else v)
        for k, v in row.items()
    }
    if "repo" in out and not out.get("repo") and out.get("repository"):
      out["repo"] = out["repository"]
    if "rule_id" in out and not out.get("rule_id") and (
        out.get("cwe_id") or out.get("vulnerability_type")
    ):
      out["rule_id"] = out.get("cwe_id") or out.get("vulnerability_type")
    if (
        "start_line" in out
        and out.get("start_line") is None
        and out.get("line_number") is not None
    ):
      out["start_line"] = out["line_number"]
    return out

  # -- jobs ----------------------------------------------------------------
  def insert_job(self, row: dict[str, Any]) -> None:
    self._insert(self._jobs_table, JOB_SCHEMA, row)

  def update_job(self, job_id: str, fields: dict[str, Any]) -> None:
    self._update(self._jobs_table, JOB_SCHEMA, "job_id", job_id, fields)

  def get_job(self, job_id: str) -> Optional[dict[str, Any]]:
    rows = self._query(
        f"SELECT * FROM `{self._jobs_table}` WHERE job_id = @id LIMIT 1",
        [self._param("id", "STRING", job_id)],
    )
    return self._normalize(rows[0]) if rows else None

  def list_jobs(self, status: str, limit: int = 100) -> list[dict[str, Any]]:
    rows = self._query(
        f"SELECT * FROM `{self._jobs_table}` WHERE status = @status"
        " ORDER BY created_at DESC LIMIT @limit",
        [self._param("status", "STRING", status),
         self._param("limit", "INT64", limit)],
    )
    return [self._normalize(r) for r in rows]

  # -- findings ------------------------------------------------------------
  def insert_findings(self, rows: list[dict[str, Any]]) -> None:
    if not rows:
      return
    for row in rows:
      _check_columns(row, FINDING_SCHEMA)
    job_config = self._bq.LoadJobConfig(
        schema=[self._bq.SchemaField(n, t) for n, t in FINDING_SCHEMA.items()],
        write_disposition=self._bq.WriteDisposition.WRITE_APPEND,
    )
    self._client.load_table_from_json(
        rows, self._findings_table, job_config=job_config
    ).result()

  def get_finding(self, finding_id: str) -> Optional[dict[str, Any]]:
    rows = self._query(
        f"SELECT * FROM `{self._findings_table}`"
        " WHERE finding_id = @id OR issue_id = @id LIMIT 1",
        [self._param("id", "STRING", finding_id)],
    )
    return self._normalize(rows[0]) if rows else None

  def list_findings(self, repo="", status="", scan_job_id="", limit=100):
    where, params = [], [self._param("limit", "INT64", limit)]
    if repo:
      where.append("(repo = @repo OR repository = @repo)")
      params.append(self._param("repo", "STRING", repo))
    for col, val in (("status", status), ("scan_job_id", scan_job_id)):
      if val:
        where.append(f"{col} = @{col}")
        params.append(self._param(col, "STRING", val))
    clause = f"WHERE {' AND '.join(where)}" if where else ""
    select_cols = (
        "finding_id, scan_job_id, COALESCE(repo, repository) AS repo, ref,"
        " commit_sha, fingerprint,"
        " COALESCE(rule_id, cwe_id, vulnerability_type) AS rule_id, severity,"
        " COALESCE(message, title) AS message, file_path,"
        " COALESCE(start_line, line_number) AS start_line, end_line, status,"
        " verify_status, fix_status, pr_url, updated_at"
    )
    rows = self._query(
        f"SELECT {select_cols} FROM `{self._findings_table}`"
        f" {clause} ORDER BY created_at DESC, finding_id LIMIT @limit",
        params,
    )
    return [self._normalize(r) for r in rows]

  def update_finding(self, finding_id: str, fields: dict[str, Any]) -> None:
    self._update(self._findings_table, FINDING_SCHEMA, "finding_id",
                 finding_id, fields)
