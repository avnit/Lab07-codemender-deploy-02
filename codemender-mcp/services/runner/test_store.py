"""Tests for BigQueryStore schema setup against a mocked BigQuery client."""

import unittest
from unittest import mock

from google.api_core import exceptions

from services.runner.store import FINDING_SCHEMA, JOB_SCHEMA, BigQueryStore


def _store(client):
  with mock.patch("google.cloud.bigquery.Client", return_value=client):
    return BigQueryStore(project="p", dataset="codemender")


def _table_with(columns):
  table = mock.MagicMock()
  table.schema = []
  for name in columns:
    field = mock.MagicMock()
    field.name = name
    table.schema.append(field)
  return table


class TestEnsureSchema(unittest.TestCase):

  def test_existing_dataset_is_not_recreated(self):
    # A dataset-scoped service account cannot call datasets.insert; with the
    # dataset already present ensure_schema must not attempt it.
    client = mock.MagicMock()
    client.create_dataset.side_effect = exceptions.Forbidden(
        "User does not have bigquery.datasets.create permission")
    client.create_table.side_effect = [_table_with(JOB_SCHEMA), _table_with(FINDING_SCHEMA)]

    _store(client).ensure_schema()

    client.get_dataset.assert_called_once_with("p.codemender")
    client.create_dataset.assert_not_called()
    self.assertEqual(client.create_table.call_count, 2)
    client.update_table.assert_not_called()

  def test_missing_dataset_is_created(self):
    client = mock.MagicMock()
    client.get_dataset.side_effect = exceptions.NotFound("no dataset")
    client.create_table.side_effect = [_table_with(JOB_SCHEMA), _table_with(FINDING_SCHEMA)]

    _store(client).ensure_schema()

    client.create_dataset.assert_called_once()

  def test_missing_columns_are_added_to_existing_table(self):
    client = mock.MagicMock()
    client.create_table.side_effect = [
        _table_with(JOB_SCHEMA), _table_with(["issue_id", "title", "severity"])]

    _store(client).ensure_schema()

    updated, fields = client.update_table.call_args.args
    self.assertEqual(fields, ["schema"])
    names = [f.name for f in updated.schema]
    for column in ("finding_id", "scan_job_id", "repo", "rule_id", "sarif"):
      self.assertIn(column, names)


if __name__ == "__main__":
  unittest.main()
