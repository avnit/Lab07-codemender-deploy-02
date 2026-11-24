"""Tests for GitClient credential handling and clone error reporting."""

import base64
import subprocess
from pathlib import Path
import unittest
from unittest import mock

from services.runner.repo import GitClient, GitHubClient, RepoError, RepoRef

_PROMPT_ERR = (b"Cloning into '/tmp/x'...\nfatal: could not read Username for"
               b" 'https://github.com': terminal prompts disabled\n")
_NOT_FOUND_ERR = b"remote: Repository not found.\nfatal: repository 'https://github.com/a/b.git/' not found\n"


def _result(returncode=0, stderr=b""):
  return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=b"abc123\n", stderr=stderr)


class TestGitClientAuth(unittest.TestCase):

  def setUp(self):
    self.repo = RepoRef.parse("avnit/homelab-dashboard")

  def _clone(self, client, result):
    with mock.patch("services.runner.repo.subprocess.run", return_value=result) as run:
      try:
        client.clone(self.repo, Path("/tmp/cm-test/repo"))
      finally:
        self.cmd = run.call_args_list[0].args[0]
        self.env = run.call_args_list[0].kwargs["env"]

  def test_token_is_sent_as_basic_auth_header_without_whitespace(self):
    self._clone(GitClient("ghp_secret\n"), _result())
    header = next(a for a in self.cmd if a.startswith("http.https://github.com/.extraHeader="))
    encoded = header.rsplit(" ", 1)[1]
    self.assertEqual(base64.b64decode(encoded).decode(), "x-access-token:ghp_secret")
    self.assertEqual(self.env["GIT_TERMINAL_PROMPT"], "0")

  def test_no_token_sends_no_header(self):
    self._clone(GitClient("  \n"), _result())
    self.assertFalse(any("extraHeader" in a for a in self.cmd))

  def test_missing_token_on_private_repo_says_so(self):
    with self.assertRaises(RepoError) as ctx:
      self._clone(GitClient(""), _result(128, _PROMPT_ERR))
    message = str(ctx.exception)
    self.assertIn("could not read Username", message)
    self.assertIn("no GitHub token is configured", message)
    self.assertIn("avnit/homelab-dashboard", message)

  def test_rejected_token_says_so_and_is_not_leaked(self):
    with self.assertRaises(RepoError) as ctx:
      self._clone(GitClient("ghp_secret"), _result(128, _PROMPT_ERR + b"ghp_secret"))
    message = str(ctx.exception)
    self.assertIn("GitHub rejected the configured GITHUB_TOKEN", message)
    self.assertNotIn("ghp_secret", message)

  def test_token_without_access_to_repo_says_so(self):
    with self.assertRaises(RepoError) as ctx:
      self._clone(GitClient("ghp_secret"), _result(128, _NOT_FOUND_ERR))
    self.assertIn("cannot see avnit/homelab-dashboard", str(ctx.exception))

  def test_unrelated_failure_has_no_auth_hint(self):
    with self.assertRaises(RepoError) as ctx:
      self._clone(GitClient("ghp_secret"), _result(128, b"fatal: unable to access: timeout\n"))
    self.assertNotIn("[", str(ctx.exception))

  def test_github_client_strips_token(self):
    self.assertEqual(GitHubClient("ghp_secret\n")._token, "ghp_secret")  # pylint: disable=protected-access


if __name__ == "__main__":
  unittest.main()
