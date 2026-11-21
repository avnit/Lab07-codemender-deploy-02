"""Map CodeMender SARIF output onto CRITICAL / HIGH / MEDIUM / LOW.

`cm` reports each result with a SARIF `level` (error, warning, note, none) and,
on the rule (or the result), an optional `security-severity` property holding a
CVSS-style score from 0.0 to 10.0. The score is the more precise signal, so it
wins when present; the level is the fallback.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

CRITICAL, HIGH, MEDIUM, LOW = "CRITICAL", "HIGH", "MEDIUM", "LOW"
SEVERITIES = (CRITICAL, HIGH, MEDIUM, LOW)

# SARIF `level` (upper-cased) -> severity. Also used to normalize rows that were
# stored with the raw level before this mapping existed.
LEVEL_TO_SEVERITY: Dict[str, str] = {
    "ERROR": HIGH,
    "WARNING": MEDIUM,
    "NOTE": LOW,
    "NONE": LOW,
}

# Lower bound of each band for a `security-severity` score (CVSS v3 ratings).
_SCORE_BANDS = ((9.0, CRITICAL), (7.0, HIGH), (4.0, MEDIUM), (0.0, LOW))


def severity_from_score(score: Any) -> Optional[str]:
    """Severity for a `security-severity` score, or None if it is not a valid score."""
    try:
        value = float(str(score).strip())
    except (TypeError, ValueError):
        return None
    if not 0.0 <= value <= 10.0:
        return None
    for lower_bound, severity in _SCORE_BANDS:
        if value >= lower_bound:
            return severity
    return None


def normalize_severity(value: Any) -> str:
    """Normalize a stored severity or SARIF level to upper case, mapping levels.

    Values that are neither a SARIF level nor empty are returned upper-cased and
    otherwise untouched, so an existing CRITICAL / HIGH / MEDIUM / LOW is kept.
    """
    text = str(value or "").strip().upper()
    return LEVEL_TO_SEVERITY.get(text, text)


def _security_severity(document: Dict[str, Any]) -> Any:
    """The `security-severity` of a single-result SARIF document, if any."""
    for run in document.get("runs") or []:
        if not isinstance(run, dict):
            continue
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            props = result.get("properties")
            if isinstance(props, dict) and props.get("security-severity") is not None:
                return props["security-severity"]
            driver = (run.get("tool") or {}).get("driver") or {}
            rules = [r for r in driver.get("rules") or [] if isinstance(r, dict)]
            rule_id = result.get("ruleId") or (result.get("rule") or {}).get("id")
            rule_index = result.get("ruleIndex", (result.get("rule") or {}).get("index"))
            rule = next((r for r in rules if rule_id and r.get("id") == rule_id), None)
            if rule is None and isinstance(rule_index, int) and 0 <= rule_index < len(rules):
                rule = rules[rule_index]
            props = (rule or {}).get("properties")
            if isinstance(props, dict) and props.get("security-severity") is not None:
                return props["security-severity"]
    return None


def severity_for_finding(document: Optional[Dict[str, Any]], level: Any) -> str:
    """Severity for one finding: its `security-severity` score, else its level."""
    scored = severity_from_score(_security_severity(document or {}))
    if scored:
        return scored
    return LEVEL_TO_SEVERITY.get(str(level or "").strip().upper(), MEDIUM)


def severity_sql(column: str = "severity") -> str:
    """BigQuery expression that normalizes `column` the way `normalize_severity` does."""
    whens = " ".join(f"WHEN '{level}' THEN '{sev}'" for level, sev in LEVEL_TO_SEVERITY.items())
    upper = f"UPPER(CAST({column} AS STRING))"
    return f"(CASE {upper} {whens} ELSE {upper} END)"
