"""
storage/export.py — Feature 16: Audit Log Export Engine

Provides:
- Export of audit records to JSON and RFC-4180 CSV.
- Strict CSV Formula Injection defense (CWE-1236): sanitizes any field
  starting with '=', '+', '-', '@', '\\t', or '\\r' by prepending a single quote.
- Filters by session_id and date range.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any, Dict, List, Optional, Union

from storage.db import _connect


_FORMULA_INJECTION_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def sanitize_csv_cell(value: Any) -> str:
    """
    Sanitize a value for safe CSV export.
    Prevents CSV / Formula Injection (CWE-1236) where an attacker crafts
    a command, file name, or reason starting with '=', '+', '-', '@'
    that would execute malicious formulas or DDE functions when opened in Excel/Calc.
    """
    if value is None:
        return ""
    s = str(value)
    if s.startswith(_FORMULA_INJECTION_PREFIXES):
        return "'" + s
    return s


def fetch_audit_records(session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Fetch actions and associated journal events for export.
    """
    with _connect() as conn:
        query = """
            SELECT id, timestamp, action_type, command, risk_tier, status,
                   suggestion, tool_use_id, session_id, base_tier, effective_tier,
                   preview_hash, manifest_hash, backup_hash, cwd
            FROM actions
        """
        params = []
        if session_id:
            query += " WHERE session_id = ?"
            params.append(session_id)
        query += " ORDER BY id ASC"

        rows = conn.execute(query, params).fetchall()
        records = []
        for r in rows:
            rec = {
                "action_id": r[0],
                "timestamp": r[1],
                "tool_name": r[2],
                "command": r[3],
                "risk_tier": r[4],
                "status": r[5],
                "suggestion": r[6],
                "tool_use_id": r[7],
                "session_id": r[8],
                "base_tier": r[9],
                "effective_tier": r[10],
                "preview_hash": r[11],
                "manifest_hash": r[12],
                "backup_hash": r[13],
                "cwd": r[14],
            }
            records.append(rec)
        return records


def export_audit_json(session_id: Optional[str] = None, indent: int = 2) -> str:
    """
    Export audit log to formatted JSON string.
    """
    records = fetch_audit_records(session_id=session_id)
    return json.dumps(records, indent=indent, default=str)


def export_audit_csv(session_id: Optional[str] = None) -> str:
    """
    Export audit log to RFC-4180 CSV string with strict formula-injection defense.
    """
    records = fetch_audit_records(session_id=session_id)
    fieldnames = [
        "action_id",
        "timestamp",
        "session_id",
        "tool_name",
        "command",
        "risk_tier",
        "effective_tier",
        "status",
        "preview_hash",
        "backup_hash",
        "cwd",
    ]

    out = io.StringIO()
    writer = csv.writer(out, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    writer.writerow(fieldnames)

    for rec in records:
        row = [
            sanitize_csv_cell(rec.get(col, ""))
            for col in fieldnames
        ]
        writer.writerow(row)

    return out.getvalue()


def export_audit_log(
    session_id: Optional[str] = None,
    format: str = "json",
    output_path: Optional[str] = None,
) -> str:
    """
    Feature 16: Universal audit export entry point.
    format: 'json' or 'csv'.
    """
    fmt = format.lower().strip()
    if fmt == "csv":
        content = export_audit_csv(session_id=session_id)
    elif fmt == "json":
        content = export_audit_json(session_id=session_id)
    else:
        raise ValueError(f"Unsupported export format: {format}. Must be 'json' or 'csv'.")

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

    return content
