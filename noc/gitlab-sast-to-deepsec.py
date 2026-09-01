#!/usr/bin/env python3
"""Convert an opengrep GitLab SAST report into deepsec FileRecord files.

deepsec's `process` stage consumes per-file records at
data/<projectId>/files/<path>.json. Each record (FileRecord) carries a
`candidates` array of CandidateMatch objects that the AI reviews:

    FileRecord     = {filePath, projectId, candidates, lastScannedAt,
                      lastScannedRunId, fileHash, findings,
                      analysisHistory, status}
    CandidateMatch = {vulnSlug, lineNumbers, snippet, matchedPattern}

Input: a GitLab SAST JSON report, i.e. what `opengrep scan --gitlab-sast`
writes (gl-sast-report.json). Each vulnerability becomes one candidate on
the record for its source file; the report is language-agnostic, so any
file type opengrep scanned works.

Usage:
    gitlab-sast-to-deepsec.py REPORT --project-id ID [--data-dir DIR]
        [--root PATH] [--run-id ID] [--reset-status]

Behaviour mirrors deepsec's own scan write path (packages/scanner):
merge candidates into existing records with dedupe, stamp scan metadata,
hash the source when --root is given, and leave existing record status
untouched (new records start as "pending" so `process` picks them up).
"""

import argparse
import hashlib
import json
import os
import re
import secrets
import sys
from datetime import datetime, timezone


# --------------------------------------------------------------------------
# GitLab SAST field extraction


def slug_for(vuln):
    """Candidate vulnSlug: prefer a CWE identifier, else name, else id."""
    for ident in vuln.get("identifiers") or []:
        hay = " ".join(
            part
            for part in (ident.get("value"), ident.get("name"), ident.get("type"))
            if part
        )
        if re.search(r"cwe", hay, re.IGNORECASE):
            return ident.get("name") or ident.get("value") or "CWE"
    return vuln.get("name") or vuln.get("id") or "opengrep"


def pattern_for(vuln):
    """Candidate matchedPattern: human-readable context for the AI."""
    bits = []
    severity = (vuln.get("severity") or "").strip()
    if severity:
        bits.append("[%s]" % severity.upper())
    name = (vuln.get("name") or "").strip()
    if name:
        bits.append(name)
    urls = [i["url"] for i in (vuln.get("identifiers") or []) if i.get("url")]
    if urls:
        bits.append("ids: " + ", ".join(urls))
    desc = squish(vuln.get("description"))
    if desc:
        bits.append(desc)
    fix = squish(vuln.get("solution"), 300)
    if fix:
        bits.append("fix: " + fix)
    return " - ".join(bits) if bits else "opengrep finding"


def vuln_line(vuln):
    """Best 1-indexed line for the finding, else None."""
    loc = vuln.get("location") or {}
    for value in (loc.get("start_line"), loc.get("end_line")):
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.isdigit():
            return int(value)
    return None


def squish(text, limit=400):
    """Collapse whitespace, trim, and cap length; empty in -> empty out."""
    if not text:
        return ""
    flat = re.sub(r"\s+", " ", str(text)).strip()
    return flat[:limit]


def normalize_path(raw):
    """Repo-relative forward-slash path; None when missing/unsafe."""
    if not raw:
        return None
    path = raw.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    path = path.lstrip("/")
    while "//" in path:
        path = path.replace("//", "/")
    parts = [p for p in path.split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return None
    return "/".join(parts)


# --------------------------------------------------------------------------
# deepsec FileRecord helpers (matching packages/scanner write semantics)


def new_record(project_id, rel_path):
    return {
        "filePath": rel_path,
        "projectId": project_id,
        "candidates": [],
        "lastScannedAt": "",
        "lastScannedRunId": "",
        "fileHash": "",
        "findings": [],
        "analysisHistory": [],
        "status": "pending",
    }


def load_record(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def candidate_key(cand):
    """Dedupe identity, same as deepsec scan: slug+pattern+lines."""
    lines = ",".join(str(n) for n in cand["lineNumbers"])
    return (cand["vulnSlug"], cand["matchedPattern"], lines)


def file_hash(root, rel_path):
    try:
        with open(os.path.join(root, rel_path), "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()
    except OSError:
        return ""


def file_snippet(root, rel_path, line):
    """Plus/minus three lines around the finding, or None."""
    try:
        with open(os.path.join(root, rel_path), "r", encoding="utf-8") as handle:
            content = handle.read().replace("\r\n", "\n")
    except (OSError, UnicodeDecodeError):
        return None
    lines = content.split("\n")
    lo = max(0, line - 4)
    hi = min(len(lines), line + 3)
    return "\n".join(lines[lo:hi]) if line <= len(lines) else None


def make_candidate(vuln, root, rel_path, line):
    snippet = file_snippet(root, rel_path, line) if root else None
    return {
        "vulnSlug": slug_for(vuln),
        "lineNumbers": [line],
        "snippet": snippet if snippet else squish(vuln.get("description"), 300),
        "matchedPattern": pattern_for(vuln),
    }


# --------------------------------------------------------------------------


def convert(report, project_id, data_dir, root, run_id, reset_status):
    now = datetime.now(timezone.utc).isoformat()
    by_file = {}
    skipped = 0

    for vuln in report.get("vulnerabilities") or []:
        loc = vuln.get("location") or {}
        rel = normalize_path(loc.get("file"))
        line = vuln_line(vuln)
        if not rel or line is None:
            skipped += 1
            continue
        by_file.setdefault(rel, []).append(make_candidate(vuln, root, rel, line))

    if not by_file:
        print("no usable findings (skipped %d); nothing written" % skipped)
        return 0

    files_dir = os.path.join(data_dir, project_id, "files")
    written = 0
    for rel_path in sorted(by_file):
        out_path = os.path.join(files_dir, rel_path) + ".og.json"
        os.makedirs(os.path.dirname(out_path), exist_ok=True)

        record = load_record(out_path) or new_record(project_id, rel_path)
        candidates = record.get("candidates")
        if not isinstance(candidates, list):
            candidates = []
            record["candidates"] = candidates

        added = 0
        for cand in by_file[rel_path]:
            if not any(candidate_key(c) == candidate_key(cand) for c in candidates):
                candidates.append(cand)
                added += 1
        if not candidates:
            continue

        record["lastScannedAt"] = now
        record["lastScannedRunId"] = run_id
        record["fileHash"] = file_hash(root, rel_path) if root else record.get("fileHash", "")
        if reset_status:
            record["status"] = "pending"

        tmp_path = out_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(record, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        os.replace(tmp_path, out_path)
        print("  %s (+%d candidates)" % (rel_path, added))
        written += 1

    print("done: %d file record(s) updated, %d finding(s) skipped" % (written, skipped))
    return written


def main():
    parser = argparse.ArgumentParser(
        description="Convert opengrep GitLab SAST JSON into deepsec FileRecord files.")
    parser.add_argument("report", help="GitLab SAST JSON (opengrep --gitlab-sast output)")
    parser.add_argument("--project-id", required=True,
                        help="deepsec project id (dir name under data/)")
    parser.add_argument("--data-dir", default="data", help="deepsec data root")
    parser.add_argument("--root", default=None,
                        help="repo root for snippets and hashes (optional)")
    parser.add_argument("--run-id", default=None,
                        help="runId to stamp (default: <UTC timestamp>-<rand4>)")
    parser.add_argument("--reset-status", action="store_true",
                        help="force records back to pending for reprocessing")
    args = parser.parse_args()

    try:
        with open(args.report, "r", encoding="utf-8") as handle:
            report = json.load(handle)
    except OSError as exc:
        sys.exit("error: cannot read report: %s" % exc)
    except ValueError as exc:
        sys.exit("error: report is not valid JSON: %s" % exc)

    if not isinstance(report, dict):
        sys.exit("error: report must be a JSON object")
    if not isinstance(report.get("vulnerabilities"), list):
        sys.exit("error: no vulnerabilities array in report")

    run_id = args.run_id
    if not run_id:
        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
        run_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + "".join(
            secrets.choice(alphabet) for _ in range(4))

    convert(report, args.project_id, args.data_dir, args.root, run_id,
            args.reset_status)


if __name__ == "__main__":
    main()