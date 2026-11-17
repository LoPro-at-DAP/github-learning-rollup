#!/usr/bin/env python3
"""
validate_detection.py -- checks a detection repository before a change is merged.

WHAT IT CHECKS (in plain words)
  1. Every rule file in rules/ (*.yml or *.yaml) is valid YAML and has the fields a
     Sigma rule needs: title, id (a UUID), status (experimental, test or stable),
     description, logsource (a mapping), detection (a mapping that includes a
     condition) and level (informational, low, medium, high or critical).
  2. Every rule has a runbook with the same name in runbooks/ (for example
     rules/abc.yml needs runbooks/abc.md), and the runbook has these four headings:
         ## What it means
         ## Triage steps
         ## Evidence to save
         ## When to escalate
  3. Every change record named change-records/CR-*.md has the seven bold fields:
     **What changes:**  **Why:**  **Risk:**  **Rollback:**  **Test:**  **Approval:**  **Result:**
     with something written in each: a field is empty when nothing follows its label, on
     its line or below it, before the next field (for example a line **Why:** on its own).
     It also holds nothing left over from change-records/TEMPLATE.md: no CR-NNNN and none of
     the template's texts in angle brackets, such as <short title of the change>.
     The Result placeholder may stay until after the merge. TEMPLATE.md itself is not checked.
  4. No text file looks like it contains a secret: a private-key header, a GitHub
     token, an AWS access key ID, or a line such as "api_key: <12 or more characters>".
     The tools/ folder is skipped, because this file has to spell out those patterns.
     Binary files (pictures, packet captures) are skipped too.

HOW TO RUN IT
  From the top folder of the repository:
      python3 tools/validate_detection.py
  To check another folder (for example the samples/ folder of a roll-up repository):
      python3 tools/validate_detection.py samples

WHAT YOU SEE
  PASS <file>                                   the file passed every check that applies to it
  FAIL <file>: <reason>                         one line for each problem found
                                                (a record with template text left gets one line
                                                naming the first piece, then "(and N more)")
  FAIL <file>:<line>: possible secret (<kind>)  a line that looks like a secret
  <N> files checked, <M> problems               always the last line
  The exit code is 0 when there are no problems and 1 when there is at least one.
  A CI check (for example a GitHub Actions job) turns red when the exit code is not 0.

NEEDS
  Python 3.10 or newer and PyYAML (pip install pyyaml). It makes no network calls and
  never changes any file.
"""

import os
import re
import sys

try:
    import yaml
except ImportError:
    print("This tool needs PyYAML. Install it with: pip install pyyaml", file=sys.stderr)
    sys.exit(2)


# ---- What a valid rule, runbook and change record must contain -------------------------

RULE_FIELDS = ["title", "id", "status", "description", "logsource", "detection", "level"]
ALLOWED_STATUS = ["experimental", "test", "stable"]
ALLOWED_LEVEL = ["informational", "low", "medium", "high", "critical"]
UUID_SHAPE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

RUNBOOK_SECTIONS = [
    "## What it means",
    "## Triage steps",
    "## Evidence to save",
    "## When to escalate",
]

CHANGE_RECORD_FIELDS = ["What changes", "Why", "Risk", "Rollback", "Test", "Approval", "Result"]


# ---- Text left over from change-records/TEMPLATE.md ---------------------------------------
# What counts as a "template placeholder" here, exactly:
#   - CR-NNNN as a whole word (the template's stand-in for the record number, used in its
#     title and in its "Copy this file" paragraph), and
#   - one of the angle-bracket texts below, brackets included, character for character as
#     TEMPLATE.md has them.
# Nothing else counts. A "<" in ordinary writing ("a < b"), in a code span
# (`git revert -m 1 <merge-commit-id>`) or in your own words in brackets is never reported,
# because only these exact texts are searched for. A placeholder you half edited is not
# caught; the reviewer reads the record too.
# The Result placeholder is left out on purpose: Result is written after the merge, so a
# record goes into its pull request with that placeholder still in place.
# If TEMPLATE.md changes, change this list too (the kit's self-test compares the two).
TEMPLATE_NUMBER = re.compile(r"(?<![A-Za-z0-9])CR-NNNN(?![A-Za-z0-9])")
TEMPLATE_PLACEHOLDERS = [
    "<short title of the change>",
    "<which files, rules or settings change, in one or two sentences>",
    "<the problem this solves or the reason for the change>",
    "<what could go wrong, how likely, and who would notice>",
    "<how to undo it, for example: revert the merge commit of this pull request"
    " through a new pull request>",
    "<how you showed it works, and the result you expect, for example a rule-test line>",
    "<who approved it, where (the pull request review), and when>",
]
TEMPLATE_RESULT_PLACEHOLDER = (
    "<filled in after the merge: the merged commit ID, the date, and anything learned>"
)


# ---- Secret patterns ---------------------------------------------------------------------
# Each entry is (kind shown in the FAIL line, pattern). The first pattern that matches a
# line is reported, so one line gives at most one FAIL.
SECRET_PATTERNS = [
    ("private key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}")),
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    (
        "credential assignment",
        re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*\S{12,}"),
    ),
]


# ---- Folders that are never checked -------------------------------------------------------
SKIP_DIRS_ANYWHERE = {".git", "__pycache__", ".venv", "venv", "node_modules"}
SKIP_TOP_LEVEL_DIRS = {"tools"}  # this tool's own folder: it contains the patterns above


def list_files(root):
    """Return every file under root as a forward-slash path relative to root, sorted."""
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        here = os.path.relpath(dirpath, root)
        keep = []
        for name in dirnames:
            if name in SKIP_DIRS_ANYWHERE:
                continue
            if here == "." and name in SKIP_TOP_LEVEL_DIRS:
                continue
            keep.append(name)
        dirnames[:] = keep
        for name in filenames:
            rel = name if here == "." else os.path.join(here, name)
            found.append(rel.replace(os.sep, "/"))
    return sorted(found)


def read_text(path):
    """Return the file's text, or None if the file looks binary (it contains a NUL byte)."""
    with open(path, "rb") as handle:
        data = handle.read()
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def show(value):
    """Short, readable form of a YAML value for a FAIL line."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        text = repr(value)
    else:
        text = str(value)
    return text if len(text) <= 60 else text[:57] + "..."


def is_missing(value):
    return value is None or (isinstance(value, str) and value.strip() == "")


def check_rule(rel, text):
    """Return a list of FAIL lines for one rule file."""
    problems = []
    try:
        rule = yaml.safe_load(text)
    except yaml.YAMLError as err:
        mark = getattr(err, "problem_mark", None) or getattr(err, "context_mark", None)
        line = mark.line + 1 if mark is not None else 1
        return [f"FAIL {rel}: YAML parse error (line {line})"]
    if not isinstance(rule, dict):
        rule = {}  # an empty file or a bare list: every field is missing

    for field in RULE_FIELDS:
        value = rule.get(field)
        if is_missing(value):
            problems.append(f"FAIL {rel}: missing required field '{field}'")
            continue
        if field in ("title", "description") and not isinstance(value, str):
            problems.append(f"FAIL {rel}: invalid value for '{field}': {show(value)}")
        elif field == "id" and not (isinstance(value, str) and UUID_SHAPE.match(value)):
            problems.append(f"FAIL {rel}: invalid value for 'id': {show(value)}")
        elif field == "status" and value not in ALLOWED_STATUS:
            problems.append(f"FAIL {rel}: invalid value for 'status': {show(value)}")
        elif field == "level" and value not in ALLOWED_LEVEL:
            problems.append(f"FAIL {rel}: invalid value for 'level': {show(value)}")
        elif field == "logsource" and not (isinstance(value, dict) and value):
            problems.append(f"FAIL {rel}: invalid value for 'logsource': {show(value)}")
        elif field == "detection":
            if not isinstance(value, dict):
                problems.append(f"FAIL {rel}: invalid value for 'detection': {show(value)}")
            elif is_missing(value.get("condition")):
                problems.append(f"FAIL {rel}: missing required field 'detection.condition'")
    return problems


def check_runbook(rel, text):
    """Return a list of FAIL lines for one runbook (missing headings)."""
    headings = {line.strip().lower() for line in text.splitlines()}
    return [
        f"FAIL {rel}: missing section '{section}'"
        for section in RUNBOOK_SECTIONS
        if section.lower() not in headings
    ]


def field_label(field):
    """The bold label of one change-record field at the start of a line, such as **Why:**
    (a list item such as "- **Why:**" counts too)."""
    return re.compile(r"^\s*(?:[-*]\s+)?\*\*" + re.escape(field) + r":\*\*", re.MULTILINE)


def check_change_record(rel, text):
    """Return a list of FAIL lines for one change record (missing or empty fields, template text left)."""
    problems = []
    for field in CHANGE_RECORD_FIELDS:
        if not field_label(field).search(text):
            problems.append(f"FAIL {rel}: missing field '{field}'")
    for field in empty_fields(text):
        problems.append(f"FAIL {rel}: empty field '{field}'")
    left = template_leftovers(text)
    if left:
        more = f" (and {len(left) - 1} more)" if len(left) > 1 else ""
        problems.append(f"FAIL {rel}: still holds template placeholder {left[0]}{more}")
    return problems


def empty_fields(text):
    """Return the fields with nothing written for them, in file order.
    A field's text is everything after its label, on the label's line and on the lines below,
    up to the next field label or the end of the file. Only spaces and empty lines there make
    the field empty. A template placeholder is text, so Result's placeholder is not empty."""
    labels = []  # (label start, label end, field)
    for field in CHANGE_RECORD_FIELDS:
        match = field_label(field).search(text)
        if match:
            labels.append((match.start(), match.end(), field))
    labels.sort()
    empty = []
    for i, (_, end, field) in enumerate(labels):
        stop = labels[i + 1][0] if i + 1 < len(labels) else len(text)
        if not text[end:stop].strip():
            empty.append(field)
    return empty


def template_leftovers(text):
    """Return the template placeholders still in a change record, each once, in file order."""
    found = []  # (position, placeholder)
    for match in TEMPLATE_NUMBER.finditer(text):
        found.append((match.start(), "CR-NNNN"))
    for placeholder in TEMPLATE_PLACEHOLDERS:
        start = text.find(placeholder)
        if start != -1:
            found.append((start, placeholder))
    left = []
    for _, placeholder in sorted(found):
        if placeholder not in left:
            left.append(placeholder)
    return left


def scan_for_secrets(rel, text):
    """Return a list of FAIL lines, one for each line that looks like a secret."""
    problems = []
    for number, line in enumerate(text.splitlines(), start=1):
        for kind, pattern in SECRET_PATTERNS:
            if pattern.search(line):
                problems.append(f"FAIL {rel}:{number}: possible secret ({kind})")
                break
    return problems


def main(argv):
    if len(argv) > 2 or (len(argv) == 2 and argv[1] in ("-h", "--help")):
        print("usage: python3 tools/validate_detection.py [FOLDER]", file=sys.stderr)
        return 2
    root = argv[1] if len(argv) == 2 else "."
    if not os.path.isdir(root):
        print(f"error: '{root}' is not a folder", file=sys.stderr)
        return 2

    files = list_files(root)
    problems = {}  # path -> list of FAIL lines
    checked = []
    runbooks_done = set()

    for rel in files:
        text = read_text(os.path.join(root, rel))
        if text is None:
            continue  # binary file: skipped and not counted
        checked.append(rel)
        found = []
        parts = rel.split("/")
        is_rule = len(parts) == 2 and parts[0] == "rules" and rel.endswith((".yml", ".yaml"))
        if is_rule:
            found += check_rule(rel, text)
            stem = parts[1].rsplit(".", 1)[0]
            runbook = f"runbooks/{stem}.md"
            runbook_path = os.path.join(root, runbook)
            if not os.path.isfile(runbook_path):
                problems.setdefault(runbook, []).append(
                    f"FAIL {runbook}: missing runbook for {rel}"
                )
            elif runbook not in runbooks_done:
                runbooks_done.add(runbook)
                runbook_text = read_text(runbook_path) or ""
                problems.setdefault(runbook, []).extend(check_runbook(runbook, runbook_text))
        if len(parts) == 2 and parts[0] == "change-records" and re.match(r"CR-.*\.md$", parts[1]):
            found += check_change_record(rel, text)
        found += scan_for_secrets(rel, text)
        problems.setdefault(rel, []).extend(found)

    total = 0
    for rel in sorted(set(checked) | {p for p, lines in problems.items() if lines}):
        lines = problems.get(rel, [])
        if lines:
            for line in lines:
                print(line)
            total += len(lines)
        else:
            print(f"PASS {rel}")
    print(f"{len(checked)} files checked, {total} problems")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
