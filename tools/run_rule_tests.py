#!/usr/bin/env python3
"""
run_rule_tests.py -- runs each detection rule against its synthetic sample events and
checks that it matches the number of events it should.

HOW IT WORKS (in plain words)
  For every test file tests/<name>.json, for example:
      {"events": "samples/wireguard_handshakes.jsonl", "expect_matches": 3}
  the tool
    1. reads the rule rules/<name>.yml,
    2. reads the events file (the path is relative to the tests/ folder). Each line of
       a .jsonl file is one event written as JSON,
    3. counts how many events the rule matches,
    4. compares that count with "expect_matches".
  A rule that suddenly matches 0 events, or far more than expected, is a broken rule
  even when its YAML is valid. This is the test that catches it.

WHICH SIGMA FEATURES IT UNDERSTANDS (a small, practice-sized subset)
  - A selection is a mapping of field: value. Every key must match (AND).
  - A list of values for one field means any of them may match (OR).
  - A list of mappings means any one mapping may match (OR).
  - Field modifiers: field|contains, field|startswith, field|endswith, and |all to
    require every listed value. Without a modifier the value must be equal.
  - Text comparisons ignore upper/lower case. A * in a plain value matches anything.
  - Conditions: a selection name, and, or, not, brackets, "1 of selection*",
    "all of selection*", "1 of them", "all of them".
  Anything else (for example "| count() > 5") is reported as unsupported.

HOW TO RUN IT
  From the top folder of the repository:
      python3 tools/run_rule_tests.py
  Only some rules:            python3 tools/run_rule_tests.py --rule wireguard_new_address
  Another folder (roll-up):   python3 tools/run_rule_tests.py samples

WHAT YOU SEE
  PASS <name>: <k> matches (expected <n>)
  FAIL <name>: <k> matches (expected <n>)
  <passed>/<total> rule tests passed            (always the last line)
  The exit code is 1 if any test fails (or no tests were found), otherwise 0.
  If a rule cannot be read at all, the reason is printed on the error stream.

NEEDS
  Python 3.10 or newer and PyYAML (pip install pyyaml). No network calls; it never
  changes any file.
"""

import argparse
import json
import os
import re
import sys

try:
    import yaml
except ImportError:
    print("This tool needs PyYAML. Install it with: pip install pyyaml", file=sys.stderr)
    sys.exit(2)


class RuleError(Exception):
    """A rule, test file or events file that cannot be evaluated."""


# ---- Comparing one event value with one rule value ---------------------------------------

def as_text(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def wildcard_to_regex(text):
    parts = []
    for char in text:
        if char == "*":
            parts.append(".*")
        elif char == "?":
            parts.append(".")
        else:
            parts.append(re.escape(char))
    return re.compile("^" + "".join(parts) + "$", re.IGNORECASE | re.DOTALL)


def value_matches(actual, expected, modifier):
    if expected is None:
        return actual is None
    if actual is None:
        return False
    if modifier in ("contains", "startswith", "endswith"):
        have, want = as_text(actual).lower(), as_text(expected).lower()
        if modifier == "contains":
            return want in have
        if modifier == "startswith":
            return have.startswith(want)
        return have.endswith(want)
    numbers = (int, float)
    if (
        isinstance(actual, numbers) and isinstance(expected, numbers)
        and not isinstance(actual, bool) and not isinstance(expected, bool)
    ):
        return actual == expected
    want = as_text(expected)
    if "*" in want or "?" in want:
        return bool(wildcard_to_regex(want).match(as_text(actual)))
    return as_text(actual).lower() == want.lower()


MISSING = object()


def field_value(event, field):
    """Look up a field; a dotted name such as ssh.client.software_version walks into nested data."""
    if field in event:
        return event[field]
    current = event
    for part in field.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return MISSING
    return current


def key_matches(event, key, expected):
    field, *modifiers = key.split("|")
    match_all = "all" in modifiers
    modifiers = [m for m in modifiers if m != "all"]
    if len(modifiers) > 1:
        raise RuleError(f"only one modifier per field is supported: '{key}'")
    modifier = modifiers[0] if modifiers else None
    if modifier not in (None, "contains", "startswith", "endswith"):
        raise RuleError(f"unsupported modifier '{modifier}' in '{key}'")
    actual = field_value(event, field)
    if actual is MISSING:
        actual = None
    wanted = expected if isinstance(expected, list) else [expected]
    if not wanted:
        return False
    results = [value_matches(actual, value, modifier) for value in wanted]
    return all(results) if match_all else any(results)


def search_matches(event, search, name):
    if isinstance(search, dict):
        return all(key_matches(event, key, value) for key, value in search.items())
    if isinstance(search, list) and all(isinstance(item, dict) for item in search):
        return any(search_matches(event, item, name) for item in search)
    raise RuleError(f"search '{name}' must be a mapping or a list of mappings")


# ---- Reading the condition ("selection and not filter") -----------------------------------

TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")


def tokenize(condition):
    tokens, position = [], 0
    condition = condition.strip()
    while position < len(condition):
        found = TOKEN.match(condition, position)
        if not found:
            raise RuleError(f"unsupported condition: '{condition}'")
        tokens.append(found.group(1))
        position = found.end()
    return tokens


class Condition:
    """A tiny recursive-descent reader for the condition grammar listed at the top."""

    def __init__(self, text, searches):
        self.text = text
        self.tokens = tokenize(text)
        self.position = 0
        self.searches = searches

    def peek(self):
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def take(self):
        token = self.peek()
        self.position += 1
        return token

    def parse(self):
        tree = self.parse_or()
        if self.peek() is not None:
            raise RuleError(f"unsupported condition: '{self.text}'")
        return tree

    def parse_or(self):
        left = self.parse_and()
        while self.peek() is not None and self.peek().lower() == "or":
            self.take()
            left = ("or", left, self.parse_and())
        return left

    def parse_and(self):
        left = self.parse_not()
        while self.peek() is not None and self.peek().lower() == "and":
            self.take()
            left = ("and", left, self.parse_not())
        return left

    def parse_not(self):
        if self.peek() is not None and self.peek().lower() == "not":
            self.take()
            return ("not", self.parse_not())
        return self.parse_atom()

    def parse_atom(self):
        token = self.take()
        if token is None:
            raise RuleError(f"unsupported condition: '{self.text}'")
        if token == "(":
            inner = self.parse_or()
            if self.take() != ")":
                raise RuleError(f"unbalanced brackets in condition: '{self.text}'")
            return inner
        if token.lower() in ("1", "all", "any") and (self.peek() or "").lower() == "of":
            self.take()
            target = self.take()
            if target is None:
                raise RuleError(f"unsupported condition: '{self.text}'")
            if target.lower() == "them":
                names = [n for n in self.searches if not n.startswith("_")]
            else:
                pattern = wildcard_to_regex(target)
                names = [n for n in self.searches if pattern.match(n)]
            if not names:
                raise RuleError(f"'{token} of {target}' matches no selection")
            return ("all" if token.lower() == "all" else "any", names)
        if token not in self.searches:
            raise RuleError(f"condition names '{token}', which is not defined in detection")
        return ("search", token)


def evaluate(tree, event, searches):
    kind = tree[0]
    if kind == "search":
        return search_matches(event, searches[tree[1]], tree[1])
    if kind == "not":
        return not evaluate(tree[1], event, searches)
    if kind == "and":
        return evaluate(tree[1], event, searches) and evaluate(tree[2], event, searches)
    if kind == "or":
        return evaluate(tree[1], event, searches) or evaluate(tree[2], event, searches)
    results = [search_matches(event, searches[name], name) for name in tree[1]]
    return all(results) if kind == "all" else any(results)


# ---- Loading files and running one test ----------------------------------------------------

def load_rule(path):
    if not os.path.isfile(path):
        raise RuleError(f"rule file not found: {path}")
    try:
        with open(path, encoding="utf-8") as handle:
            rule = yaml.safe_load(handle)
    except yaml.YAMLError as err:
        raise RuleError(f"{path} is not valid YAML: {err}") from None
    detection = rule.get("detection") if isinstance(rule, dict) else None
    if not isinstance(detection, dict) or "condition" not in detection:
        raise RuleError(f"{path} has no detection with a condition")
    condition = detection["condition"]
    searches = {k: v for k, v in detection.items() if k not in ("condition", "timeframe")}
    texts = condition if isinstance(condition, list) else [condition]
    if not texts or not all(isinstance(t, str) for t in texts):
        raise RuleError(f"{path}: condition must be text")
    if any("|" in t for t in texts):
        raise RuleError(f"{path}: aggregation conditions (with |) are not supported")
    trees = [Condition(t, searches).parse() for t in texts]
    return trees, searches


def load_events(path):
    if not os.path.isfile(path):
        raise RuleError(f"events file not found: {path}")
    events = []
    with open(path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                raise RuleError(f"{path} line {number} is not valid JSON") from None
            if not isinstance(event, dict):
                raise RuleError(f"{path} line {number} is not a JSON object")
            events.append(event)
    return events


def run_test(root, stem):
    """Return (match_count, expected) for tests/<stem>.json; may raise RuleError."""
    test_path = os.path.normpath(os.path.join(root, "tests", stem + ".json"))
    try:
        with open(test_path, encoding="utf-8") as handle:
            test = json.load(handle)
    except (OSError, json.JSONDecodeError) as err:
        raise RuleError(f"cannot read {test_path}: {err}") from None
    expected = test.get("expect_matches") if isinstance(test, dict) else None
    if not isinstance(expected, int) or isinstance(expected, bool):
        raise RuleError(f"{test_path} needs a whole-number \"expect_matches\"")
    events_name = test.get("events")
    if not isinstance(events_name, str):
        raise RuleError(f"{test_path} needs an \"events\" file name", expected)
    rule_path = None
    for extension in (".yml", ".yaml"):
        candidate = os.path.normpath(os.path.join(root, "rules", stem + extension))
        if os.path.isfile(candidate):
            rule_path = candidate
            break
    try:
        trees, searches = load_rule(
            rule_path or os.path.normpath(os.path.join(root, "rules", stem + ".yml"))
        )
        events = load_events(os.path.normpath(os.path.join(root, "tests", events_name)))
        count = sum(
            1 for event in events if any(evaluate(tree, event, searches) for tree in trees)
        )
    except RuleError as err:
        raise RuleError(str(err), expected) from None
    return count, expected


def main(argv):
    parser = argparse.ArgumentParser(description="Run each rule against its sample events.")
    parser.add_argument("folder", nargs="?", default=".", help="repository folder (default: .)")
    parser.add_argument("--rule", action="append", default=[], metavar="NAME",
                        help="test only this rule (repeat for more)")
    args = parser.parse_args(argv[1:])

    tests_dir = os.path.join(args.folder, "tests")
    stems = []
    if os.path.isdir(tests_dir):
        stems = sorted(n[:-5] for n in os.listdir(tests_dir) if n.endswith(".json"))
    if args.rule:
        unknown = [r for r in args.rule if r not in stems]
        for name in unknown:
            print(f"note: no test file tests/{name}.json", file=sys.stderr)
        stems = [s for s in stems if s in args.rule] + unknown

    passed = 0
    for stem in stems:
        try:
            count, expected = run_test(args.folder, stem)
        except RuleError as err:
            expected = err.args[1] if len(err.args) > 1 else "?"
            print(f"FAIL {stem}: 0 matches (expected {expected})")
            print(f"  reason ({stem}): {err.args[0]}", file=sys.stderr)
            continue
        if count == expected:
            passed += 1
            print(f"PASS {stem}: {count} matches (expected {expected})")
        else:
            print(f"FAIL {stem}: {count} matches (expected {expected})")

    print(f"{passed}/{len(stems)} rule tests passed")
    if not stems:
        print("note: no tests found in tests/*.json, so nothing was proven", file=sys.stderr)
        return 1
    return 0 if passed == len(stems) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
