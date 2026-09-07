#!/bin/bash
set -euo pipefail

# ------------------------------------------------------------
# 3-sigma_runner.sh
#
# Execute the subset of Sigma used by this project directly
# against normalized JSON evidence.
#
# Usage:
#   ./3-sigma_runner.sh RULE [EVIDENCE]
#   ./3-sigma_runner.sh RULE --dry-run
#   ./3-sigma_runner.sh RULE --count-only
#   ./3-sigma_runner.sh RULE --window START,END
#
# Default evidence:
#   $HANDOFF_DIR/data/normalized_events.json
# ------------------------------------------------------------


# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
DEFAULT_EVIDENCE="$HANDOFF_DIR/data/normalized_events.json"


# ------------------------------------------------------------
# Usage
# ------------------------------------------------------------

usage() {
    echo "Usage: $0 <rule.yml> [evidence.json] [--dry-run] [--count-only] [--window <start_iso,end_iso>]" >&2
}


# ------------------------------------------------------------
# Read required rule argument
# ------------------------------------------------------------

if [[ $# -lt 1 ]]; then
    usage
    exit 1
fi

RULE_FILE="$1"
shift


# ------------------------------------------------------------
# Defaults
# ------------------------------------------------------------

EVIDENCE_FILE="$DEFAULT_EVIDENCE"
EVIDENCE_SET=0
DRY_RUN=0
COUNT_ONLY=0
WINDOW_ARG=""


# ------------------------------------------------------------
# Parse optional arguments
# ------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=1
            shift
            ;;

        --count-only)
            COUNT_ONLY=1
            shift
            ;;

        --window)
            if [[ $# -lt 2 ]]; then
                echo "ERROR: --window requires <start_iso,end_iso>" >&2
                exit 1
            fi

            WINDOW_ARG="$2"
            shift 2
            ;;

        -h|--help)
            usage
            exit 0
            ;;

        --*)
            echo "ERROR: unknown option: $1" >&2
            usage
            exit 1
            ;;

        *)
            if [[ "$EVIDENCE_SET" -eq 1 ]]; then
                echo "ERROR: only one evidence file may be supplied" >&2
                exit 1
            fi

            EVIDENCE_FILE="$1"
            EVIDENCE_SET=1
            shift
            ;;
    esac
done


# ------------------------------------------------------------
# Input validation
# ------------------------------------------------------------

if [[ ! -f "$RULE_FILE" ]]; then
    echo "ERROR: rule file not found: $RULE_FILE" >&2
    exit 1
fi

# Dry-run only needs the rule.
if [[ "$DRY_RUN" -eq 0 && ! -f "$EVIDENCE_FILE" ]]; then
    echo "ERROR: evidence file not found: $EVIDENCE_FILE" >&2
    exit 1
fi


# ------------------------------------------------------------
# Python Sigma helper
# ------------------------------------------------------------

python3 - "$RULE_FILE" "$EVIDENCE_FILE" \
    "$DRY_RUN" "$COUNT_ONLY" "$WINDOW_ARG" <<'PY'
import fnmatch
import json
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml


# ------------------------------------------------------------
# Arguments passed from Bash
# ------------------------------------------------------------

RULE_PATH = Path(sys.argv[1])
EVIDENCE_PATH = Path(sys.argv[2])

DRY_RUN = sys.argv[3] == "1"
COUNT_ONLY = sys.argv[4] == "1"
WINDOW_ARG = sys.argv[5]


# ------------------------------------------------------------
# Project-required Sigma fields
# ------------------------------------------------------------

REQUIRED_RULE_KEYS = {
    "title",
    "id",
    "status",
    "description",
    "logsource",
    "detection",
    "falsepositives",
    "level",
    "tags",
}

VALID_LEVELS = {
    "informational",
    "low",
    "medium",
    "high",
    "critical",
}


# ------------------------------------------------------------
# Load and validate Sigma YAML
# ------------------------------------------------------------

def load_rule(path):
    try:
        with path.open("r", encoding="utf-8") as handle:
            rule = yaml.safe_load(handle)

    except yaml.YAMLError as exc:
        raise ValueError(f"YAML parse error: {exc}") from exc

    if not isinstance(rule, dict):
        raise ValueError("rule must be a YAML mapping")

    missing = sorted(REQUIRED_RULE_KEYS - set(rule))

    if missing:
        raise ValueError(
            "missing required rule fields: " + ", ".join(missing)
        )

    # Validate UUID.
    try:
        rule_uuid = uuid.UUID(str(rule["id"]))
    except ValueError as exc:
        raise ValueError("id is not a valid UUID") from exc

    if rule_uuid.version != 4:
        raise ValueError("id must be a UUID v4")

    if rule["level"] not in VALID_LEVELS:
        raise ValueError("invalid rule level")

    detection = rule.get("detection")

    if not isinstance(detection, dict):
        raise ValueError("detection must be a mapping")

    if "condition" not in detection:
        raise ValueError("detection.condition is required")

    return rule


# ------------------------------------------------------------
# Load JSON or NDJSON evidence
# ------------------------------------------------------------

def load_events(path):
    text = path.read_text(encoding="utf-8").strip()

    if not text:
        return []

    # First try a normal JSON document.
    try:
        parsed = json.loads(text)

        if isinstance(parsed, list):
            return parsed

        if isinstance(parsed, dict):
            if isinstance(parsed.get("events"), list):
                return parsed["events"]

            return [parsed]

    except json.JSONDecodeError:
        pass

    # If that failed, treat it as NDJSON.
    events = []

    for line_number, line in enumerate(
        text.splitlines(),
        start=1,
    ):
        line = line.strip()

        if not line:
            continue

        try:
            event = json.loads(line)

        except json.JSONDecodeError as exc:
            raise ValueError(
                f"invalid JSON on line {line_number}: {exc}"
            ) from exc

        if not isinstance(event, dict):
            raise ValueError(
                f"JSON line {line_number} is not an object"
            )

        events.append(event)

    return events


# ------------------------------------------------------------
# Timestamp handling
# ------------------------------------------------------------

def parse_iso(value, normalize_utc=True):
    if not isinstance(value, str) or not value:
        return None

    candidate = value.strip()

    # datetime.fromisoformat() understands +00:00 more
    # consistently than the Z suffix.
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(candidate)

    except ValueError:
        return None

    # Treat timestamps without an explicit timezone as UTC.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    if normalize_utc:
        return parsed.astimezone(timezone.utc)

    return parsed


def event_timestamp(event):
    possible_fields = (
        "timestamp",
        "@timestamp",
        "event_time",
        "timestamp_raw",
    )

    for field in possible_fields:
        value = get_field(event, field, derive=False)

        if value is not None:
            return value

    return None


# ------------------------------------------------------------
# Read event fields
#
# Supports both:
#   hostname
#
# and nested field syntax:
#   host.name
#
# The runner also provides the project-specific synthetic field:
#   hour_of_day
# ------------------------------------------------------------

def get_field(event, field, derive=True):

    # Custom extension required by T2.
    if derive and field == "hour_of_day":
        raw_timestamp = event_timestamp(event)

        # Keep the hour expressed in the event timestamp itself.
        parsed = parse_iso(
            raw_timestamp,
            normalize_utc=False,
        )

        if parsed is None:
            return None

        return parsed.hour

    # First try the exact key.
    if field in event:
        return event[field]

    # Then support dotted nested fields.
    current = event

    for part in field.split("."):
        if not isinstance(current, dict):
            return None

        if part not in current:
            return None

        current = current[part]

    return current


# ------------------------------------------------------------
# Comparison helpers
# ------------------------------------------------------------

def comparable_number(value):
    if isinstance(value, bool):
        return None

    if isinstance(value, (int, float)):
        return float(value)

    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None

    return None


def equal_value(actual, expected):

    if actual is None:
        return expected is None

    # This lets integer 4624 match string "4624", for example.
    actual_number = comparable_number(actual)
    expected_number = comparable_number(expected)

    if (
        actual_number is not None
        and expected_number is not None
    ):
        return actual_number == expected_number

    # String matching is case-insensitive.
    if isinstance(actual, str) and isinstance(expected, str):

        # Basic Sigma wildcard support.
        if "*" in expected or "?" in expected:
            return fnmatch.fnmatch(
                actual.casefold(),
                expected.casefold(),
            )

        return actual.casefold() == expected.casefold()

    return actual == expected


# ------------------------------------------------------------
# Sigma field modifiers
#
# Supports the modifiers needed by this project:
#
#   field|gte
#   field|gt
#   field|lte
#   field|lt
#   field|contains
#   field|startswith
#   field|endswith
#   field|re
#   field|exists
#   field|all
# ------------------------------------------------------------

def scalar_match(actual, expected, modifiers):

    if "exists" in modifiers:
        wanted = bool(expected)
        return (actual is not None) == wanted

    if actual is None:
        return False

    # Numeric comparisons.
    numeric_modifiers = {
        "gte",
        "gt",
        "lte",
        "lt",
    }

    if numeric_modifiers.intersection(modifiers):

        actual_number = comparable_number(actual)
        expected_number = comparable_number(expected)

        if (
            actual_number is None
            or expected_number is None
        ):
            return False

        if "gte" in modifiers:
            return actual_number >= expected_number

        if "gt" in modifiers:
            return actual_number > expected_number

        if "lte" in modifiers:
            return actual_number <= expected_number

        return actual_number < expected_number

    actual_text = str(actual)
    expected_text = str(expected)

    if "contains" in modifiers:
        return (
            expected_text.casefold()
            in actual_text.casefold()
        )

    if "startswith" in modifiers:
        return actual_text.casefold().startswith(
            expected_text.casefold()
        )

    if "endswith" in modifiers:
        return actual_text.casefold().endswith(
            expected_text.casefold()
        )

    if "re" in modifiers:
        return (
            re.search(
                expected_text,
                actual_text,
                flags=re.IGNORECASE,
            )
            is not None
        )

    return equal_value(actual, expected)


def field_matches(event, field_expression, expected):

    parts = field_expression.split("|")

    field = parts[0]
    modifiers = parts[1:]

    match_all = "all" in modifiers

    modifiers = [
        modifier
        for modifier in modifiers
        if modifier != "all"
    ]

    actual = get_field(event, field)

    # A Sigma list normally means OR.
    if isinstance(expected, list):

        results = [
            scalar_match(
                actual,
                item,
                modifiers,
            )
            for item in expected
        ]

        if match_all:
            return all(results)

        return any(results)

    return scalar_match(
        actual,
        expected,
        modifiers,
    )


# ------------------------------------------------------------
# Evaluate one named Sigma selection
# ------------------------------------------------------------

def selection_matches(event, selection):

    # All fields inside one mapping must match.
    if isinstance(selection, dict):
        return all(
            field_matches(
                event,
                field,
                expected,
            )
            for field, expected in selection.items()
        )

    # A list of mappings acts as OR.
    if isinstance(selection, list):
        return any(
            selection_matches(event, item)
            for item in selection
        )

    return False


def selection_names(detection):
    return [
        key
        for key in detection
        if key not in {
            "condition",
            "timeframe",
        }
    ]


# ------------------------------------------------------------
# Boolean Sigma condition parser
#
# Supports:
#
#   selection
#
#   selection and filter
#
#   selection and (filter1 or filter2)
#
#   selection and not filter
#
#   1 of selection_*
#
#   all of selection_*
#
#   1 of them
#
#   all of them
# ------------------------------------------------------------

TOKEN_RE = re.compile(
    r"\s*("
    r"\(|\)"
    r"|\b(?:and|or|not|of|all|them)\b"
    r"|1"
    r"|[A-Za-z_][A-Za-z0-9_.*-]*"
    r")",
    flags=re.IGNORECASE,
)


class ConditionParser:

    def __init__(self, expression, detection, event):
        self.detection = detection
        self.event = event

        self.tokens = self._tokenize(expression)
        self.position = 0

    def _tokenize(self, expression):
        tokens = []
        index = 0

        while index < len(expression):

            match = TOKEN_RE.match(
                expression,
                index,
            )

            if not match:
                raise ValueError(
                    "unsupported condition syntax near: "
                    + expression[index:]
                )

            tokens.append(match.group(1))
            index = match.end()

        return tokens

    def current(self):
        if self.position >= len(self.tokens):
            return None

        return self.tokens[self.position]

    def consume(self, expected=None):

        token = self.current()

        if token is None:
            raise ValueError(
                "unexpected end of condition"
            )

        if (
            expected is not None
            and token.casefold() != expected.casefold()
        ):
            raise ValueError(
                f"expected '{expected}', got '{token}'"
            )

        self.position += 1
        return token

    def parse(self):

        value = self.parse_or()

        if self.current() is not None:
            raise ValueError(
                f"unexpected token: {self.current()}"
            )

        return value

    def parse_or(self):

        value = self.parse_and()

        while (
            self.current()
            and self.current().casefold() == "or"
        ):
            self.consume("or")

            # Do not use Python short-circuiting here.
            # We must consume every token in the expression.
            right = self.parse_and()
            value = value or right

        return value

    def parse_and(self):

        value = self.parse_not()

        while (
            self.current()
            and self.current().casefold() == "and"
        ):
            self.consume("and")

            right = self.parse_not()
            value = value and right

        return value

    def parse_not(self):

        if (
            self.current()
            and self.current().casefold() == "not"
        ):
            self.consume("not")
            return not self.parse_not()

        return self.parse_primary()

    def parse_primary(self):

        token = self.current()

        if token is None:
            raise ValueError(
                "unexpected end of condition"
            )

        # Parenthesized expression.
        if token == "(":

            self.consume("(")
            value = self.parse_or()
            self.consume(")")

            return value

        # "1 of ..." or "all of ..."
        if token.casefold() in {"1", "all"}:

            quantity = self.consume().casefold()

            self.consume("of")
            target = self.consume()

            names = selection_names(
                self.detection
            )

            if target.casefold() == "them":
                selected_names = names

            else:
                selected_names = [
                    name
                    for name in names
                    if fnmatch.fnmatch(
                        name,
                        target,
                    )
                ]

            if not selected_names:
                return False

            results = [
                selection_matches(
                    self.event,
                    self.detection[name],
                )
                for name in selected_names
            ]

            if quantity == "all":
                return all(results)

            return any(results)

        # Normal named selection.
        name = self.consume()

        if name not in self.detection:
            raise ValueError(
                f"unknown detection selection: {name}"
            )

        return selection_matches(
            self.event,
            self.detection[name],
        )


def condition_matches(
    event,
    expression,
    detection,
):
    parser = ConditionParser(
        expression,
        detection,
        event,
    )

    return parser.parse()


# ------------------------------------------------------------
# Apply Sigma logsource
#
# Our normalized handoff uses:
#
#   product: linux   -> linux_text
#   product: windows -> windows_json
#
# If explicit product/service fields exist in an event,
# they are also checked.
# ------------------------------------------------------------

def logsource_matches(event, logsource):

    if not isinstance(logsource, dict):
        return True

    product = str(
        logsource.get("product", "")
    ).casefold()

    source_type = get_field(
        event,
        "source_type",
    )

    product_source_map = {
        "linux": "linux_text",
        "windows": "windows_json",
    }

    expected_source = product_source_map.get(
        product
    )

    if (
        expected_source
        and source_type is not None
    ):
        if (
            str(source_type).casefold()
            != expected_source
        ):
            return False

    # Check an explicit product field if one exists.
    event_product = get_field(
        event,
        "product",
    )

    if event_product is not None and product:

        if (
            str(event_product).casefold()
            != product
        ):
            return False

    # Check service if the normalized event supplies it.
    service = logsource.get("service")

    event_service = get_field(
        event,
        "service",
    )

    if (
        service is not None
        and event_service is not None
    ):
        if (
            str(event_service).casefold()
            != str(service).casefold()
        ):
            return False

    return True


# ------------------------------------------------------------
# --window support
# ------------------------------------------------------------

def parse_window(argument):

    if not argument:
        return None, None

    if "," not in argument:
        raise ValueError(
            "--window must be <start_iso,end_iso>"
        )

    start_text, end_text = argument.split(
        ",",
        1,
    )

    start = parse_iso(start_text.strip())
    end = parse_iso(end_text.strip())

    if start is None or end is None:
        raise ValueError(
            "--window contains an invalid ISO timestamp"
        )

    if start > end:
        raise ValueError(
            "--window start is after end"
        )

    return start, end


def inside_window(event, start, end):

    if start is None and end is None:
        return True

    timestamp = parse_iso(
        event_timestamp(event)
    )

    # Events without a usable timestamp cannot satisfy
    # a requested time window.
    if timestamp is None:
        return False

    return start <= timestamp <= end


# ------------------------------------------------------------
# Duration parser
#
# Supports:
#   120s
#   5m
#   2h
#   1d
# ------------------------------------------------------------

def parse_duration(value):

    if isinstance(value, int):
        return value

    if not isinstance(value, str):
        raise ValueError(
            "timeframe must be a duration such as 120s"
        )

    match = re.fullmatch(
        r"\s*(\d+)\s*([smhd])\s*",
        value,
        flags=re.IGNORECASE,
    )

    if not match:
        raise ValueError(
            f"unsupported timeframe: {value}"
        )

    amount = int(match.group(1))
    unit = match.group(2).casefold()

    multiplier = {
        "s": 1,
        "m": 60,
        "h": 3600,
        "d": 86400,
    }[unit]

    return amount * multiplier


# ------------------------------------------------------------
# Aggregation syntax
#
# Supports either:
#
#   condition:
#     selection | count() by src_ip > 5
#
#   timeframe: 120s
#
# Or:
#
#   selection | count() by src_ip > 5 within 120s
# ------------------------------------------------------------

AGGREGATION_RE = re.compile(
    r"^\s*"
    r"(?P<base>.+?)"
    r"\s*\|\s*count\(\)"
    r"\s+by\s+"
    r"(?P<field>[A-Za-z_][A-Za-z0-9_.-]*)"
    r"\s*"
    r"(?P<operator>>=|<=|==|=|>|<)"
    r"\s*"
    r"(?P<threshold>\d+)"
    r"(?:\s+within\s+"
    r"(?P<within>\d+\s*[smhd]))?"
    r"\s*$",
    flags=re.IGNORECASE,
)


def compare_count(
    value,
    operator,
    threshold,
):

    if operator == ">":
        return value > threshold

    if operator == ">=":
        return value >= threshold

    if operator == "<":
        return value < threshold

    if operator == "<=":
        return value <= threshold

    return value == threshold


# ------------------------------------------------------------
# Sliding-window aggregation
# ------------------------------------------------------------

def evaluate_aggregation(
    events,
    detection,
    condition,
    logsource,
):

    match = AGGREGATION_RE.fullmatch(
        condition
    )

    if not match:
        raise ValueError(
            f"unsupported aggregation condition: {condition}"
        )

    base_expression = match.group("base")
    group_field = match.group("field")
    operator = match.group("operator")

    threshold = int(
        match.group("threshold")
    )

    within = match.group("within")

    if within:
        window_seconds = parse_duration(
            within.replace(" ", "")
        )

    elif "timeframe" in detection:
        window_seconds = parse_duration(
            detection["timeframe"]
        )

    else:
        window_seconds = None

    # Group matching events by the aggregation field.
    groups = {}

    for original_index, event in events:

        if not logsource_matches(
            event,
            logsource,
        ):
            continue

        if not condition_matches(
            event,
            base_expression,
            detection,
        ):
            continue

        group_value = get_field(
            event,
            group_field,
        )

        if group_value is None:
            continue

        timestamp = parse_iso(
            event_timestamp(event)
        )

        # Time-based aggregation requires a timestamp.
        if (
            window_seconds is not None
            and timestamp is None
        ):
            continue

        key = str(group_value)

        groups.setdefault(
            key,
            [],
        ).append(
            (
                original_index,
                event,
                timestamp,
            )
        )

    matched_indexes = set()

    # Evaluate each group separately.
    for group_events in groups.values():

        # No timeframe: aggregate over all matching events.
        if window_seconds is None:

            if compare_count(
                len(group_events),
                operator,
                threshold,
            ):
                matched_indexes.update(
                    item[0]
                    for item in group_events
                )

            continue

        # Sort chronologically for deterministic
        # sliding-window evaluation.
        group_events.sort(
            key=lambda item: (
                item[2],
                item[0],
            )
        )

        left = 0

        for right in range(
            len(group_events)
        ):

            right_time = group_events[right][2]

            # Remove events older than the configured window.
            while (
                left <= right
                and (
                    right_time
                    - group_events[left][2]
                ).total_seconds()
                > window_seconds
            ):
                left += 1

            current_count = (
                right - left + 1
            )

            if compare_count(
                current_count,
                operator,
                threshold,
            ):
                # Add every event participating in this
                # qualifying window.
                for position in range(
                    left,
                    right + 1,
                ):
                    matched_indexes.add(
                        group_events[position][0]
                    )

    return matched_indexes


# ------------------------------------------------------------
# Produce compact event references
# ------------------------------------------------------------

def event_reference(
    event,
    original_index,
):

    possible_fields = (
        "event_ref",
        "record_id",
        "id",
        "event_uuid",
    )

    for field in possible_fields:

        value = get_field(
            event,
            field,
        )

        if value is not None:
            return str(value)

    # Deterministic fallback when the normalized event
    # contains no unique reference field.
    return f"index:{original_index}"


def hostname_value(event):

    possible_fields = (
        "hostname",
        "host.name",
        "computer_name",
        "Computer",
        "host",
    )

    for field in possible_fields:

        value = get_field(
            event,
            field,
        )

        if (
            value is not None
            and not isinstance(
                value,
                (dict, list),
            )
        ):
            return str(value)

    return None


def build_match(
    event,
    original_index,
):

    return {
        "timestamp": event_timestamp(event),
        "hostname": hostname_value(event),
        "event_ref": event_reference(
            event,
            original_index,
        ),
    }


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

try:
    rule = load_rule(RULE_PATH)

    # --------------------------------------------------------
    # Dry-run does not read or evaluate evidence.
    # --------------------------------------------------------

    if DRY_RUN:
        print("VALID")
        sys.exit(0)

    started = time.perf_counter()

    events = load_events(
        EVIDENCE_PATH
    )

    start_window, end_window = parse_window(
        WINDOW_ARG
    )

    # Keep original indexes so event references stay stable.
    filtered_events = [
        (index, event)
        for index, event in enumerate(events)
        if isinstance(event, dict)
        and inside_window(
            event,
            start_window,
            end_window,
        )
    ]

    detection = rule["detection"]

    condition = str(
        detection["condition"]
    )

    logsource = rule.get(
        "logsource",
        {},
    )

    # --------------------------------------------------------
    # Aggregation rule
    # --------------------------------------------------------

    if (
        "|" in condition
        and "count()" in condition.casefold()
    ):

        matched_indexes = evaluate_aggregation(
            filtered_events,
            detection,
            condition,
            logsource,
        )

    # --------------------------------------------------------
    # Normal event-by-event rule
    # --------------------------------------------------------

    else:

        matched_indexes = {
            index
            for index, event
            in filtered_events
            if logsource_matches(
                event,
                logsource,
            )
            and condition_matches(
                event,
                condition,
                detection,
            )
        }

    # Preserve original evidence order.
    matches = [
        build_match(
            event,
            index,
        )
        for index, event
        in filtered_events
        if index in matched_indexes
    ]

    elapsed_ms = round(
        (
            time.perf_counter()
            - started
        )
        * 1000,
        3,
    )

    # --------------------------------------------------------
    # --count-only
    # --------------------------------------------------------

    if COUNT_ONLY:
        print(len(matches))
        sys.exit(0)

    # --------------------------------------------------------
    # Normal JSON contract
    # --------------------------------------------------------

    result = {
        "rule_id": str(rule["id"]),
        "rule_title": rule["title"],
        "level": rule["level"],
        "evidence_path": str(EVIDENCE_PATH),
        "match_count": len(matches),
        "matches": matches,
        "execution_time_ms": elapsed_ms,
    }

    print(
        json.dumps(
            result,
            indent=2,
            sort_keys=False,
        )
    )

except (OSError, ValueError) as exc:

    if DRY_RUN:
        print(f"INVALID: {exc}")

    else:
        print(
            f"ERROR: {exc}",
            file=sys.stderr,
        )

    sys.exit(1)
PY
