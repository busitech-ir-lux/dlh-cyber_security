#!/bin/bash

# ============================================================
# Task 8 - Temporal Pattern Analysis
#
# Reads:
#   labeled_events.json
#
# Produces:
#   temporal_profile.json
#
# For every source_type and canonical_label, the script builds:
#   - 24-hour activity histogram
#   - 7-day-of-week activity histogram
#   - peak hour
#   - quiet hour
#   - business-hours / off-hours event ratio
#
# It also prints ASCII histograms for the three most active
# canonical labels during the baseline.
# ============================================================

set -euo pipefail


# ============================================================
# 1. Configuration
# ============================================================

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff/}"
BASELINE_DAYS="${BASELINE_DAYS:-7}"

# ------------------------------------------------------------
# Business hours
#
# The project task does not define exact business-hour limits,
# so keep them configurable.
#
# Default:
#   08:00 inclusive
#   18:00 exclusive
#
# Example override:
#   BUSINESS_START_HOUR=6 BUSINESS_END_HOUR=20 \
#       ./8-temporal_profile.sh
# ------------------------------------------------------------

BUSINESS_START_HOUR="${BUSINESS_START_HOUR:-8}"
BUSINESS_END_HOUR="${BUSINESS_END_HOUR:-18}"

INPUT_FILE="labeled_events.json"
OUTPUT_FILE="temporal_profile.json"


# ============================================================
# 2. Locate input file
# ============================================================

if [ ! -f "$INPUT_FILE" ] && \
   [ -f "${HANDOFF_DIR%/}/data/labeled_events.json" ]; then
    INPUT_FILE="${HANDOFF_DIR%/}/data/labeled_events.json"
fi

if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: labeled_events.json not found" >&2
    exit 1
fi


# ============================================================
# 3. Validate numeric configuration
# ============================================================

case "$BASELINE_DAYS" in
    ''|*[!0-9]*)
        echo "Error: BASELINE_DAYS must be a positive integer" >&2
        exit 1
        ;;
esac

if [ "$BASELINE_DAYS" -lt 1 ]; then
    echo "Error: BASELINE_DAYS must be at least 1" >&2
    exit 1
fi


case "$BUSINESS_START_HOUR" in
    ''|*[!0-9]*)
        echo "Error: BUSINESS_START_HOUR must be 0-23" >&2
        exit 1
        ;;
esac

case "$BUSINESS_END_HOUR" in
    ''|*[!0-9]*)
        echo "Error: BUSINESS_END_HOUR must be 1-24" >&2
        exit 1
        ;;
esac


if [ "$BUSINESS_START_HOUR" -lt 0 ] || \
   [ "$BUSINESS_START_HOUR" -gt 23 ]; then
    echo "Error: BUSINESS_START_HOUR must be 0-23" >&2
    exit 1
fi

if [ "$BUSINESS_END_HOUR" -lt 1 ] || \
   [ "$BUSINESS_END_HOUR" -gt 24 ]; then
    echo "Error: BUSINESS_END_HOUR must be 1-24" >&2
    exit 1
fi

if [ "$BUSINESS_START_HOUR" -ge "$BUSINESS_END_HOUR" ]; then
    echo "Error: business start hour must be before end hour" >&2
    exit 1
fi


# ============================================================
# 4. Build temporal profile
# ============================================================

python3 -W error - \
    "$INPUT_FILE" \
    "$OUTPUT_FILE" \
    "$BASELINE_DAYS" \
    "$BUSINESS_START_HOUR" \
    "$BUSINESS_END_HOUR" <<'PYTHON'

import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone


input_file = sys.argv[1]
output_file = sys.argv[2]
baseline_days = int(sys.argv[3])
business_start = int(sys.argv[4])
business_end = int(sys.argv[5])


DAY_NAMES = [
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
]


# ============================================================
# 5. Input helpers
# ============================================================

def load_events(path):
    """
    Read either:
      - a JSON array
      - one JSON object
      - NDJSON
    """

    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read().strip()

    if not text:
        return []

    try:
        data = json.loads(text)

    except json.JSONDecodeError:
        events = []

        for line_number, line in enumerate(
            text.splitlines(),
            start=1
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
                    f"record on line {line_number} "
                    "is not a JSON object"
                )

            events.append(event)

        return events

    if isinstance(data, list):
        if not all(isinstance(event, dict) for event in data):
            raise ValueError(
                "JSON array contains non-object records"
            )

        return data

    if isinstance(data, dict):
        return [data]

    raise ValueError(
        "input must contain JSON objects"
    )


def present(value):
    if value is None:
        return False

    if isinstance(value, str) and not value.strip():
        return False

    return True


# ============================================================
# 6. Timestamp helpers
# ============================================================

def parse_timestamp(value):
    """
    Parse normalized ISO-8601 timestamps.

    The 3x00 schema defines timestamp values in UTC, but this
    also safely handles an explicit timezone offset.
    """

    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            "event has missing timestamp"
        )

    text = value.strip()

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(text)

    except ValueError as exc:
        raise ValueError(
            f"invalid timestamp: {value}"
        ) from exc

    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=timezone.utc
        )

    return parsed.astimezone(
        timezone.utc
    )


def iso_utc(value):
    return (
        value
        .astimezone(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


# ============================================================
# 7. Label helper
# ============================================================

def canonical_label(event):
    """
    Task 8 operates on canonical labels.

    Events without a canonical_label are ignored rather than
    inventing a category for them.
    """

    value = event.get("canonical_label")

    if not present(value):
        return None

    return str(value).strip()


# ============================================================
# 8. Load complete dataset
# ============================================================

events = load_events(input_file)

if not events:
    raise ValueError(
        "labeled_events.json contains no events"
    )


parsed_events = []

for event in events:
    timestamp = parse_timestamp(
        event.get("timestamp")
    )

    parsed_events.append(
        (timestamp, event)
    )


# ============================================================
# 9. Derive baseline window
#
# No dates are hardcoded.
# ============================================================

dataset_start = min(
    timestamp
    for timestamp, _ in parsed_events
)

baseline_end = (
    dataset_start
    + timedelta(days=baseline_days)
)


baseline_events = [
    (timestamp, event)
    for timestamp, event in parsed_events
    if dataset_start <= timestamp < baseline_end
]


if not baseline_events:
    raise ValueError(
        "no events fall inside the baseline window"
    )


# ============================================================
# 10. Determine weekday opportunities
#
# Example with a normal 7-day baseline:
#
#   Monday    = 1
#   Tuesday   = 1
#   ...
#
# If BASELINE_DAYS is larger than 7, weekdays may occur more
# than once. This lets the daily histogram remain a true mean.
# ============================================================

weekday_occurrences = Counter()

for offset in range(baseline_days):
    day = (
        dataset_start
        + timedelta(days=offset)
    ).weekday()

    weekday_occurrences[day] += 1


# ============================================================
# 11. Activity counters
#
# profile_counts[source][label]["hours"]
# profile_counts[source][label]["weekdays"]
# ============================================================

hour_counts = defaultdict(
    lambda: defaultdict(Counter)
)

weekday_counts = defaultdict(
    lambda: defaultdict(Counter)
)

total_counts = defaultdict(
    lambda: Counter()
)

business_counts = defaultdict(
    lambda: Counter()
)

offhours_counts = defaultdict(
    lambda: Counter()
)


# Used for selecting the overall top three labels.
overall_label_counts = Counter()


# ============================================================
# 12. Count baseline events
# ============================================================

for timestamp, event in baseline_events:

    source_type = event.get("source_type")
    label = canonical_label(event)

    if not present(source_type):
        continue

    if label is None:
        continue

    source_type = str(source_type).strip()

    hour = timestamp.hour
    weekday = timestamp.weekday()


    # --------------------------------------------------------
    # Hourly profile
    # --------------------------------------------------------

    hour_counts[
        source_type
    ][label][hour] += 1


    # --------------------------------------------------------
    # Day-of-week profile
    # --------------------------------------------------------

    weekday_counts[
        source_type
    ][label][weekday] += 1


    # --------------------------------------------------------
    # Total activity
    # --------------------------------------------------------

    total_counts[
        source_type
    ][label] += 1

    overall_label_counts[
        label
    ] += 1


    # --------------------------------------------------------
    # Business versus off-hours
    #
    # Start is inclusive.
    # End is exclusive.
    #
    # Example:
    #   08 <= hour < 18
    # --------------------------------------------------------

    if business_start <= hour < business_end:

        business_counts[
            source_type
        ][label] += 1

    else:

        offhours_counts[
            source_type
        ][label] += 1


# ============================================================
# 13. Build profile
# ============================================================

profiles = {}


for source_type in sorted(total_counts):

    profiles[source_type] = {}


    for label in sorted(
        total_counts[source_type]
    ):

        # ----------------------------------------------------
        # Hour-of-day mean
        #
        # Every hour gets a bucket, including zero-activity
        # hours.
        #
        # Divide by number of baseline days so:
        #
        #   count at 08:00 over 7 days / 7
        #
        # becomes the expected average for that hour.
        # ----------------------------------------------------

        hourly_means = {}

        for hour in range(24):

            count = hour_counts[
                source_type
            ][label][hour]

            mean = (
                count
                / baseline_days
            )

            hourly_means[
                f"{hour:02d}"
            ] = round(
                mean,
                4
            )


        # ----------------------------------------------------
        # Day-of-week mean
        # ----------------------------------------------------

        daily_means = {}

        for weekday in range(7):

            count = weekday_counts[
                source_type
            ][label][weekday]

            opportunities = weekday_occurrences[
                weekday
            ]

            if opportunities == 0:
                mean = 0.0
            else:
                mean = (
                    count
                    / opportunities
                )

            daily_means[
                DAY_NAMES[weekday]
            ] = round(
                mean,
                4
            )


        # ----------------------------------------------------
        # Peak and quiet hours
        #
        # Ties are deterministic:
        # earliest hour wins.
        # ----------------------------------------------------

        peak_hour = max(
            range(24),
            key=lambda hour: (
                hourly_means[f"{hour:02d}"],
                -hour
            )
        )

        quiet_hour = min(
            range(24),
            key=lambda hour: (
                hourly_means[f"{hour:02d}"],
                hour
            )
        )


        # ----------------------------------------------------
        # Business/off-hours ratio
        #
        # Ratio =
        #
        #     business events / off-hours events
        #
        # If no off-hours events exist, the mathematical ratio
        # is undefined, so JSON null is used rather than an
        # artificial number.
        # ----------------------------------------------------

        business = business_counts[
            source_type
        ][label]

        offhours = offhours_counts[
            source_type
        ][label]


        if offhours == 0:
            ratio = None
        else:
            ratio = round(
                business / offhours,
                6
            )


        profiles[
            source_type
        ][label] = {

            "hour_of_day_histogram":
                hourly_means,

            "day_of_week_histogram":
                daily_means,

            "peak_hour":
                f"{peak_hour:02d}",

            "quiet_hour":
                f"{quiet_hour:02d}",

            "business_offhours_ratio":
                ratio,
        }


# ============================================================
# 14. Final JSON object
# ============================================================

result = {

    "baseline_window": {
        "start": iso_utc(
            dataset_start
        ),
        "end_exclusive": iso_utc(
            baseline_end
        ),
        "baseline_days": baseline_days,
    },

    "business_hours": {
        "start_hour": business_start,
        "end_hour_exclusive": business_end,
    },

    "profiles": profiles,
}


# ============================================================
# 15. Write deterministic JSON
# ============================================================

temporary_file = (
    output_file + ".tmp"
)


with open(
    temporary_file,
    "w",
    encoding="utf-8"
) as handle:

    json.dump(
        result,
        handle,
        indent=2,
        sort_keys=True,
        ensure_ascii=False
    )

    # Project files must end with newline.
    handle.write("\n")


os.replace(
    temporary_file,
    output_file
)


# ============================================================
# 16. Human-readable source summary
# ============================================================

print(
    "source_type         labels profiled"
)

for source_type in sorted(profiles):

    print(
        f"  {source_type:<20}"
        f"{len(profiles[source_type]):>5}"
    )


# ============================================================
# 17. Top three canonical labels
#
# Labels are ranked globally across source types by baseline
# activity.
# ============================================================

top_labels = [
    label
    for label, _ in overall_label_counts.most_common(3)
]


print(
    "top 3 labels temporal shape "
    "(per hour, baseline avg):"
)


# ============================================================
# 18. ASCII histogram
#
# Aggregate the label across all source types.
#
# Each hour is normalized against the most active hour for that
# label. Maximum bar width is 20 characters.
# ============================================================

for label in top_labels:

    combined_hour_counts = Counter()

    for source_type in hour_counts:

        for hour in range(24):

            combined_hour_counts[hour] += (
                hour_counts[
                    source_type
                ][label][hour]
            )


    hourly_means = [
        combined_hour_counts[hour]
        / baseline_days
        for hour in range(24)
    ]


    max_mean = max(
        hourly_means,
        default=0
    )


    print(
        f"  {label}"
    )


    for hour, mean in enumerate(
        hourly_means
    ):

        if max_mean == 0:
            bar_length = 0
        else:
            bar_length = round(
                (mean / max_mean) * 20
            )


        bar = "#" * bar_length


        print(
            f"    {hour:02d} | "
            f"{bar:<20} "
            f"{mean:.2f}"
        )


print(
    f"{output_file} written"
)

PYTHON
