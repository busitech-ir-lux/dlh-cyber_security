#!/bin/bash

set -euo pipefail


# --------------------------------------------------
# Helper
# --------------------------------------------------

fail() {
    echo "[resp] ERROR: $1" >&2
    exit 1
}


# --------------------------------------------------
# Required environment variables
# --------------------------------------------------

for var in SHIFT_WORKSPACE ASSETS_DIR
do
    if [[ -z "${!var:-}" ]]; then
        fail "$var is not set"
    fi
done


CAMPAIGN="$SHIFT_WORKSPACE/campaign/campaign_assessment.json"
INCIDENTS="$SHIFT_WORKSPACE/alerts/incidents.json"
IOC_FEED="$ASSETS_DIR/ioc_feed.json"
ASSETS="$ASSETS_DIR/assets.json"

FINDING_A="$SHIFT_WORKSPACE/investigations/incident_A.json"
FINDING_B="$SHIFT_WORKSPACE/investigations/incident_B.json"
FINDING_C="$SHIFT_WORKSPACE/investigations/incident_C_cli.json"

CONTAINMENT="$SHIFT_WORKSPACE/response/containment.json"
IOC_PACKAGE="$SHIFT_WORKSPACE/response/ioc_package.json"


# --------------------------------------------------
# Find enriched events
# --------------------------------------------------

if [[ -s "$SHIFT_WORKSPACE/enriched/enriched_events.jsonl" ]]; then

    EVENTS="$SHIFT_WORKSPACE/enriched/enriched_events.jsonl"

elif [[ -s "$SHIFT_WORKSPACE/enriched/enriched_events.json" ]]; then

    EVENTS="$SHIFT_WORKSPACE/enriched/enriched_events.json"

else

    fail "enriched events file is missing"

fi


# --------------------------------------------------
# Check required files
# --------------------------------------------------

for file in \
    "$CAMPAIGN" \
    "$INCIDENTS" \
    "$IOC_FEED" \
    "$FINDING_A" \
    "$FINDING_B" \
    "$FINDING_C"
do
    if [[ ! -s "$file" ]]; then
        fail "missing or empty file: $file"
    fi
done


mkdir -p "$SHIFT_WORKSPACE/response"


echo "[resp] loading campaign_assessment and incidents"


# --------------------------------------------------
# Build containment + IOC package
# --------------------------------------------------

python3 - \
    "$CAMPAIGN" \
    "$INCIDENTS" \
    "$IOC_FEED" \
    "$ASSETS" \
    "$EVENTS" \
    "$FINDING_A" \
    "$FINDING_B" \
    "$FINDING_C" \
    "$CONTAINMENT" \
    "$IOC_PACKAGE" <<'PY'

import json
import re
import sys
from datetime import datetime, timezone


campaign_path = sys.argv[1]
incidents_path = sys.argv[2]
feed_path = sys.argv[3]
assets_path = sys.argv[4]
events_path = sys.argv[5]

finding_paths = {
    "A": sys.argv[6],
    "B": sys.argv[7],
    "C": sys.argv[8],
}

containment_path = sys.argv[9]
package_path = sys.argv[10]


# --------------------------------------------------
# Helpers
# --------------------------------------------------

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def clean(value):
    if value is None:
        return ""

    return re.sub(
        r"\s+",
        " ",
        str(value)
    ).strip()


def now():
    return datetime.now(
        timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


def event_id(event):

    return clean(
        event.get("event_ref")
        or event.get("event_id")
        or event.get("id")
        or event.get("event_uid")
        or (
            event.get("event", {}).get("id")
            if isinstance(
                event.get("event"),
                dict
            )
            else ""
        )
    )


def event_time(event):

    return clean(
        event.get("timestamp")
        or event.get("@timestamp")
        or event.get("event_time")
        or event.get("time")
    )


def add_candidate(result, ioc_type, value):

    value = clean(value)

    if not value:
        return

    result.add(
        (ioc_type, value)
    )


def extract_candidates(event):
    """
    Extract possible IOC-style values from one
    real event.
    """

    result = set()


    # ------------------------------
    # IP addresses
    # ------------------------------

    add_candidate(
        result,
        "ip",
        event.get("src_ip")
    )

    add_candidate(
        result,
        "ip",
        event.get("dst_ip")
    )


    for key in (
        "source",
        "destination",
        "src",
        "dst",
    ):

        obj = event.get(key)

        if isinstance(obj, dict):

            add_candidate(
                result,
                "ip",
                obj.get("ip")
            )


    # ------------------------------
    # Domain
    # ------------------------------

    for value in (
        event.get("domain"),
        event.get("dns_name"),
        event.get("destination_domain"),
    ):

        add_candidate(
            result,
            "domain",
            value
        )


    dns = event.get("dns")

    if isinstance(dns, dict):

        question = dns.get("question")

        if isinstance(question, dict):

            add_candidate(
                result,
                "domain",
                question.get("name")
            )


    destination = event.get(
        "destination"
    )

    if isinstance(destination, dict):

        add_candidate(
            result,
            "domain",
            destination.get("domain")
        )


    # ------------------------------
    # Account
    # ------------------------------

    for value in (
        event.get("username"),
        event.get("account"),
    ):

        add_candidate(
            result,
            "account",
            value
        )


    user = event.get("user")

    if isinstance(user, str):

        add_candidate(
            result,
            "account",
            user
        )

    elif isinstance(user, dict):

        add_candidate(
            result,
            "account",
            user.get("name")
        )


    # ------------------------------
    # Service name
    # ------------------------------

    add_candidate(
        result,
        "service_name",
        event.get("service_name")
    )


    service = event.get("service")

    if isinstance(service, dict):

        add_candidate(
            result,
            "service_name",
            service.get("name")
        )


    winlog = event.get("winlog")

    if isinstance(winlog, dict):

        event_data = winlog.get(
            "event_data"
        )

        if isinstance(event_data, dict):

            add_candidate(
                result,
                "service_name",
                event_data.get(
                    "ServiceName"
                )
            )


    # ------------------------------
    # Hashes
    # ------------------------------

    for key in (
        "hash",
        "sha256",
        "md5",
        "sha1",
    ):

        add_candidate(
            result,
            "hash",
            event.get(key)
        )


    file_obj = event.get("file")

    if isinstance(file_obj, dict):

        hash_obj = file_obj.get("hash")

        if isinstance(hash_obj, dict):

            for value in hash_obj.values():

                add_candidate(
                    result,
                    "hash",
                    value
                )


    # ------------------------------
    # Port
    # ------------------------------

    for value in (
        event.get("dst_port"),
        event.get("destination_port"),
    ):

        if value is not None:

            add_candidate(
                result,
                "port",
                str(value)
            )


    destination = event.get(
        "destination"
    )

    if isinstance(destination, dict):

        if destination.get(
            "port"
        ) is not None:

            add_candidate(
                result,
                "port",
                destination.get(
                    "port"
                )
            )


    return result


def defang(ioc_type, value):

    value = clean(value)

    if ioc_type in (
        "ip",
        "domain",
    ):
        return value.replace(
            ".",
            "[.]"
        )

    return value


# --------------------------------------------------
# Load data
# --------------------------------------------------

campaign = load_json(campaign_path)
incidents_data = load_json(
    incidents_path
)
feed_data = load_json(feed_path)


# --------------------------------------------------
# Incident map
# --------------------------------------------------

incidents = {}

for incident in incidents_data.get(
    "incidents",
    []
):

    iid = clean(
        incident.get("incident_id")
    )

    if iid.endswith("-A"):
        incidents["A"] = incident

    elif iid.endswith("-B"):
        incidents["B"] = incident

    elif iid.endswith("-C"):
        incidents["C"] = incident


for letter in ("A", "B", "C"):

    if letter not in incidents:

        raise SystemExit(
            f"[resp] ERROR: Incident "
            f"{letter} missing"
        )


valid_incident_ids = {
    incident["incident_id"]
    for incident
    in incidents.values()
}


# --------------------------------------------------
# Shift ID
# --------------------------------------------------

shift_id = clean(
    incidents_data.get("shift_id")
)

if not shift_id:
    shift_id = "unknown"


# --------------------------------------------------
# Findings
# --------------------------------------------------

findings = {
    letter: load_json(path)
    for letter, path
    in finding_paths.items()
}


# --------------------------------------------------
# Read enriched events
# --------------------------------------------------

events = []

if events_path.endswith(
    ".jsonl"
):

    with open(
        events_path,
        "r",
        encoding="utf-8"
    ) as f:

        for line in f:

            line = line.strip()

            if line:

                events.append(
                    json.loads(line)
                )

else:

    data = load_json(events_path)

    if isinstance(data, list):
        events = data
    else:
        events = [data]


events_by_id = {}

for event in events:

    eid = event_id(event)

    if eid:
        events_by_id[eid] = event


# --------------------------------------------------
# IOC feed lookup
# --------------------------------------------------

feed_lookup = {}


for item in feed_data.get(
    "iocs",
    []
):

    value = clean(
        item.get("value")
        or item.get("indicator")
        or item.get("ioc")
    )

    if not value:
        continue


    feed_lookup[value] = {

        "type":
            clean(
                item.get("type")
                or "unknown"
            ),

        "confidence":
            clean(
                item.get("confidence")
                or "medium"
            ).lower(),
    }


# --------------------------------------------------
# Resolve IOC evidence from findings
# --------------------------------------------------

package_iocs = []
package_keys = set()

new_discovered = 0


for letter in (
    "A",
    "B",
    "C",
):

    finding = findings[letter]
    incident = incidents[letter]

    incident_id = clean(
        incident.get("incident_id")
    )


    # --------------------------------------------------
    # Finding text
    #
    # A candidate is considered explicitly relevant
    # when it appears in the finding narrative/actions
    # or in incidents.json ioc_list.
    # --------------------------------------------------

    finding_text = json.dumps(
        finding,
        ensure_ascii=False
    )


    explicit_iocs = {
        clean(value)
        for value
        in incident.get(
            "ioc_list",
            []
        )
        if clean(value)
    }


    # --------------------------------------------------
    # Only inspect events cited in the finding.
    # --------------------------------------------------

    references = [
        clean(ref)
        for ref
        in finding.get(
            "event_refs",
            []
        )
        if clean(ref)
    ]


    for ref in references:

        if ref not in events_by_id:
            continue

        event = events_by_id[ref]

        candidates = (
            extract_candidates(event)
        )


        for ioc_type, value in candidates:

            in_feed = (
                value in feed_lookup
            )


            explicitly_relevant = (
                value in explicit_iocs
                or value in finding_text
            )


            # Include feed IOCs observed in the
            # evidence or newly discovered values
            # explicitly identified by the finding.
            if not (
                in_feed
                or explicitly_relevant
            ):
                continue


            key = (
                incident_id,
                ioc_type,
                value
            )


            # Find all event refs backing this IOC.
            backing = []

            times = []


            for check_ref in references:

                event2 = events_by_id.get(
                    check_ref
                )

                if not event2:
                    continue


                if (
                    ioc_type,
                    value
                ) in extract_candidates(
                    event2
                ):

                    backing.append(
                        check_ref
                    )

                    ts = event_time(
                        event2
                    )

                    if ts:
                        times.append(ts)


            # Requirement: every IOC must
            # have event backing.
            if not backing:
                continue


            if key in package_keys:
                continue


            package_keys.add(key)


            source = (
                "ioc_feed"
                if in_feed
                else "shift_discovered"
            )


            if source == (
                "shift_discovered"
            ):
                new_discovered += 1


            if in_feed:

                confidence = (
                    feed_lookup[value][
                        "confidence"
                    ]
                )

            else:

                confidence = clean(
                    finding.get(
                        "confidence"
                    )
                    or "low"
                ).lower()


            if confidence not in (
                "low",
                "medium",
                "high",
            ):
                confidence = "medium"


            first_seen = (
                min(times)
                if times
                else ""
            )

            last_seen = (
                max(times)
                if times
                else ""
            )


            package_iocs.append({

                "type":
                    ioc_type,

                "value":
                    defang(
                        ioc_type,
                        value
                    ),

                "first_seen":
                    first_seen,

                "last_seen":
                    last_seen,

                "incident_id":
                    incident_id,

                "source":
                    source,

                "confidence":
                    confidence,

                # Internal validation only.
                "_raw_value":
                    value,

                "_event_refs":
                    backing,
            })


# --------------------------------------------------
# Validate IOC event backing
# --------------------------------------------------

for ioc in package_iocs:

    if not ioc["_event_refs"]:

        raise SystemExit(
            "[resp] ERROR: IOC "
            f"{ioc['value']} "
            "has no event backing"
        )


# --------------------------------------------------
# Build containment actions
# --------------------------------------------------

actions = []
action_keys = set()


def add_action(
    priority,
    action,
    target_type,
    target_value,
    incident_id,
    impact,
    approval,
):

    if incident_id not in (
        valid_incident_ids
    ):

        raise SystemExit(
            "[resp] ERROR: action "
            f"references invalid incident "
            f"{incident_id}"
        )


    action = clean(action)[:160]
    impact = clean(impact)[:160]


    key = (
        priority,
        target_type,
        target_value,
        incident_id,
    )


    if key in action_keys:
        return


    action_keys.add(key)


    actions.append({

        "priority":
            priority,

        "action":
            action,

        "target_type":
            target_type,

        "target_value":
            target_value,

        "incident_id":
            incident_id,

        "operational_impact":
            impact,

        "requires_approval_from":
            approval,
    })


# --------------------------------------------------
# Immediate: confirmed IOC IPs
# --------------------------------------------------

for ioc in package_iocs:

    if ioc["type"] != "ip":
        continue


    add_action(

        "immediate",

        (
            "Block confirmed malicious "
            f"IP {ioc['value']} at the "
            "perimeter firewall."
        ),

        "ip",

        ioc["value"],

        ioc["incident_id"],

        (
            "Connections to this "
            "destination will be blocked."
        ),

        "SOC Lead",
    )


# --------------------------------------------------
# Incident-derived host/user/service actions
# --------------------------------------------------

for letter in (
    "A",
    "B",
    "C",
):

    incident = incidents[letter]
    finding = findings[letter]

    iid = incident["incident_id"]


    # --------------------------------------------------
    # Immediate: isolate affected hosts
    # --------------------------------------------------

    for host in incident.get(
        "host_list",
        []
    ):

        host = clean(host)

        if not host:
            continue


        add_action(

            "immediate",

            (
                f"Isolate {host} from the "
                "network while preserving "
                "security telemetry."
            ),

            "host",

            host,

            iid,

            (
                "Host network access will "
                "be interrupted during "
                "containment."
            ),

            "SOC Lead",
        )


    # --------------------------------------------------
    # Short term: reset involved accounts
    # --------------------------------------------------

    for user in incident.get(
        "user_list",
        []
    ):

        user = clean(user)

        if not user:
            continue


        add_action(

            "short_term",

            (
                f"Reset credentials and "
                f"review active sessions "
                f"for account {user}."
            ),

            "user",

            user,

            iid,

            (
                "User sessions may be "
                "terminated and credentials "
                "must be redistributed."
            ),

            "System Owner",
        )


# --------------------------------------------------
# Short term: IOC service names
# --------------------------------------------------

for ioc in package_iocs:

    if ioc["type"] != (
        "service_name"
    ):
        continue


    add_action(

        "short_term",

        (
            "Audit service accounts and "
            f"services matching "
            f"{ioc['value']}."
        ),

        "service",

        ioc["value"],

        ioc["incident_id"],

        (
            "Service review may require "
            "temporary restart or "
            "credential rotation."
        ),

        "System Owner",
    )


# --------------------------------------------------
# Medium term:
# firewall review by affected zone
# --------------------------------------------------

assets_data = {}

try:
    assets_data = load_json(
        assets_path
    )
except Exception:
    assets_data = {}


if isinstance(
    assets_data,
    list
):
    asset_list = assets_data

elif isinstance(
    assets_data,
    dict
):
    asset_list = assets_data.get(
        "assets",
        []
    )

else:
    asset_list = []


asset_by_host = {}


for asset in asset_list:

    host = clean(
        asset.get("host")
        or asset.get("hostname")
        or asset.get("name")
    ).lower()

    if host:
        asset_by_host[host] = asset


for letter in (
    "A",
    "B",
    "C",
):

    incident = incidents[letter]
    iid = incident["incident_id"]

    zones = set()


    for host in incident.get(
        "host_list",
        []
    ):

        hostname = clean(
            host
        ).lower()

        asset = asset_by_host.get(
            hostname,
            {}
        )

        zone = clean(
            asset.get("zone")
        )

        if zone:
            zones.add(zone)


        # Additional Sysmon coverage.

        add_action(

            "medium_term",

            (
                "Deploy or tighten Sysmon "
                f"detection coverage on "
                f"{host}."
            ),

            "host",

            clean(host),

            iid,

            (
                "Additional telemetry may "
                "increase endpoint log "
                "volume."
            ),

            "Security Architecture",
        )


    for zone in sorted(zones):

        add_action(

            "medium_term",

            (
                "Review and tighten "
                f"firewall rules for "
                f"zone {zone}."
            ),

            "rule",

            zone,

            iid,

            (
                "Firewall changes may "
                "affect legitimate traffic "
                "and require testing."
            ),

            "Security Architecture",
        )


# --------------------------------------------------
# Maximum 12 actions
#
# Keep priority order:
# immediate -> short-term -> medium-term
# --------------------------------------------------

priority_order = {
    "immediate": 0,
    "short_term": 1,
    "medium_term": 2,
}


actions.sort(
    key=lambda x: (
        priority_order[
            x["priority"]
        ],
        x["incident_id"],
        x["target_type"],
        x["target_value"],
    )
)


actions = actions[:12]


# Assign action IDs AFTER limiting.

for number, action in enumerate(
    actions,
    start=1,
):

    action["action_id"] = (
        f"ACT-{number:03d}"
    )


# Put action_id first for readability.

final_actions = []


for action in actions:

    final_actions.append({

        "action_id":
            action["action_id"],

        "priority":
            action["priority"],

        "action":
            action["action"],

        "target_type":
            action["target_type"],

        "target_value":
            action["target_value"],

        "incident_id":
            action["incident_id"],

        "operational_impact":
            action[
                "operational_impact"
            ],

        "requires_approval_from":
            action[
                "requires_approval_from"
            ],
    })


# --------------------------------------------------
# Validate action incident IDs
# --------------------------------------------------

for action in final_actions:

    if action[
        "incident_id"
    ] not in valid_incident_ids:

        raise SystemExit(
            "[resp] ERROR: invalid "
            "incident_id in action"
        )


# --------------------------------------------------
# Containment output
# --------------------------------------------------

containment = {

    "shift_id":
        shift_id,

    "generated_at":
        now(),

    "actions":
        final_actions,
}


with open(
    containment_path,
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        containment,
        f,
        indent=2,
    )

    f.write("\n")


# --------------------------------------------------
# Remove internal IOC fields
# --------------------------------------------------

final_iocs = []


for ioc in package_iocs:

    final_iocs.append({

        "type":
            ioc["type"],

        "value":
            ioc["value"],

        "first_seen":
            ioc["first_seen"],

        "last_seen":
            ioc["last_seen"],

        "incident_id":
            ioc["incident_id"],

        "source":
            ioc["source"],

        "confidence":
            ioc["confidence"],
    })


# --------------------------------------------------
# IOC package
# --------------------------------------------------

cluster = clean(
    campaign.get(
        "cluster_id"
    )
)

if cluster not in (
    "HC-RED7",
    "unknown",
):
    cluster = "unknown"


ioc_package = {

    "shift_id":
        shift_id,

    "tlp":
        "AMBER",

    "cluster_id":
        cluster,

    "generated_at":
        now(),

    "iocs":
        final_iocs,
}


with open(
    package_path,
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        ioc_package,
        f,
        indent=2,
    )

    f.write("\n")


# --------------------------------------------------
# Print summary
# --------------------------------------------------

priority_counts = {
    "immediate": 0,
    "short_term": 0,
    "medium_term": 0,
}


for action in final_actions:

    priority_counts[
        action["priority"]
    ] += 1


type_counts = {
    "ip": 0,
    "domain": 0,
    "hash": 0,
    "account": 0,
    "service_name": 0,
    "port": 0,
}


for ioc in final_iocs:

    if ioc["type"] in type_counts:

        type_counts[
            ioc["type"]
        ] += 1


print(
    "[resp] actions: "
    f"immediate={priority_counts['immediate']} "
    f"short_term={priority_counts['short_term']} "
    f"medium_term={priority_counts['medium_term']} "
    f"total={len(final_actions)}"
)


print(
    "[resp] IOCs: "
    f"ip={type_counts['ip']} "
    f"domain={type_counts['domain']} "
    f"hash={type_counts['hash']} "
    f"account={type_counts['account']} "
    f"service={type_counts['service_name']} "
    f"port={type_counts['port']} "
    f"total={len(final_iocs)}"
)


print(
    "[resp] newly discovered "
    f"(not in feed): {new_discovered}"
)


print(
    "[resp] all IOCs traced "
    "to events: OK"
)


print(
    "[resp] containment.json written"
)

print(
    "[resp] ioc_package.json written"
)

PY
