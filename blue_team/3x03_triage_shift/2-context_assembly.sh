#!/bin/bash
set -euo pipefail

# ------------------------------------------------------------
# Paths
# ------------------------------------------------------------

CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x03_assets}"

QUEUE="$CATALOG_DIR/alerts/alert_queue.json"
ASSETS="$HANDOFF_DIR/context/asset_inventory.json"
EVENTS="$HANDOFF_DIR/data/enriched_events.json"
BASELINE="$BASELINE_PKG/baselines/baseline_summary.json"
IOCS="$ASSETS_DIR/ioc_context.json"
OUTPUT="enriched_queue.json"

mkdir -p tickets

# Make sure all required inputs exist.
for file in "$QUEUE" "$ASSETS" "$EVENTS" "$BASELINE" "$IOCS"; do
    [[ -f "$file" ]] || {
        echo "ERROR: $file not found" >&2
        exit 1
    }
done

# ------------------------------------------------------------
# Build enriched queue
# ------------------------------------------------------------

jq \
    --slurpfile assets "$ASSETS" \
    --slurpfile events "$EVENTS" \
    --slurpfile baseline "$BASELINE" \
    --slurpfile iocs "$IOCS" '

# Convert asset inventory to an array if it is keyed by hostname.
def asset_list:
    $assets[0]
    | if type == "array" then .
      else to_entries
           | map(.value + {hostname: (.value.hostname // .key)})
      end;

# Find the asset belonging to a hostname.
def find_asset($host):
    [
      asset_list[]
      | select(
          (.hostname // .host // .asset_id) == $host
        )
    ][0] // null;

# Find the original event referenced by the alert.
def find_event($ref):
    [
      $events[]
      | select(
          (.record_id // .event_ref) == $ref
        )
    ][0] // null;

# Convert an event category to its baseline category.
def baseline_category($category):
    if $category == "authentication" then "authentication"
    elif $category == "process"
      or $category == "powershell"
      or $category == "service" then "process"
    elif $category == "file" then "file"
    elif $category == "network"
      or $category == "network_alert"
      or $category == "network_flow" then "network"
    else $category
    end;

# Find host-specific baseline data relevant to the alert category.
def find_baseline($host; $category):
    (baseline_category($category)) as $wanted

    | [
        $baseline[0]
        | paths(objects) as $path
        | getpath($path) as $value

        | select(
            (
              ($value.hostname? // $value.host? // "") == $host
              or
              (
                ($path[-1] | tostring) == $host
              )
            )
          )

        | select(
            (
              $path
              | map(tostring | ascii_downcase)
              | join(".")
            )
            | contains($wanted)
          )

        | $value
      ][0] // null;

# Find IOC values anywhere in the alert or referenced event.
def find_iocs($alert; $event):
    [
      (
        [$alert, $event]
        | .. | strings
      ) as $value

      | select($iocs[0][$value]? != null)

      | {
          indicator: $value
        }
        + $iocs[0][$value]
        + {
            ioc_flag: ($iocs[0][$value].reputation != "clean")
          }
    ]
    | unique_by(.indicator);

# Convert priority score into its required band.
def priority_band($score):
    if $score >= 20 then "critical"
    elif $score >= 10 then "high"
    elif $score >= 5 then "medium"
    else "low"
    end;

[
  .[] as $alert

  | ($alert.event_summary.hostname // "") as $host
  | ($alert.event_summary.event_category // "") as $category
  | find_event($alert.event_ref) as $event

  | $alert
    + {
        asset: find_asset($host),

        baseline_host_profile:
          find_baseline($host; $category),

        event_record: $event,

        ioc_hits:
          find_iocs($alert; $event),

        priority_band:
          priority_band($alert.priority_score)
      }
]

' "$QUEUE" > "$OUTPUT"

# ------------------------------------------------------------
# Shift summary
# ------------------------------------------------------------

printf "alerts processed          : %s\n" \
    "$(jq 'length' "$OUTPUT")"

printf "assets joined             : %s\n" \
    "$(jq '[.[] | select(.asset != null)] | length' "$OUTPUT")"

printf "missing asset records     : %2s\n" \
    "$(jq '[.[] | select(.asset == null)] | length' "$OUTPUT")"

printf "alerts with IOC hits      : %s\n" \
    "$(jq '[.[] | select((.ioc_hits | length) > 0)] | length' "$OUTPUT")"

printf "  malicious               : %2s\n" \
    "$(jq '[.[] | select(any(.ioc_hits[]?; .reputation == "malicious"))] | length' "$OUTPUT")"

printf "  suspicious              : %2s\n" \
    "$(jq '[.[] | select(any(.ioc_hits[]?; .reputation == "suspicious"))] | length' "$OUTPUT")"

printf "  unknown                 : %2s\n" \
    "$(jq '[.[] | select(any(.ioc_hits[]?; .reputation == "unknown"))] | length' "$OUTPUT")"

printf "baseline profiles joined  : %s\n" \
    "$(jq '[.[] | select(.baseline_host_profile != null)] | length' "$OUTPUT")"

SIZE="$(du -h "$OUTPUT" | cut -f1)"
echo "$OUTPUT written ($SIZE)"
