Overview

This pipeline inventories, validates, parses, normalizes, cleans, enriches, validates, and indexes multi-source cybersecurity evidence from Windows, Linux, firewall, Suricata, and PCAP-derived telemetry. The one-command entry point is ./evidence_pipeline.sh <evidence_pack_root>. The orchestrator sets EVIDENCE_PACK, runs all executable stages in order, fails fast on errors, and writes a timestamped run log. event_schema.json is a required design artifact and is not executed as a pipeline stage.

Stage Table

stage

script

input

output

failure_modes

0

0-source_inventory.sh

windows/, linux/, network/

source_inventory.json

missing pack; unreadable file; hash/parse failure

1

1-telemetry_import.sh

student_telemetry/*.json

import_validation.json

missing file; invalid JSON; empty file; required telemetry field missing

2

2-windows_parse.sh

windows/*.json, student Windows telemetry

windows_events.json

missing source; malformed JSON; parse/write failure

3

3-linux_parse.sh

linux/auth.log, audit.log, syslog, student Linux telemetry

linux_events.json

missing source; malformed telemetry JSON; parse/write failure

5

5-normalize.sh

windows_events.json, linux_events.json, event_schema.json

normalized_events.json, quarantine.json

required field missing; timestamp unparseable; schema mapping failure

6

6-network_normalize.sh

network/firewall.csv, suricata_eve.json, pcap_summary.json

network_events.json; append to normalized_events.json

missing source; invalid CSV/JSON; timestamp conversion failure

7

7-schema_validate.sh

event_schema.json, normalized_events.json

validation_report.json

required field null/missing; type mismatch; compliance ≤99%

8

8-data_quality.sh

normalized_events.json

cleaned_events.json, cleaning_log.json

unrepaired timestamp; malformed input; cleaning/write failure

9

9-enrich.sh

cleaned_events.json, context/asset_inventory.json, network_zones.json

enriched_events.json

missing context file; invalid JSON/CIDR; enrichment/write failure

10

10-timeline.sh

enriched_events.json

timeline_index.json

invalid/missing timestamp; malformed input; write failure

11

11-source_stats.sh

enriched_events.json

source_stats.json

missing input; invalid timestamp/data shape; jq failure

Schema Summary

Schema definition: event_schema.json

Required fields:

timestamp

source_type

event_category

raw_message

The current schema also defines optional analytical fields including hostname, severity, user, process_name, src_ip, and dst_ip.

Inputs and Outputs

Expected evidence pack:

<evidence_pack_root>/
├── windows/
│   ├── security.json
│   ├── sysmon.json
│   └── powershell.json
├── linux/
│   ├── auth.log
│   ├── audit.log
│   └── syslog
├── network/
│   ├── firewall.csv
│   ├── suricata_eve.json
│   └── pcap_summary.json
├── context/
│   ├── asset_inventory.json
│   └── network_zones.json
└── student_telemetry/
    ├── windows_events.json
    ├── linux_events.json
    └── attack_ground_truth.json

Final handoff directory:

$HANDOFF_DIR/
├── event_schema.json
├── enriched_events.json
├── timeline_index.json
├── source_stats.json
├── validation_report.json
├── cleaning_log.json
└── pipeline_run.log

Running the Pipeline

./evidence_pipeline.sh ~/evidence_pack_primary

Generalization test:

./13-pipeline_test.sh

Known Limitations

Linux syslog timestamps without a year require a configured or inferred evidence year.

Network-only records may not have hostname or user context.

PCAP summary timestamps are interpreted using the expected source format and UTC assumption.

Deduplication uses selected normalized fields and may collapse repeated events that are semantically identical.

Asset and zone enrichment depends on complete, current inventory and CIDR definitions.
