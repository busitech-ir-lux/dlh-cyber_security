# MedDefense SOC Triage Methodology

## Classification Taxonomy

* `true_positive`: The alert correctly identifies malicious or unauthorized activity; example: `ssh_brute_force` shows repeated failed SSH logins followed by suspicious access.
* `false_positive`: The rule fired on activity that should not be treated as a security alert, including authorized activity; example: `unknown_outbound_destination` fires for an approved external service.
* `benign`: The alert represents unusual but harmless activity, with no evidence of compromise and no clear rule defect; example: `unknown_outbound_destination` points to a `clean` IOC and behavior consistent with the host baseline.
* `escalated`: The alert has sufficient evidence of compromise or unauthorized activity to require Tier 2 handling; example: `credential_theft_chain` is supported by related suspicious events and is handed to Tier 2.

## Priority Ordering Rule

Work alerts in descending `priority_score`. If scores tie, keep queue order. Override normal ordering when evidence shows a malicious IOC, active compromise, or multiple alerts clearly describing the same incident.

## Evidence Requirement

Every ticket must reference at least one `event_ref` from `enriched_events.json`.

* `true_positive`: cite `timestamp`, `hostname`, and the exact rule-relevant field/value showing unauthorized or malicious activity.
* `false_positive`: cite `timestamp`, `hostname`, and the field/value proving the activity is expected or authorized.
* `benign`: cite the event fields plus baseline or IOC context showing the activity is harmless.
* `escalated`: include supporting `event_ref` values, relevant field/value evidence, IOC hits, and related events.

## Escalation Criteria

Escalate when any predicate is true:

* `classification == true_positive`
* `ioc_reputation == malicious`
* `related_alerts >= 2 AND evidence shows one underlying incident`
* `priority_score >= 10 AND evidence shows active or unauthorized activity`
* `evidence shows credential theft, unauthorized patient-data access, or suspicious medical-segment egress`

## SLA

* `critical`: 15 minutes
* `high`: 30 minutes
* `medium`: 60 minutes
* `low`: same day

## Documentation Standard

Every ticket must contain:

* [ ] `ticket_id`
* [ ] `alert_id`
* [ ] `classification`
* [ ] `justification`
* [ ] `evidence_refs`
* [ ] `ioc_hits`
* [ ] `attack_techniques`
* [ ] `recommended_action`
* [ ] `analyst_time_seconds`
* [ ] `created_at`

