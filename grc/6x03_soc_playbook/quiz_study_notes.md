# SOC automation quiz study notes

The source labels this quiz Task 0. No individual platform questions are supplied,
so these notes explain the concepts needed for the written and coding tasks.

## Enrichment, triage, and response

An indicator of compromise, or IOC, is a value that may help identify suspicious
activity, such as an IP address or domain. Enrichment attaches context: local-feed
matches, confidence, address type, and best-effort reverse DNS. Triage uses that
context to prioritize a case. Response changes an operational system, such as
isolating a workstation or disabling an account.

At MedDefense, enrichment and case preparation can reduce repetitive lookup work.
They still need correct source data and error handling. A `BLOCK` verdict means
strong indicator evidence under the exercise rules; the program does not actually
block anything. The credential playbook records a proposed isolation action for
analyst authorization, protecting clinical systems from an unreviewed response.

## Confidence is not certainty

The local feed uses a confidence threshold of 80: at or above it the label is
BLOCK; below it a listed malicious IOC is INVESTIGATE. Unknown indicators score
30 and require review. The prescribed private/loopback and benign-list exemptions
score zero, but those exemptions are limited enrichment rules, not proof that an
internal user or host is uncompromised.

A compromised internal sender can participate in a real attack. Do not use an
allowlisted IP alone as production authority to close a behavior-based alert.
Similarly, an internal source does not cancel the risk of a Domain Admin account
appearing in a credential-access alert. The privilege decision must remain visible.

## False positives and false negatives

A false positive marks benign activity as malicious; acting on it could interrupt
patient care. A false negative misses malicious activity; closing that alert can
hide a real incident. These errors need different measurements. Define the labeled
population and denominator before reporting a rate, and have an analyst check
outcomes independently of the automation's own verdict.

Matching five known fixtures verifies those decision paths, not the real-world
error rate. Before production closure or response actions, MedDefense also requires
measured error rates, owner approval, clinical review, exceptions, audit records,
change control, and a way to reverse the decision where possible.

## Two kinds of deduplication

Within one phishing alert, a sender IP can appear again inside a URL. Normalize
and enrich each unique host once. Alert 001 has four occurrences but only two
unique hosts, so it needs two enrichments.

Across alerts, repeated detections or replayed messages can create many cases for
the same event. Use a stable event identity to prevent duplicate case creation,
and a separate correlation rule to attach genuinely related events without hiding
new evidence. This prototype implements within-alert IOC deduplication only;
replaying an alert creates another case. Production needs idempotent case/queue
writes before a live alert-to-ticket connection.

## Caching and failure handling

A time-to-live, or TTL, cache keeps a lookup result for a defined interval. Repeated
queries can reuse it until expiry, reducing latency and external API demand. The
cache must include the normalized IOC, source/version, observation time, and expiry;
a feed update or corrected verdict may require immediate invalidation.

A timeout must not be cached as a clean result. When enrichment fails, preserve
the alert for review rather than closing it. The exercise uses a local feed and
has no TTL cache or live reputation API integration. Reverse DNS is supporting
metadata: NXDOMAIN or TIMEOUT must not override a known feed match.

## Cases, logs, and operational limits

Cases store the decision, status, notes, and linked indicators. An append-only
execution log makes it possible to trace which playbook ran against which alert
and case. Local file and database evidence still needs protected permissions,
retention, backups, and a reliable delivery/retry design before production use.

The SOC planning baseline is 150 total alerts per day at eight minutes each:
20 analyst-hours, with 13.4 hours of enrichment at 67%. Those are planning numbers,
not measured savings from this lab. The strategy separates them from the different
150-phishing-alert illustration in the task instructions.
