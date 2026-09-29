# YARA Rule Testing Results - HEALTHBANE Campaign

**Analyst:** MH
**Project:** 4x02 Intelligence-Driven Defense - Task 11
**Date:** 30 September 2026
**Corpus:** `samples\_manifest.txt` (seed 20260425)

\---

## Overview

This document records systematic testing of all YARA rules from Tasks 9 and 10 against the HEALTHBANE sample corpus. Metrics include True Positives (TP), True Negatives (TN), False Positives (FP), False Negatives (FN), detection rate, false positive rate, precision, and deployment recommendations.

\---

### Rule: HEALTHBANE\_Phishing\_PDF

|Metric|Value|
|-|-|
|True Positives|2|
|True Negatives|2|
|False Positives|0|
|False Negatives|0|
|Detection Rate|100%|
|False Positive Rate|0%|
|Precision|100%|
|**Recommendation**|**DEPLOY**|

**Analysis:** Perfect score on PDF corpus. No modifications required. The rule successfully distinguishes campaign lures from benign invoices using the combination of toolkit fingerprint (wkhtmltopdf) and lure tokens (INV-2026-, urgency CTAs).

**Deployment Decision:** DEPLOY — Ready for production use at mail gateway or endpoint scanning.

\---

### Rule: HEALTHBANE\_Email\_Headers

|Metric|Value|
|-|-|
|True Positives|3|
|True Negatives|1|
|False Positives|0|
|False Negatives|0|
|Detection Rate|100%|
|False Positive Rate|0%|
|Precision|100%|
|**Recommendation**|**DEPLOY**|

**Analysis:** Perfect score on email corpus. The separator-tolerant regex for PHPMailer (`X-?Mailer:\\s\*PHPMailer\[\\s\\-\\/\\.]?\[0-9]`) successfully catches all three emails including the hyphen variant (email\_03). The benign newsletter is correctly rejected because it lacks X-Priority header and PHPMailer tooling.

**Known Limitation:** The rule only matches .eml files in the manifest; .txt variants (renamed uploads) also trigger but represent duplicate evidence, not new detections.

**Deployment Decision:** DEPLOY — Ready for production use at mail gateway with real-time YARA integration.

\---

### Rule: HEALTHBANE\_Document\_Metadata

|Metric|Value|
|-|-|
|True Positives|2|
|True Negatives|2|
|False Positives|0|
|False Negatives|0|
|Detection Rate|100%|
|False Positive Rate|0%|
|Precision|100%|
|**Recommendation**|**DEPLOY**|

**Analysis:** Perfect score on PDF corpus. The simplified `wkhtmltopdf` literal string (no version regex) combined with the PDF magic check at offset 0 reliably identifies campaign lures. The false negative discovered earlier was due to an incorrect `uint32()` endianness check, which has been corrected.

**Deployment Decision:** DEPLOY — Ready for production use on endpoint scanning or email attachment filtering.

\---

### Rule: HEALTHBANE\_Campaign\_Composite

|Metric|Value|
|-|-|
|True Positives|5|
|True Negatives|3|
|False Positives|0|
|False Negatives|0|
|Detection Rate|100%|
|False Positive Rate|0%|
|Precision|100%|
|**Recommendation**|**DEPLOY**|

**Analysis:** Perfect score across all 8 manifest samples (5 malicious, 3 benign). The threshold logic (3-of-5 families) provides high-fidelity detection while surviving single-attribute rotation. The benign newsletter correctly fails the threshold because it contains only one family (brand lookalike via recipient address).

**Operational Value:** This rule serves as a high-confidence escalation tier for SOC triage. Lower-threshold rules (Email\_Headers, Document\_Metadata) provide broad coverage; the composite provides escalation evidence.

**Deployment Decision:** DEPLOY — Ready for production use in SOC alerting pipelines with high-severity classification.

\---

## Testing Summary

### All Rules Summary Table

|Rule|TP|TN|FP|FN|Detection Rate|FP Rate|Precision|Recommendation|
|-|-|-|-|-|-|-|-|-|
|HEALTHBANE\_Phishing\_PDF|2|2|0|0|100%|0%|100%|DEPLOY|
|HEALTHBANE\_Email\_Headers|3|1|0|0|100%|0%|100%|DEPLOY|
|HEALTHBANE\_Document\_Metadata|2|2|0|0|100%|0%|100%|DEPLOY|
|HEALTHBANE\_Campaign\_Composite|5|3|0|0|100%|0%|100%|DEPLOY|

### Aggregate Statistics

* **Total Samples Tested:** 8 (5 malicious, 3 benign)
* **Total Rule-Sample Evaluations:** 12 unique manifest entries
* **Overall Detection Rate:** 100%
* **Overall False Positive Rate:** 0%
* **Rules Ready for Deployment:** 4/4

\---

## False Negative Analysis

*None encountered during this test cycle. All expected detections fired successfully.*

\---

## False Positive Analysis

*None encountered during this test cycle. All benign samples remained silent across all rules.*

\---

## Deployment Recommendations

### Production Readiness Assessment

|Rule|Status|Justification|
|-|-|-|
|HEALTHBANE\_Phishing\_PDF|**DEPLOY**|Perfect precision and recall on test corpus; tooling fingerprint is campaign-specific; low risk of drift|
|HEALTHBANE\_Email\_Headers|**DEPLOY**|Perfect precision and recall; separator-tolerant regex prevents variant misses; header-based detection survives body regeneration|
|HEALTHBANE\_Document\_Metadata|**DEPLOY**|Perfect precision and recall; simplified tooling string reduces brittleness; PDF magic check ensures file-type specificity|
|HEALTHBANE\_Campaign\_Composite|**DEPLOY**|Perfect precision and recall; cross-family threshold provides high-fidelity escalation; resilient to single-attribute rotation|

### Integration Guidance

1. **Mail Gateway Integration:** Deploy `HEALTHBANE\_Email\_Headers` and `HEALTHBANE\_Document\_Metadata` via ClamAV/YARA hook on inbound SMTP
2. **Endpoint Scanning:** Deploy `HEALTHBANE\_Phishing\_PDF` and `HEALTHBANE\_Document\_Metadata` on scheduled file-system scans
3. **SOC Alerting:** Configure `HEALTHBANE\_Campaign\_Composite` matches as HIGH severity incidents requiring immediate analyst review
4. **Feedback Loop:** Monitor production alert volumes; if FP rate exceeds 1%, tune the composite threshold (4-of-5 instead of 3-of-5)

### Maintenance Cadence

* **Weekly:** Review false-positive alerts from production deployment; refine string patterns if recurring benign matches occur
* **Monthly:** Test all rules against new threat-intel samples; update toolkit fingerprints as adversaries rotate tools
* **Quarterly:** Full re-validation against expanded corpus including newly collected phishing samples

\---

## Appendix: Known Edge Cases Documented

1. **PHPMailer Separator Variation:** `PHPMailer 6.6.0` (space) vs `PHPMailer-6.6.0` (hyphen). Handled via character-class regex; prevents classic literal-matching false negative.
2. **wkhtmltopdf Version Pinning:** Initial regex `/wkhtmltopdf\[ \\/]?0?\\.?12\\.?6/i` too restrictive; simplified to literal `/wkhtmltopdf/i` since version adds no additional discrimination power.
3. **PDF Magic Byte Endianness:** Initial `uint32(0) == 0x25504446` check failed due to little-endian mismatch; replaced with `$pdf\_magic at 0` string anchor.
4. **Duplicate Corpus Files:** `.txt` renamed uploads of `.eml` emails match identically; treated as duplicate evidence, not independent tests.

\---

*End of YARA Rule Testing Report*

