# The Breach

## Introduction

> "_We don't rise to the level of our expectations; we fall to the level of our training._" — **Archilochus**

Everything you have built across this module gets used here. The IR program. The containment discipline. The forensic rigor. The detection rules and their validation. The post-incident improvement process. The tabletop methodology.

None of it is called out by name. None of it is guided step by step. Sunday evening, 19:43, MedDefense has a problem. You own the response from the first alert to the board brief the morning after.

This capstone does not introduce new techniques. It demands you apply the ones you have already built, at the same time, across the full incident lifecycle, in an environment you know. You will triage, contain, investigate, communicate, eradicate, recover, and improve, in that order, under that pressure, with nothing but your prior work as a reference.

Three review checkpoints are embedded in the capstone. They test whether you understand the principles behind what you have been doing, at the depth and difficulty the professional field expects. They are placed at the points where the operational work pauses long enough to ask a harder question.

### Why this matters

Incident response is a full-contact skill. Reading about containment is not the same as choosing between two containment strategies with patient care on the line. Understanding forensics is not the same as finding a 72-hour-old Cobalt Strike beacon in a memory dump. Knowing the HIPAA breach rule is not the same as writing the four-factor assessment for 1,847 patient files at midnight with a board meeting in nine hours.

The skills tested here, and the judgment required to apply them, are what the market looks for when it hires **IR analysts**, **forensic** **investigators**, **detection** **engineers**, and **blue** **team** **leads**. They appear in hiring exercises and practical interviews because they are the shape of the actual job.

---

## Context

Sunday, 19:43. Your personal device buzzes. It is Mike Torres.

_"I need you on a call right now. Something is wrong at Site A. The on-call nurse says her workstation is crawling and files on her desktop look different. I checked the scheduling server, it is hammering the disk. I pulled the SIEM and I see a service installation alert on three hosts I have never seen before. I do not know what I am looking at."_

You do.

The attacker gained initial access via a spearphishing email with a malicious Word document macro, delivered to the MedDefense on-call clinical coordinator on Thursday. The macro executed a PowerShell downloader that retrieved a Cobalt Strike beacon from a squatted Microsoft CDN domain. The beacon has been running for 72 hours.

During the dwell period, the attacker moved laterally to three additional workstations using extracted NTLM credential hashes, accessed the clinical documentation file server, and read 1,847 patient files, lab results and clinical notes. Ransomware staging scripts have been placed in system directories on four workstations. They have not yet executed.

You must contain this before Sunday is over.

**Provided artifacts**

- `cs-ws-101.dd` disk image of the initial compromised workstation, acquired before isolation
    
- `cs-ws-101.mem` memory dump of the same workstation, acquired at `19:38Z` before the call
    
- `proxy_72h.jsonl` proxy logs for all MedDefense hosts covering the 72-hour dwell window
    
- `sysmon_multihost.jsonl` Sysmon process creation and network connection events across all affected hosts for the same window
    
- `fileserver_access.evtx` Windows Security Event Log from the file server covering the dwell period
    

---

## Requirements

- A `Linux` workstation with Volatility 3, The Sleuth Kit, `bash`, `sha256sum`, `jq`, and `yamllint`
    
- The provided forensic artifacts listed in the Context section
    
- All artifacts produced in 5x00 through 5x04 (playbooks, severity matrix, templates, detection rules)
    

### Lab Materials

Expected local structure:

```text
5x05/
├── fileserver_access.sample.json
├── proxy_72h.sample.jsonl
├── sysmon_multihost.sample.jsonl
└── torres_call_transcript.md
```