# The Patch Equation


## Introduction
"The window between disclosure and exploitation is measured in hours. The window between patch availability and deployment is measured in months." — Mandiant M-Trends, 2024

You hardened billing-srv-01. You instrumented every endpoint. Sysmon, auditd, Script Block Logging: the defensive layer is in place. Then, at 08:14 this morning, Dr. Morales forwards you a CISA advisory. Three critical CVEs landed overnight: a kernel privilege escalation in linux-image (CISA KEV, active exploitation), an openssh-server pre-authentication RCE and a TLS parsing bug in libssl3. Every server you hardened is on the affected list.

Hardening decays. sysctl values, AppArmor profiles, PAM policies do not change by themselves, but the software they protect does. Every week, new CVEs are published. Every month, vendors ship patches. And every quarter, some hospital somewhere gets breached through a vulnerability that had a fix available for 180 days. The advisory was explicit: in 4 of 5 hospital breaches, the compromised software had a patch sitting in the repository the whole time.

This project treats patching as engineering, not housekeeping. You will build a pipeline that measures vulnerability exposure, maps which services a patch can break, snapshots state before touching anything, applies patches safely, validates the outcome, detects configuration drift, recovers a broken apt state, rolls back when a patch regresses and tracks every change as structured data. No policy writing. No change request templates. No maintenance window calendars. Only scripts and JSON. The organizational process sits on top of this later, but the engine underneath has to work first.

Why this matters
Patching is the most boring and most dangerous operation in endpoint security. Boring because nothing visibly changes when it works. Dangerous because one unattended apt upgrade -y can brick a billing server at 02:00 on a Sunday. The engineers who get this right build the inventory, the snapshot, the validation, the rollback and the compliance artifact as code. Everything in this project is deterministic, measurable and replayable. When Dr. Morales asks "are we vulnerable to CVE-2024-1086 right now ?", the answer is not an opinion. It is a JSON file produced by a script you wrote.

Context
Week eight at MedDefense Health Systems. Thursday morning.

Dr. Patricia Morales drops a printed CISA advisory on your desk. The email chain above it is three hours old.

"Three CVEs. All critical. All affect packages running on our Linux fleet. The kernel one is in CISA KEV with active exploitation. The OpenSSH one dropped yesterday and there are already proof-of-concepts on GitHub. And libssl3 affects every TLS connection on every server. I need to know three things by tonight: which of our systems are exposed, what a patch to each of those systems would break and how fast we can safely roll them out."

She turns to the whiteboard and writes the CVEs.

"And I do not want a Word document. I want a pipeline. If I get another one of these advisories next week, I do not want to redo this work. I want to run one script, hand me a JSON report and know in five minutes which of our servers is a risk."

James Chen arrives with additional context:

"One more thing. billing-srv-01 has a broken apt state from an interrupted upgrade last week. Mike Torres ran apt upgrade -y without a maintenance window, the session died halfway through, and nobody fixed it. dpkg is locked, apache2 is half-configured. Add that to your list. I want the broken state recovered by the same pipeline that handles the new advisory."

Sarah Park adds the constraint that matters most:

"Whatever you build, it runs against production. No staging environment. No lab doubles. So the pipeline has to be safe by default: measure first, then change, then validate and always keep the rollback path open."

Learning Objectives
By the end of this project, you are expected to be able to explain to anyone, without the help of Google:

Vulnerability Management

How to enumerate installed packages and cross-reference them against known CVE sources using apt, dpkg and apt-get changelog

How to prioritize patches using CVSS, exploit availability, asset criticality and exposure, and why raw CVSS alone is an incomplete signal

How to validate that a patch actually resolved the vulnerability it was intended to fix, not just that the command succeeded

The difference between security patches, feature updates, kernel updates and library updates, and why each has a different deployment and rollback profile

Change Management

How to produce a structured change log from package operations, capturing what was modified, when, by whom and with what outcome

How maintenance window enforcement works as code, not policy: a script that refuses to apply changes outside defined windows

How to track configuration drift introduced by patch operations, distinguishing expected changes from unexpected ones

How to build an end-to-end patch pipeline that is idempotent, auditable and safe to re-run

Operational Skills

How to diagnose and repair a broken apt/dpkg state: stale locks, half-configured packages, interrupted transactions, unmet dependencies

How to configure unattended-upgrades for security-only patching with blacklists for critical packages and suppressed automatic reboots

How to implement rollback via apt version downgrade, apt-mark hold and preference pinning

How to write idempotent bash scripts that measure system state before and after every change and emit structured JSON artifacts

Resources
Read or Watch:

Patch Management

NIST SP 800-40 Rev.4: Guide to Enterprise Patch Management Planning -- The authoritative patch management reference. Read Sections 3 through 5.

CISA Known Exploited Vulnerabilities Catalog -- Active exploitation data feed used for prioritization.

Ubuntu Security Notices -- Upstream CVE-to-package mapping for the distribution you are patching.

Debian and APT Internals

Debian APT Preferences Manual -- Pin syntax and priority rules.

Unattended Upgrades Wiki -- Configuration and behavior of the automatic security updater.

dpkg Internals (Debian Admin Handbook, Chapter 5) -- Package state machine and recovery semantics.

CVE and Vulnerability Feeds

NVD CVE Data Feeds -- Machine-readable CVE source used for lookup tasks.
Man or Help:

man apt

man apt-get

man apt-mark

man apt_preferences

man dpkg

man dpkg-query

man unattended-upgrades

man needrestart

Requirements
General
A README.md file, at the root of the folder of the project, is mandatory.

All your files should end with a new line.

Bash Scripting
All your scripts must be executable.

The first line of all your scripts should be exactly #!/bin/bash.

All scripts must pass shellcheck without errors.

Scripts that modify system state must be idempotent: a second execution must not corrupt state and must not re-apply changes that are already in place.

Specific Project Rules
Measure before you change. Every task that modifies package state must first capture the relevant state and store it in JSON for comparison.

JSON is the deliverable format. Every analysis, validation and tracking task produces a structured JSON artifact. Human-readable summaries printed to stdout are allowed, but the machine-readable artifact is the deliverable.

No blind upgrades. apt upgrade -y without a preceding dry-run, dependency analysis and plan is the incident this project was created to prevent. Every patch action must be preceded by a plan and followed by a validation.

Rollback must always be possible. Every patch operation must leave enough state behind to reverse it. Scripts must record pre-operation package versions so that the rollback script (T9) can use them.

No centralized SIEM dependency. This project does not assume a Wazuh manager, Splunk instance or any external aggregator. All outputs are local files on the hardened endpoint.
