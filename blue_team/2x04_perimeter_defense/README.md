# Perimeter and Network Defense

## Introduction

> _"The network is the only place where you can see an attacker before they are inside a machine. Lose that view and you lose the first move."_ — **Richard Bejtlich, The Practice of Network Security Monitoring**

Every endpoint in MedDefense is now hardened. `auditd` is loaded on every Linux host. Sysmon and Script Block Logging cover every Windows host. PAM, `AppArmor`, `sysctl`, audit policy: the host layer is in place. Then at 10:22 on Tuesday, Mike Torres walks over with a single observation that undoes half the work. Between the hardened endpoints, the network is flat. Anything that reaches one machine can reach every other machine. There is nothing on the wire between them.

This project builds the control plane that lives between hosts. You will map what the host sees from its own interface, enumerate the attack surface it presents, design zones with intent, write `nftables` rules that enforce default-deny, validate every rule with real connection tests, audit and remediate insecure protocols, parse firewall logs for scan patterns, replay packet captures through Suricata in offline mode, write custom Suricata rules against MedDefense-specific threats, investigate a suspicious PCAP byte by byte and package the resulting network evidence in the exact format Module 3 will consume. No live monitoring stack. No SIEM daemon. No collector. Every deliverable is a script, a rule file or a structured JSON artifact.

### Why this matters

A hardened host on a flat network is a solved problem sitting next to an unsolved one. The attacker who cannot defeat your `sshd` configuration can still scan your subnet, move laterally over SMB, tunnel data over DNS or pivot through a forgotten Telnet listener on a medical device. The defenses in this project cover the space between hosts. And because the evidence you produce (firewall logs, PCAP summaries, Suricata alerts, connection metadata) is the same evidence a Tier 1 SOC analyst reads every shift, the artifacts you ship at the end of this project become the input dataset for the analyst work in Module 3. Build them as if a junior analyst will read them next week, because one will.

---

## Context

**Week nine at MedDefense Health Systems. Tuesday morning.**

Mike Torres, the network engineer, drops a printed `arp -a` dump and a manual `traceroute` on your desk.

_"I ran a few probes between `billing-srv-01`, `web-srv-01` and `log-srv-01`. Everything talks to everything on every port. The clinical workstations talk to the medical device VLAN. The guest Wi-Fi can reach the billing database. There is a lab PC in radiology still running Telnet. I hardened nothing because my job is network plumbing, not endpoint configuration, but this is the part nobody can fix with Sysmon."_

He sketches a diagram on a legal pad.

```css
  [ guest wifi ]  ─┐
                   │
  [ clinical ws ]  ┼── flat L2 ──┬── [ server zone ]
                   │              │
  [ mgmt ws ]  ────┘              └── [ medical device zone ]
```

_"Every line is an allowed path. Not because we chose to allow it. Because we never chose to block it. That is the problem."_

James Chen adds the operational constraint.

_"We do not run a live IDS. We do not run a central manager. We do not run Splunk. What we do run is `nftables` on every Linux host, Windows Firewall on every Windows host and a Suricata binary that we point at captured PCAPs offline when we need to investigate something. So everything you build this week has to fit that footprint. No daemons that expect a collector. No rules that expect a manager. Local enforcement, local evidence, local validation."_

Sarah Park adds one more thing.

_"And whatever evidence you produce at the end, package it so the Module 3 analysts can read it without calling you. They get the same JSON, same directory layout, same field names every week. If you can make it boring, you have done it right."_
