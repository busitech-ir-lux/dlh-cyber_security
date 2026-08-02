#!/bin/bash
#===============================================================================
# 1-cis_profile.sh
#
# MedDefense - System Hardening Project
# Task 1: MedDefense CIS Control Profile
#
# Generates cis_profile.json: a threat-driven subset of the CIS Ubuntu 22.04
# LTS Benchmark, scoped to billing-srv-01, web-srv-01 and log-srv-01, and
# mapped to the six risks identified in the MedDefense assessment:
#
#   R1  SSH lateral movement            R4  Missing audit visibility
#   R2  Weak authentication             R5  Exposed database services
#   R3  Unnecessary services            R6  Insufficient kernel hardening
#
# This profile is the CONTRACT that every later hardening script implements
# and every verification script tests against. Nothing gets hardened that is
# not in this file, and nothing in this file goes unimplemented.
#
# The output is deterministic: no timestamps, no host-specific data. Two runs
# produce a byte-identical file, so `git diff cis_profile.json` shows policy
# changes only - never noise. That is what makes this script idempotent, and
# it is why the generation timestamp lives in the evidence artifacts from
# task 0 rather than in the policy document itself.
#
# Usage:
#   ./1-cis_profile.sh [-o OUTPUT_FILE]
#===============================================================================

set -euo pipefail

OUTPUT_FILE="${OUTPUT_FILE:-cis_profile.json}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output) OUTPUT_FILE="$2"; shift 2 ;;
        -h|--help)   grep '^#' "$0" | sed 's/^# \?//' | head -25; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

# Expected profile shape. The script validates its own output against these
# values before exiting - a profile that silently drifts out of shape would
# break every downstream remediation and verification script.
EXPECT_CONTROLS=15
EXPECT_CRITICAL=5
EXPECT_HIGH=7
EXPECT_MEDIUM=3
EXPECT_SECTIONS=5
EXPECT_TASKS=10

#-------------------------------------------------------------------------------
# The control profile
#
# CIS references are given at section level (e.g. "CIS 5.2 SSH Server
# Configuration") rather than by exact recommendation number, because
# recommendation numbering shifts between benchmark releases. Pin the exact
# numbers from the PDF version in use before submitting to audit.
#-------------------------------------------------------------------------------
cat > "$OUTPUT_FILE" <<'JSON'
{
  "profile": {
    "name": "MedDefense Linux Server Hardening Profile",
    "profile_version": "1.0.0",
    "schema_version": "1.0",
    "benchmark": "CIS Ubuntu Linux 22.04 LTS Benchmark",
    "cis_profile_level": "Level 1 Server, with selected Level 2 controls",
    "scope": ["billing-srv-01", "web-srv-01", "log-srv-01"],
    "selection_basis": "Controls were selected against the six MedDefense assessment risks, not by benchmark completeness. A generic CIS pass would produce several hundred recommendations; this profile is the enforceable subset that materially reduces the identified attack paths on these three hosts.",
    "risks_addressed": {
      "R1": "SSH lateral movement",
      "R2": "Weak authentication",
      "R3": "Unnecessary services",
      "R4": "Missing audit visibility",
      "R5": "Exposed database services",
      "R6": "Insufficient kernel hardening"
    }
  },

  "controls": [
    {
      "control_id": "MD-CIS-001",
      "title": "Enforce key-only SSH authentication and reject empty passwords",
      "cis_section": "5 - Access, Authentication and Authorization",
      "severity": "critical",
      "asset_scope": ["billing-srv-01", "web-srv-01", "log-srv-01"],
      "threat_mapping": {
        "meddefense_risk": "R1 - SSH lateral movement / R2 - Weak authentication",
        "attack_narrative": "A single reused or phished credential currently yields an interactive shell on any of the three servers. Password authentication is what converts one credential compromise into full lateral movement across the estate.",
        "mitre_attack": ["T1021.004", "T1110.001", "T1078"]
      },
      "implementation_task": "2-ssh_auth_hardening.sh",
      "verification_method": "sshd -T | grep -E '^(passwordauthentication|permitemptypasswords|kbdinteractiveauthentication) ' must return 'no' for all three directives; an ssh attempt with a valid password and no key must be rejected before the shell is granted.",
      "justification": "CIS 5.2 (SSH Server Configuration), Level 1. This is the highest-leverage single control in the profile: it removes the entire credential-guessing attack surface rather than rate-limiting it. Prerequisite gate - the implementation script must abort if no authorized key is installed for an allowed account, since applying this control on a keyless host is a self-inflicted denial of service."
    },
    {
      "control_id": "MD-CIS-002",
      "title": "Prohibit direct SSH login as root",
      "cis_section": "5 - Access, Authentication and Authorization",
      "severity": "critical",
      "asset_scope": ["billing-srv-01", "web-srv-01", "log-srv-01"],
      "threat_mapping": {
        "meddefense_risk": "R1 - SSH lateral movement",
        "attack_narrative": "root is the one account name an attacker can rely on existing on every host, making it the default target for credential attacks. Direct root login also destroys attribution: every action lands in the logs as 'root' with no originating human identity.",
        "mitre_attack": ["T1021.004", "T1078.003"]
      },
      "implementation_task": "2-ssh_auth_hardening.sh",
      "verification_method": "sshd -T | grep '^permitrootlogin ' must return 'no'; a direct 'ssh root@host' attempt must be refused; sudo escalation from a named account must still succeed.",
      "justification": "CIS 5.2 (SSH Server Configuration), Level 1. Forces every privileged action through a named account and sudo, which is what makes the auditd trail from MD-CIS-005 attributable to a person. Note that the Ubuntu default of 'prohibit-password' is not sufficient here - it still permits key-based root login, which defeats attribution."
    },
    {
      "control_id": "MD-CIS-003",
      "title": "Lock accounts after repeated failed authentication attempts",
      "cis_section": "5 - Access, Authentication and Authorization",
      "severity": "critical",
      "asset_scope": ["billing-srv-01", "web-srv-01", "log-srv-01"],
      "threat_mapping": {
        "meddefense_risk": "R2 - Weak authentication",
        "attack_narrative": "Without lockout, an attacker can attempt credentials indefinitely against any authentication path that survives MD-CIS-001 - console, sudo, and any service using PAM - at machine speed and without generating an alert.",
        "mitre_attack": ["T1110", "T1110.003"]
      },
      "implementation_task": "4-pam_hardening.sh",
      "verification_method": "grep pam_faillock /etc/pam.d/common-auth /etc/pam.d/common-account must match; five deliberate failures against a disposable test account must produce a lock, confirmed via 'faillock --user <acct>'; the account must auto-unlock after unlock_time.",
      "justification": "CIS 5.3 (Configure PAM), Level 1. Configured as deny=5, unlock_time=900 rather than a permanent lock: in a clinical environment an indefinite lockout is itself a safety event, since a locked-out administrator cannot respond to a system failure at 03:00. Fifteen minutes destroys brute-force economics while remaining self-healing. root is deliberately exempted from lockout (even_deny_root omitted) to preserve a break-glass path, with the compensating control that root has no network login path at all under MD-CIS-002."
    },
    {
      "control_id": "MD-CIS-004",
      "title": "Enforce default-deny inbound host firewall posture",
      "cis_section": "3 - Network Configuration",
      "severity": "critical",
      "asset_scope": ["billing-srv-01", "web-srv-01", "log-srv-01"],
      "threat_mapping": {
        "meddefense_risk": "R5 - Exposed database services / R3 - Unnecessary services",
        "attack_narrative": "The task 0 baseline shows listeners reachable from the network that no documented workflow requires. Any service that binds a socket is reachable until proven otherwise, including services installed as package dependencies that nobody chose to run.",
        "mitre_attack": ["T1046", "T1190", "T1133"]
      },
      "implementation_task": "10-firewall_default_deny.sh",
      "verification_method": "ufw status verbose must report 'Default: deny (incoming), deny (routed)'; a port scan from an adjacent host must return only the documented allowlist; the open-port count must match the baseline delta report.",
      "justification": "CIS 3.5 (Firewall Configuration), Level 1. Default-deny inverts the burden of proof: services become unreachable unless explicitly justified, so a newly installed package cannot silently widen the attack surface. This is a host firewall and does not replace the network boundary - it is the control that still applies once an attacker is already inside the segment. Implementation order is a safety requirement: the SSH allow rule must be committed before the policy is enabled, or the run locks out its own operator."
    },
    {
      "control_id": "MD-CIS-005",
      "title": "Deploy auditd with an immutable, security-relevant rule set",
      "cis_section": "4 - Logging and Auditing",
      "severity": "critical",
      "asset_scope": ["billing-srv-01", "web-srv-01", "log-srv-01"],
      "threat_mapping": {
        "meddefense_risk": "R4 - Missing audit visibility",
        "attack_narrative": "With no audit subsystem, an intrusion leaves no reconstructable record. Privilege escalation, identity file modification and PHI access are all currently invisible, which means an incident cannot be scoped and a breach notification cannot be bounded.",
        "mitre_attack": ["T1070", "T1562.001", "T1548.003"]
      },
      "implementation_task": "9-auditd_deployment.sh",
      "verification_method": "systemctl is-enabled --quiet auditd && systemctl is-active --quiet auditd; 'auditctl -s' must report enabled 2 (immutable); 'auditctl -l | wc -l' must be non-zero; a deliberate write to /etc/passwd must appear via 'ausearch -k identity'.",
      "justification": "CIS 4.1 (Configure System Accounting), Level 2. Accepted as critical despite Level 2 status because MedDefense handles PHI: a healthcare breach investigation that cannot establish which records were accessed must be reported at worst-case scope. The '-e 2' immutable flag is what makes the trail trustworthy - an attacker with root can still stop the daemon, but cannot quietly edit the rules and continue, and the reboot required to change them is itself a logged event."
    },
    {
      "control_id": "MD-CIS-006",
      "title": "Enforce SSH idle timeout, login grace period and authentication attempt limits",
      "cis_section": "5 - Access, Authentication and Authorization",
      "severity": "high",
      "asset_scope": ["billing-srv-01", "web-srv-01", "log-srv-01"],
      "threat_mapping": {
        "meddefense_risk": "R1 - SSH lateral movement",
        "attack_narrative": "Abandoned interactive sessions on unattended terminals are a standing authenticated foothold. Unbounded login grace periods additionally allow an attacker to hold open pre-authentication connections and exhaust the daemon's connection slots.",
        "mitre_attack": ["T1563.001", "T1499.002"]
      },
      "implementation_task": "3-ssh_session_controls.sh",
      "verification_method": "sshd -T must show clientaliveinterval 300, clientalivecountmax 3, logingracetime 60 and maxauthtries 4; an idle session must be terminated within the configured window.",
      "justification": "CIS 5.2 (SSH Server Configuration), Level 1. ClientAliveCountMax is set to 3 rather than the CIS-recommended 0, a documented deviation: on a high-latency or briefly flapping link, a value of 0 tears down an administrator's session on the first missed probe, which during an active incident is an availability risk with no security benefit. The effective idle limit remains bounded at 15 minutes, and the compensating control is screen locking on the administrative workstations."
    },
    {
      "control_id": "MD-CIS-007",
      "title": "Restrict SSH access to explicitly authorized groups",
      "cis_section": "5 - Access, Authentication and Authorization",
      "severity": "high",
      "asset_scope": ["billing-srv-01", "web-srv-01", "log-srv-01"],
      "threat_mapping": {
        "meddefense_risk": "R1 - SSH lateral movement / R2 - Weak authentication",
        "attack_narrative": "Every account on the host is currently a viable SSH entry point, including service and application accounts that have no business logging in interactively. A compromised web application account should not translate into a shell.",
        "mitre_attack": ["T1078.003", "T1021.004"]
      },
      "implementation_task": "3-ssh_session_controls.sh",
      "verification_method": "sshd -T | grep '^allowgroups ' must list only the approved administrative groups; an account outside those groups holding a valid key must be refused; group membership must reconcile against the sudo membership captured in the task 0 baseline.",
      "justification": "CIS 5.2 (SSH Server Configuration), Level 1. Group-based allowlisting rather than user-based: an AllowUsers list drifts the moment staff change, whereas group membership is already managed as part of joiner/leaver process. This narrows the account surface from every entry in /etc/passwd to a reviewed list, and makes the review itself a single 'getent group' command."
    },
    {
      "control_id": "MD-CIS-008",
      "title": "Enforce password quality, reuse history and ageing policy",
      "cis_section": "5 - Access, Authentication and Authorization",
      "severity": "high",
      "asset_scope": ["billing-srv-01", "web-srv-01", "log-srv-01"],
      "threat_mapping": {
        "meddefense_risk": "R2 - Weak authentication",
        "attack_narrative": "Default policy permits short, previously breached passwords on accounts that hold sudo. These survive MD-CIS-001 on every non-SSH authentication path: console, sudo escalation, and any PAM-backed application.",
        "mitre_attack": ["T1110.001", "T1110.002", "T1078"]
      },
      "implementation_task": "4-pam_hardening.sh",
      "verification_method": "A scripted 'chpasswd' attempt with a 8-character password against a disposable test account must be rejected; /etc/security/pwquality.conf must show minlen=14 with the four credit classes set; 'grep ENCRYPT_METHOD /etc/login.defs' must return yescrypt or sha512.",
      "justification": "CIS 5.3 (Configure PAM) and 5.4 (User Accounts and Environment), Level 1. Length is weighted above rotation: minlen=14 with history enforcement, but PASS_MAX_DAYS kept at 365 rather than the shorter intervals CIS suggests. Documented deviation - forced 90-day rotation demonstrably drives predictable incrementing passwords and shoulder-written credentials on clinical workstations, and NIST SP 800-63B recommends against it. The compensating controls are the lockout in MD-CIS-003 and key-only remote access in MD-CIS-001."
    },
    {
      "control_id": "MD-CIS-009",
      "title": "Remove or disable non-essential services and legacy insecure clients",
      "cis_section": "2 - Services",
      "severity": "high",
      "asset_scope": ["billing-srv-01", "web-srv-01", "log-srv-01"],
      "threat_mapping": {
        "meddefense_risk": "R3 - Unnecessary services",
        "attack_narrative": "Each running service is an independently exploitable process, and legacy clients such as telnet, rsh and ftp transmit credentials in cleartext - directly feeding the credential reuse that drives R1. The task 0 baseline shows services running that no documented workflow requires.",
        "mitre_attack": ["T1190", "T1543.002", "T1040"]
      },
      "implementation_task": "5-service_minimization.sh",
      "verification_method": "The running-service count must fall measurably against the task 0 baseline; 'dpkg -l' must show no telnet, rsh-client, ftp or nis packages; every remaining running service must appear in the documented service allowlist.",
      "justification": "CIS 2.1 (Configure Time Synchronization) and 2.2 (Special Purpose Services), Level 1. The mechanism is mask-then-remove rather than stop: a stopped service restarts on the next dependency pull or reboot, whereas a masked unit cannot. The service allowlist is per-role, not per-estate - log-srv-01 legitimately runs collectors that would be an unexplained listener on web-srv-01, so this control is verified against role, not against a single global list."
    },
    {
      "control_id": "MD-CIS-010",
      "title": "Bind database and management listeners to loopback or the management interface",
      "cis_section": "2 - Services",
      "severity": "high",
      "asset_scope": ["billing-srv-01", "log-srv-01"],
      "threat_mapping": {
        "meddefense_risk": "R5 - Exposed database services",
        "attack_narrative": "A database bound to 0.0.0.0 is directly reachable from any host that can route to the segment, turning a single application-layer flaw or leaked connection string into direct access to billing records and PHI - with no need to compromise the application server at all.",
        "mitre_attack": ["T1190", "T1046", "T1005"]
      },
      "implementation_task": "5-service_minimization.sh",
      "verification_method": "ss -tulnp must show the database listener bound to 127.0.0.1 or the management address only, never 0.0.0.0 or ::; a connection attempt from an off-host address must fail at the TCP layer.",
      "justification": "CIS 2.2 (Special Purpose Services), Level 1. Scoped to billing-srv-01 and log-srv-01 because web-srv-01 hosts no database of its own. This is deliberate defence in depth beneath MD-CIS-004: the firewall is the enforcement boundary, but a firewall is one 'ufw disable' or one misordered rule change away from exposure, whereas a loopback bind fails closed. Where the application genuinely requires a remote database connection, the compensating control is a bind to the management interface with TLS required, documented in the implementation script."
    },
    {
      "control_id": "MD-CIS-011",
      "title": "Apply network stack sysctl protections",
      "cis_section": "3 - Network Configuration",
      "severity": "high",
      "asset_scope": ["billing-srv-01", "web-srv-01", "log-srv-01"],
      "threat_mapping": {
        "meddefense_risk": "R6 - Insufficient kernel hardening",
        "attack_narrative": "Default kernel networking accepts ICMP redirects and source-routed packets, permitting an attacker on the segment to reroute traffic through a host they control, and leaves the host willing to forward traffic - turning a compromised server into a pivot into the clinical network.",
        "mitre_attack": ["T1557", "T1090", "T1498"]
      },
      "implementation_task": "6-kernel_network_hardening.sh",
      "verification_method": "sysctl -a must show tcp_syncookies=1, ip_forward=0, accept_redirects=0, secure_redirects=0, send_redirects=0, accept_source_route=0, rp_filter=1 and log_martians=1 across all and default scopes, IPv4 and IPv6; values must persist across reboot via /etc/sysctl.d.",
      "justification": "CIS 3.2 (Network Parameters - Host Only) and 3.3 (Network Parameters - Host and Router), Level 1. Settings are delivered as a drop-in file in /etc/sysctl.d/ rather than appended to /etc/sysctl.conf, which is what makes the implementation script idempotent - the file is owned and rewritten rather than grown on each run. ip_forward=0 is a deliberate assertion that none of these three hosts is a router; it must be revisited if container networking is ever introduced on them."
    },
    {
      "control_id": "MD-CIS-012",
      "title": "Enforce nodev, nosuid and noexec on user-writable filesystems",
      "cis_section": "1 - Initial Setup",
      "severity": "high",
      "asset_scope": ["billing-srv-01", "web-srv-01", "log-srv-01"],
      "threat_mapping": {
        "meddefense_risk": "R6 - Insufficient kernel hardening / R1 - SSH lateral movement",
        "attack_narrative": "/tmp, /var/tmp and /dev/shm are writable by every account including compromised service accounts, and are the standard staging ground for dropped tooling. Combined with the unreviewed SUID inventory from the task 0 baseline, this is the shortest available path from web application compromise to root.",
        "mitre_attack": ["T1548.001", "T1068", "T1036.005"]
      },
      "implementation_task": "8-filesystem_mount_options.sh",
      "verification_method": "findmnt must show nodev, nosuid and noexec on /tmp, /var/tmp and /dev/shm; a test binary copied to /tmp must fail to execute; the SUID/SGID and world-writable file counts must reconcile against the task 0 baseline with every remaining entry present on the approved list.",
      "justification": "CIS 1.1.2 (Configure Filesystem Partitions), Level 1. noexec on /tmp is applied with eyes open: some package installers and Java-based clinical middleware use /tmp as a build or extraction area and will fail. The implementation script must test the affected applications in staging first, and where a genuine dependency exists the documented compensating control is a dedicated exec-permitted path outside /tmp with an AppArmor profile and an auditd watch, rather than reverting the mount option estate-wide."
    },
    {
      "control_id": "MD-CIS-013",
      "title": "Enable full address space randomisation and restrict core dumps and ptrace",
      "cis_section": "1 - Initial Setup",
      "severity": "medium",
      "asset_scope": ["billing-srv-01", "web-srv-01", "log-srv-01"],
      "threat_mapping": {
        "meddefense_risk": "R6 - Insufficient kernel hardening",
        "attack_narrative": "Without full ASLR, memory-corruption exploits against exposed services become reliably repeatable rather than probabilistic. Unrestricted core dumps and ptrace let any local account read secrets - credentials, session tokens, PHI in flight - directly out of a privileged process or its crash file.",
        "mitre_attack": ["T1068", "T1003.007", "T1005"]
      },
      "implementation_task": "7-kernel_process_hardening.sh",
      "verification_method": "sysctl kernel.randomize_va_space must return 2, fs.suid_dumpable must return 0, kernel.yama.ptrace_scope must be at least 1; /etc/security/limits.d must enforce a hard core limit of 0; a deliberate crash of a SUID binary must produce no core file.",
      "justification": "CIS 1.5 (Additional Process Hardening), Level 1. Rated medium rather than high because these are exploit-mitigation controls: they raise the cost and reliability threshold of an attack rather than closing an open door, and they only matter once an attacker already has an exploitable flaw or a local foothold. Cheap, zero operational impact, and they make the difference between a proof-of-concept and a working exploit - but they are correctly ranked below the controls that remove access outright."
    },
    {
      "control_id": "MD-CIS-014",
      "title": "Forward logs to log-srv-01 and restrict local log file permissions",
      "cis_section": "4 - Logging and Auditing",
      "severity": "medium",
      "asset_scope": ["billing-srv-01", "web-srv-01", "log-srv-01"],
      "threat_mapping": {
        "meddefense_risk": "R4 - Missing audit visibility",
        "attack_narrative": "Logs held only on the host that generated them are under the control of whoever compromises that host - log clearing is a routine step in the intrusion lifecycle. World-readable log files additionally leak usernames, internal hostnames and access patterns to any local account.",
        "mitre_attack": ["T1070.002", "T1562.001", "T1552.001"]
      },
      "implementation_task": "11-logging_pipeline.sh",
      "verification_method": "A test message injected with 'logger' on billing-srv-01 and web-srv-01 must appear on log-srv-01; rsyslog must be configured with $FileCreateMode 0640; 'find /var/log -type f -perm /o+r' must return nothing outside documented exceptions.",
      "justification": "CIS 4.2 (Configure Logging) and 4.3 (Ensure logrotate is configured), Level 1. Rated medium because MD-CIS-005 already establishes the audit record and this control protects its integrity rather than its existence - but note that forwarding is what makes the record admissible after a full host compromise, since an attacker with root can always alter local files. Transport must be TCP with TLS, not the UDP default: UDP silently drops under load, which produces gaps that look identical to log tampering during an investigation."
    },
    {
      "control_id": "MD-CIS-015",
      "title": "Configure log rotation and retention aligned to healthcare record requirements",
      "cis_section": "4 - Logging and Auditing",
      "severity": "medium",
      "asset_scope": ["billing-srv-01", "web-srv-01", "log-srv-01"],
      "threat_mapping": {
        "meddefense_risk": "R4 - Missing audit visibility",
        "attack_narrative": "Aggressive default rotation destroys the evidence of a slow intrusion before anyone detects it - industry dwell times routinely exceed the default retention window. The inverse failure is equally real: unrotated audit logs fill the partition, at which point auditd halts and visibility is lost entirely.",
        "mitre_attack": ["T1070", "T1499.001"]
      },
      "implementation_task": "11-logging_pipeline.sh",
      "verification_method": "'logrotate -d /etc/logrotate.conf' must parse cleanly with no errors; audit log retention must be configured as max_log_file_action=keep_logs with space_left_action set to notify rather than rotate-and-delete; retained log age on log-srv-01 must meet the documented retention period.",
      "justification": "CIS 4.3 (Ensure logrotate is configured), Level 1. This is the one control in the profile where the retention period is a compliance decision rather than a security one - HIPAA-adjacent audit trails are retained for years, which means rotation must ship logs off-host before compressing, never rotate-and-delete. Deliberate deviation from a pure disk-space policy: on log-srv-01 the space_left_action is set to notify rather than rotate, accepting a disk-full risk in exchange for never silently discarding audit records, with the compensating control of monitored capacity alerting."
    }
  ],

  "documented_deviations": [
    {
      "cis_reference": "CIS 1.6 - Mandatory Access Control (AppArmor enforce mode)",
      "decision": "Deferred from this profile, not rejected",
      "rationale": "AppArmor profile development requires per-service complain-mode observation and log analysis before enforcement, which cannot be delivered as a single idempotent script run against a fresh host. Enforcing shipped profiles blind would break the clinical middleware on billing-srv-01.",
      "compensating_control": "Service minimization (MD-CIS-009), loopback binding (MD-CIS-010) and noexec mounts (MD-CIS-012) constrain the same blast radius. AppArmor remains on the roadmap as a staged follow-up with a complain-mode observation period.",
      "risk_accepted_by": "MedDefense platform security owner",
      "review_date": "next quarterly control review"
    },
    {
      "cis_reference": "CIS 5.2 - SSH ClientAliveCountMax set to 0",
      "decision": "Applied with modification (value 3)",
      "rationale": "A value of 0 terminates an administrator session on a single missed keepalive, which on a flapping link is an availability risk during exactly the incidents where shell access matters most.",
      "compensating_control": "Effective idle limit remains bounded at 15 minutes via ClientAliveInterval 300; workstation screen locking enforced separately.",
      "risk_accepted_by": "MedDefense platform security owner",
      "review_date": "next quarterly control review"
    },
    {
      "cis_reference": "CIS 5.4 - Password expiration of 365 days or less (shortened intervals)",
      "decision": "Applied at the ceiling (365 days), shorter rotation rejected",
      "rationale": "Forced short-interval rotation produces predictable incrementing passwords and written-down credentials on shared clinical workstations, degrading rather than improving authentication strength. Consistent with NIST SP 800-63B guidance against arbitrary periodic rotation.",
      "compensating_control": "minlen=14 with complexity and history (MD-CIS-008), failed-attempt lockout (MD-CIS-003), and key-only remote access (MD-CIS-001).",
      "risk_accepted_by": "MedDefense platform security owner",
      "review_date": "next quarterly control review"
    }
  ]
}
JSON

#-------------------------------------------------------------------------------
# Derive the summary from the generated file
#
# The counts are parsed back out of the artifact rather than tracked in shell
# variables while writing it. If the JSON and the reported figures ever
# disagree, that is a bug worth failing on - a profile whose summary does not
# match its contents cannot be used as an audit input.
#-------------------------------------------------------------------------------
count_key_value() {  # $1 = key, $2 = value
    grep -c "\"$1\": \"$2\"" "$OUTPUT_FILE" || true
}

distinct_values() {  # $1 = key -> number of distinct string values
    grep -o "\"$1\": \"[^\"]*\"" "$OUTPUT_FILE" | sort -u | wc -l
}

TOTAL="$(grep -c '"control_id":' "$OUTPUT_FILE" || true)"
CRITICAL="$(count_key_value severity critical)"
HIGH="$(count_key_value severity high)"
MEDIUM="$(count_key_value severity medium)"
SECTIONS="$(distinct_values cis_section)"
TASKS="$(distinct_values implementation_task)"

#-------------------------------------------------------------------------------
# Self-validation gate
#-------------------------------------------------------------------------------
FAILED=0
check() {  # $1 = label, $2 = actual, $3 = expected
    if [[ "$2" -ne "$3" ]]; then
        echo "VALIDATION FAILED: $1 = $2, expected $3" >&2
        FAILED=1
    fi
}
check "control count" "$TOTAL"     "$EXPECT_CONTROLS"
check "critical"      "$CRITICAL"  "$EXPECT_CRITICAL"
check "high"          "$HIGH"      "$EXPECT_HIGH"
check "medium"        "$MEDIUM"    "$EXPECT_MEDIUM"
check "cis sections"  "$SECTIONS"  "$EXPECT_SECTIONS"
check "impl tasks"    "$TASKS"     "$EXPECT_TASKS"

# Structural validation where a parser is available. Malformed JSON here would
# fail silently in every downstream script that consumes the profile.
if command -v python3 >/dev/null 2>&1; then
    python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$OUTPUT_FILE" 2>/dev/null \
        || { echo "VALIDATION FAILED: $OUTPUT_FILE is not valid JSON" >&2; FAILED=1; }
elif command -v jq >/dev/null 2>&1; then
    jq -e . "$OUTPUT_FILE" >/dev/null 2>&1 \
        || { echo "VALIDATION FAILED: $OUTPUT_FILE is not valid JSON" >&2; FAILED=1; }
fi

if (( FAILED )); then
    echo "Profile generation aborted: output does not match the declared shape." >&2
    exit 1
fi

#-------------------------------------------------------------------------------
# Summary
#-------------------------------------------------------------------------------
echo "Controls selected: ${TOTAL}"
echo "Critical: ${CRITICAL}"
echo "High: ${HIGH}"
echo "Medium: ${MEDIUM}"
echo "CIS sections covered: ${SECTIONS}"
echo "Mapped implementation tasks: ${TASKS}"
echo "Report saved to: ${OUTPUT_FILE}"

exit 0
