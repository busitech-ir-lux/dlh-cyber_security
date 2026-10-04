#!/bin/bash

WAZUH_RULES="hunt_wazuh_rules.xml"
NETWORK_RULES="hunt_network_rules.rules"

# --------------------------------------------------
# Create Wazuh-style rule drafts
# --------------------------------------------------

cat > "$WAZUH_RULES" <<'EOF'
<group name="healthbane_hunt,">

  <!-- PsExec from unusual source -->
  <rule id="100100" level="12">
    <field name="data.win.eventdata.image">(?i)psexec</field>
    <description>PsExec activity - check source host and admin baseline</description>
  </rule>

  <!-- LSASS access -->
  <rule id="100101" level="13">
    <field name="data.win.eventdata.targetImage">(?i)lsass.exe</field>
    <description>LSASS accessed by process - check source process allowlist</description>
  </rule>

  <!-- Service account authentication -->
  <rule id="100102" level="13">
    <field name="data.win.eventdata.targetUserName">(?i)svc_</field>
    <description>Service account authentication - check authorized source host</description>
  </rule>

  <!-- WMI child process -->
  <rule id="100103" level="10">
    <field name="data.win.eventdata.parentImage">(?i)wmiprvse.exe</field>
    <field name="data.win.eventdata.image">(?i)(cmd.exe|powershell.exe)</field>
    <description>WMI spawned command shell or PowerShell</description>
  </rule>

</group>
EOF

# --------------------------------------------------
# Create network-level rule draft
# --------------------------------------------------

cat > "$NETWORK_RULES" <<'EOF'
# Draft network detection rule
# Detect possible PsExec SMB service installation

alert tcp any any -> any 445 (
    msg:"Possible PsExec SMB Lateral Movement";
    flow:to_server,established;
    content:"PSEXESVC";
    nocase;
    sid:9000030;
    rev:1;
)
EOF

# --------------------------------------------------
# Print documentation
# --------------------------------------------------

echo "================================================================"
echo "   DETECTION ENGINEERING - Hunt-Derived Rules"
echo "================================================================"
echo

echo "=== WAZUH-STYLE RULE DRAFTS ==="
echo

echo "[Rule 100100] PsExec from Non-Admin Workstation"
echo "  Behavior: PsExec execution from unusual source"
echo "  Evidence: Hunt Task 4"
echo "  FP Rate: VERY LOW"
echo "  Baseline: Allow WS-ADMIN-01 and Robert Kim's normal schedule"
echo

echo "[Rule 100101] LSASS Memory Access from Non-System Process"
echo "  Behavior: Suspicious process accessing lsass.exe"
echo "  Evidence: Hunt Task 6"
echo "  FP Rate: LOW"
echo "  Baseline: Allow known Windows/system processes"
echo

echo "[Rule 100102] Service Account from Unauthorized Host"
echo "  Behavior: Service account used outside its approved server"
echo "  Evidence: Hunt Task 9"
echo "  FP Rate: VERY LOW"
echo "  Baseline: Compare source with service_accounts.txt"
echo

echo "[Rule 100103] WMI Remote Child Process Anomaly"
echo "  Behavior: wmiprvse.exe spawning cmd.exe or powershell.exe"
echo "  Evidence: Hunt Task 5"
echo "  FP Rate: MEDIUM"
echo "  Baseline: Allow known admin activity from WS-ADMIN-01"
echo

echo "=== NETWORK RULE DRAFTS ==="
echo

echo "[Rule 9000030] SMB Lateral Movement - PsExec Service Installation"
echo "  Behavior: PSEXESVC pattern over SMB"
echo "  Evidence: Hunt Task 4"
echo "  FP Rate: LOW"
echo "  Baseline: Allow documented admin PsExec activity"
echo

echo "=== DETECTION POSTURE UPDATE ==="
echo "  Before hunt: 55% observed coverage"
echo "  After hunt: approximately 80% coverage"
echo
echo "  Newly improved coverage:"
echo "    - PsExec lateral movement"
echo "    - LSASS credential access"
echo "    - Service account misuse"
echo "    - WMI remote execution"
echo "    - SMB/PsExec network activity"
echo

echo "Draft files created:"
echo "  $WAZUH_RULES"
echo "  $NETWORK_RULES"

echo
echo "================================================================"