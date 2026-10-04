#!/bin/bash

ALERTS="siem_export/wazuh_alerts_14d.json"
SYSMON="siem_export/wazuh_raw_sysmon_14d.json"
MATRIX="reference/service_accounts.txt"

DATA="/tmp/svc_hunt.jsonl"

# --------------------------------------------------
# Prepare SIEM data
# --------------------------------------------------

jq -c 'if type == "array" then .[] else . end' \
    "$ALERTS" "$SYSMON" > "$DATA"

echo "================================================================"
echo "   HUNT EXECUTION - H5: Service Account Abuse"
echo "   Technique: T1078.002 Domain Accounts"
echo "================================================================"
echo

# --------------------------------------------------
# Show authorization matrix
# --------------------------------------------------

echo "SERVICE ACCOUNT AUTHORIZATION MATRIX:"

grep -Ei "svc_" "$MATRIX"

echo

# --------------------------------------------------
# Get service accounts from reference file
# --------------------------------------------------

ACCOUNTS=$(grep -Eoi 'svc_[a-zA-Z0-9_-]+' "$MATRIX" | sort -u)

TOTAL_UNAUTHORIZED=0

echo "AUTHENTICATION AUDIT:"
echo

# --------------------------------------------------
# Check each service account
# --------------------------------------------------

for ACCOUNT in $ACCOUNTS
do
    # Find the host authorized for this account
    AUTH_HOST=$(grep -i "$ACCOUNT" "$MATRIX" |
        grep -Eo '(SRV|WS)-[A-Za-z0-9-]+' |
        head -1)

    TMP="/tmp/${ACCOUNT}_auth.jsonl"

    # Find events containing this service account
    jq -c --arg ACCOUNT "$ACCOUNT" '
        select(
            (
                (.data.win.eventdata.targetUserName // "") |
                ascii_downcase
            ) == ($ACCOUNT | ascii_downcase)

            or

            (
                (.data.win.eventdata.user // "") |
                ascii_downcase |
                contains($ACCOUNT | ascii_downcase)
            )
        )
    ' "$DATA" > "$TMP"

    TOTAL=$(wc -l < "$TMP")
    AUTHORIZED=0
    UNAUTHORIZED=0

    echo "  $ACCOUNT:"
    echo "    Authorized host: $AUTH_HOST"
    echo "    Total auth events: $TOTAL"

    while IFS=$'\t' read -r TIME SOURCE TARGET LOGONTYPE AUTH_TYPE COMMAND
    do
        BAD=0
        FLAGS=""

        # ------------------------------------------
        # Wrong source host
        # ------------------------------------------

        if [ "$SOURCE" != "$AUTH_HOST" ]; then
            FLAGS="$FLAGS
        [!] Wrong source host"
            BAD=1
        fi

        # ------------------------------------------
        # Workstation source
        # ------------------------------------------

        if [[ "$SOURCE" == WS-* ]]; then
            FLAGS="$FLAGS
        [!] Service account used from workstation"
            BAD=1
        fi

        # ------------------------------------------
        # Interactive login
        # 2  = Interactive
        # 10 = Remote Interactive
        # ------------------------------------------

        if [ "$LOGONTYPE" = "2" ] || [ "$LOGONTYPE" = "10" ]; then
            FLAGS="$FLAGS
        [!] Interactive logon"
            BAD=1
        fi

        # ------------------------------------------
        # NTLM check
        # ------------------------------------------

        if [[ "$AUTH_TYPE" == *"NTLM"* ]]; then
            FLAGS="$FLAGS
        [!] NTLM authentication"
        fi

        # ------------------------------------------
        # Classification
        # ------------------------------------------

        if [ "$BAD" -eq 0 ]; then
            AUTHORIZED=$((AUTHORIZED + 1))
        else
            UNAUTHORIZED=$((UNAUTHORIZED + 1))
            TOTAL_UNAUTHORIZED=$((TOTAL_UNAUTHORIZED + 1))

            echo
            echo "      $TIME"
            echo "        Source: $SOURCE"
            echo "        Target: $TARGET"
            echo "        Logon Type: $LOGONTYPE"
            echo "        Authentication: $AUTH_TYPE"

            if [ "$COMMAND" != "unknown" ]; then
                echo "        Related command: $COMMAND"
            fi

            echo "$FLAGS"
        fi

    done < <(
        jq -r '
            [
                (.timestamp // "unknown"),

                (.data.win.eventdata.workstationName //
                 .data.win.eventdata.ipAddress //
                 .agent.name //
                 "unknown"),

                (.data.win.system.computer //
                 .data.win.eventdata.targetServerName //
                 "unknown"),

                (.data.win.eventdata.logonType //
                 "unknown"),

                (.data.win.eventdata.authenticationPackageName //
                 "unknown"),

                (.data.win.eventdata.commandLine //
                 "unknown")
            ]
            | @tsv
        ' "$TMP"
    )

    echo "    Authorized: $AUTHORIZED"
    echo "    UNAUTHORIZED: $UNAUTHORIZED"
    echo
done

# --------------------------------------------------
# Correlation with lateral movement tools
# --------------------------------------------------

echo "LATERAL MOVEMENT CORRELATION:"

jq -r '
    select(
        (tostring | test("svc_"; "i"))
        and
        (tostring | test("psexec|wmi|winrm|psremoting"; "i"))
    )
    |
    [
        (.timestamp // "unknown"),
        (.agent.name // .data.win.system.computer // "unknown"),
        (.data.win.eventdata.targetUserName //
         .data.win.eventdata.user //
         "unknown"),
        (.data.win.eventdata.commandLine // "unknown")
    ]
    | @tsv
' "$DATA" |
while IFS=$'\t' read -r TIME HOST USER COMMAND
do
    echo "  $TIME"
    echo "    Host: $HOST"
    echo "    User: $USER"
    echo "    Command: $COMMAND"
done

echo

# --------------------------------------------------
# Final result
# --------------------------------------------------

echo "FINDING:"

if [ "$TOTAL_UNAUTHORIZED" -gt 0 ]; then
    echo "  Status: POSITIVE - CRITICAL CONFIDENCE"
    echo "  Service account authentication was found outside"
    echo "  its authorized host or normal service context."
    echo "  Recommendation: ESCALATE"
else
    echo "  Status: NO POSITIVE FINDING"
    echo "  Service account usage matched the authorization matrix."
fi

echo
echo "================================================================"