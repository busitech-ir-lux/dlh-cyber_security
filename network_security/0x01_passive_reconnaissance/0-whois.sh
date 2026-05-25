#!/bin/bash

# Check if a domain argument was provided
if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

DOMAIN=$1

# Execute whois and pipe it directly into awk
whois "$DOMAIN" | awk -F': +' '
BEGIN {
    # 1. Define mappings to capture specific whois keys
    
    # Registrant mappings
    map["Registrant Name"] = "Registrant Name"; map["Registrant Organization"] = "Registrant Organization";
    map["Registrant Street"] = "Registrant Street"; map["Registrant City"] = "Registrant City";
    map["Registrant State/Province"] = "Registrant State/Province"; map["Registrant Postal Code"] = "Registrant Postal Code";
    map["Registrant Country"] = "Registrant Country"; map["Registrant Phone"] = "Registrant Phone";
    map["Registrant Phone Ext"] = "Registrant Phone Ext"; map["Registrant Fax"] = "Registrant Fax";
    map["Registrant Fax Ext"] = "Registrant Fax Ext"; map["Registrant Email"] = "Registrant Email";

    # Admin mappings
    map["Admin Name"] = "Admin Name"; map["Admin Organization"] = "Admin Organization";
    map["Admin Street"] = "Admin Street"; map["Admin City"] = "Admin City";
    map["Admin State/Province"] = "Admin State/Province"; map["Admin Postal Code"] = "Admin Postal Code";
    map["Admin Country"] = "Admin Country"; map["Admin Phone"] = "Admin Phone";
    map["Admin Phone Ext"] = "Admin Phone Ext"; map["Admin Fax"] = "Admin Fax";
    map["Admin Fax Ext"] = "Admin Fax Ext"; map["Admin Email"] = "Admin Email";

    # Tech mappings
    map["Tech Name"] = "Tech Name"; map["Tech Organization"] = "Tech Organization";
    map["Tech Street"] = "Tech Street"; map["Tech City"] = "Tech City";
    map["Tech State/Province"] = "Tech State/Province"; map["Tech Postal Code"] = "Tech Postal Code";
    map["Tech Country"] = "Tech Country"; map["Tech Phone"] = "Tech Phone";
    map["Tech Phone Ext"] = "Tech Phone Ext"; map["Tech Fax"] = "Tech Fax";
    map["Tech Fax Ext"] = "Tech Fax Ext"; map["Tech Email"] = "Tech Email";

    # 2. Define strict output order for the CSV fields
    order[1] = "Registrant Name"; order[2] = "Registrant Organization"; order[3] = "Registrant Street";
    order[4] = "Registrant City"; order[5] = "Registrant State/Province"; order[6] = "Registrant Postal Code";
    order[7] = "Registrant Country"; order[8] = "Registrant Phone"; order[9] = "Registrant Phone Ext";
    order[10] = "Registrant Fax"; order[11] = "Registrant Fax Ext"; order[12] = "Registrant Email";
    
    order[13] = "Admin Name"; order[14] = "Admin Organization"; order[15] = "Admin Street";
    order[16] = "Admin City"; order[17] = "Admin State/Province"; order[18] = "Admin Postal Code";
    order[19] = "Admin Country"; order[20] = "Admin Phone"; order[21] = "Admin Phone Ext";
    order[22] = "Admin Fax"; order[23] = "Admin Fax Ext"; order[24] = "Admin Email";

    order[25] = "Tech Name"; order[26] = "Tech Organization"; order[27] = "Tech Street";
    order[28] = "Tech City"; order[29] = "Tech State/Province"; order[30] = "Tech Postal Code";
    order[31] = "Tech Country"; order[32] = "Tech Phone"; order[33] = "Tech Phone Ext";
    order[34] = "Tech Fax"; order[35] = "Tech Fax Ext"; order[36] = "Tech Email";
}

{
    # Clean up carriage returns (\r) and strip edge spaces
    gsub(/\r/, "");
    sub(/^ +/, "", $1); sub(/ +$/, "", $1);
    sub(/^ +/, "", $2); sub(/ +$/, "", $2);

    # If the field matches a map target, save its value
    if ($1 in map) {
        values[$1] = $2;
    }
}

END {
    # Loop through the fields in exact specified sequence
    for (i = 1; i <= 36; i++) {
        field = order[i];
        val = values[field];

        # Rule: Add space after Street fields
        if (field ~ /Street$/ && val != "") {
            val = val " ";
        }

        # Rule: Include colon in Ext fields even if empty: "Phone Ext:,"
        if (field ~ /Ext$/) {
            field = field ":";
        }

        # Format line output as "Field,Value"
        line = field "," val;

        # Rule: Ensure no extra newline at the absolute end of the stream
        if (i == 36) {
            printf "%s", line;
        } else {
            printf "%s\n", line;
        }
    }
}'
