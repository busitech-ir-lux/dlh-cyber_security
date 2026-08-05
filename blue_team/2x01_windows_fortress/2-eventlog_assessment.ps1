from pathlib import Path

path = Path("/mnt/data/2-eventlog_assessment.ps1")
text = path.read_text(encoding="utf-8")

text = text.replace(
'''        Description = "Process Creation"
        Subcategory = "Process Creation"
        RequiredSetting = "Success"''',
'''        Description = "Process Creation"
        AuditCategory = "Process Tracking"
        Subcategory = "Process Creation"
        RequiredSetting = "Success"'''
)

# Add AuditCategory to all other event objects where absent.
replacements = {
'''        Description = "Successful Logon"
        Subcategory = "Logon"''':
'''        Description = "Successful Logon"
        AuditCategory = "Logon"
        Subcategory = "Logon"''',

'''        Description = "Failed Logon"
        Subcategory = "Logon"''':
'''        Description = "Failed Logon"
        AuditCategory = "Logon"
        Subcategory = "Logon"''',

'''        Description = "Explicit Credentials"
        Subcategory = "Logon"''':
'''        Description = "Explicit Credentials"
        AuditCategory = "Logon"
        Subcategory = "Logon"''',

'''        Description = "Account Created"
        Subcategory = "User Account Management"''':
'''        Description = "Account Created"
        AuditCategory = "Account Management"
        Subcategory = "User Account Management"''',

'''        Description = "Account Deleted"
        Subcategory = "User Account Management"''':
'''        Description = "Account Deleted"
        AuditCategory = "Account Management"
        Subcategory = "User Account Management"''',

'''        Description = "Member Added to Group"
        Subcategory = "Security Group Management"''':
'''        Description = "Member Added to Group"
        AuditCategory = "Account Management"
        Subcategory = "Security Group Management"''',

'''        Description = "Special Logon"
        Subcategory = "Special Logon"''':
'''        Description = "Special Logon"
        AuditCategory = "Special Logon"
        Subcategory = "Special Logon"''',

'''        Description = "Audit Log Cleared"
        Subcategory = "Other System Events"''':
'''        Description = "Audit Log Cleared"
        AuditCategory = "System Integrity"
        Subcategory = "Other System Events"'''
}

for old, new in replacements.items():
    text = text.replace(old, new)

text = text.replace(
'''            AuditSubcategory = $item.Subcategory
            RequiredAudit    = $item.RequiredSetting''',
'''            AuditCategory    = $item.AuditCategory
            AuditSubcategory = $item.Subcategory
            RequiredAudit    = $item.RequiredSetting'''
)

text = text.replace(
'''        @{Name="Audit Subcategory"; Expression={$_.AuditSubcategory}},
        Status |''',
'''        @{Name="Audit Subcategory"; Expression={$_.AuditCategory}},
        Status |'''
)

path.write_text(text, encoding="utf-8", newline="\n")

print("Updated:", path)
print("Contains 'Process Tracking':", "Process Tracking" in text)
print("Contains 'Process Creation':", "Process Creation" in text)
print("Line count:", len(text.splitlines()))

