# MedDefense Structured Environment Summary

## 1. Organization Overview

MedDefense Health Systems has three locations:

### Central Hospital

- Downtown hospital with 350 beds.
    
- Around 1,400 staff.
    
- Main departments include Emergency, Surgery, Radiology, Pharmacy and Laboratory.
    
- Most servers and medical devices are located here.
    

### Westside Clinic

- Small outpatient clinic.
    
- Around 180 staff.
    
- Provides primary care, imaging, blood tests and minor procedures.
    
- Uses some services from Central Hospital.
    
- Has a small local server closet.
    

### Corporate HQ

- Administrative office with around 220 staff.
    
- Includes Finance, HR, Legal, Marketing, management and IT.
    
- Has no local servers.
    
- Connects to Central Hospital through a VPN.
    

### Security and IT Structure

- The CISO position is empty.
    
- James Chen is the acting security leader.
    
- Sarah Park manages the IT department.
    
- James controls security policy but does not control IT operations.
    
- This sometimes causes problems between the security and IT teams.
    

---

## 2. IT Infrastructure Identified

### Central Hospital

Main servers:

- `ehr-srv-01` – runs the Electronic Health Record application.
    
- `ehr-db-01` – stores the EHR database.
    
- `pacs-srv-01` – stores medical images.
    
- `billing-srv-01` – processes billing and insurance claims.
    
- `ad-dc-01` and `ad-dc-02` – manage users and logins.
    
- `file-srv-01` – stores shared department files.
    
- `print-srv-01` – manages printing.
    
- `backup-srv-01` – performs backups.
    
- `web-srv-01` – hosts the public website and patient portal.
    

Network equipment:

- FortiGate 100F firewall.
    
- Cisco core and access switches.
    
- 12 UniFi wireless access points.
    
- Local backup NAS.
    

Endpoints:

- Around 320 Windows workstations.
    
- Around 60 thin clients.
    
- Around 25 iPads.
    

Medical devices:

- Around 80 patient monitors.
    
- Around 120 infusion pumps.
    
- One MRI scanner running Windows XP.
    
- One CT scanner.
    
- IP-based nurse call system.
    
- Badge access system.
    

The Central network is mostly flat. Servers, computers and medical devices are connected to the same `10.10.0.0/16` network.

### Westside Clinic

- `ws-srv-01` – file storage and scheduling.
    
- Around 45 Windows workstations.
    
- One unmanaged switch.
    
- One Netgear consumer router.
    
- A VPN connection to Central Hospital.
    
- There may be another server, but this has not been confirmed.
    

### Corporate HQ

- Around 120 workstations.
    
- Around 30 laptops.
    
- Uses Microsoft O365.
    
- Uses a building-managed network.
    
- Connects to Central Hospital through a site-to-site VPN.
    

---

## 3. Data and Services

MedDefense handles:

- Patient health records.
    
- Medical images.
    
- Laboratory results.
    
- Patient-monitoring information.
    
- Medication and infusion information.
    
- Billing and insurance claims.
    
- Employee and HR information.
    
- Financial and legal information.
    
- User accounts and passwords.
    
- Internal department files.
    

Important IT services include:

- Electronic Health Record system.
    
- Medical imaging and PACS.
    
- Billing and insurance claims.
    
- Patient scheduling.
    
- Patient monitoring.
    
- Medication and infusion systems.
    
- Email and Microsoft O365.
    
- File sharing.
    
- Printing.
    
- Backups.
    
- Patient portal.
    
- Nurse call system.
    
- User login and access management.
    

Doctors, nurses, administrative staff, IT staff and patients depend on these services.

---

## 4. Known Unknowns

The following information is missing or unclear:

- The asset list is incomplete.
    
- The real number of computers and devices is unknown.
    
- There may be another server at Westside.
    
- The Central network diagram is incomplete.
    
- The model of the Central core switch is unknown.
    
- Westside Wi-Fi details are unknown.
    
- Guest Wi-Fi isolation has not been confirmed.
    
- HQ VPN access rules have not been checked.
    
- The CT scanner operating system is unknown.
    
- It is unclear whether the iPads are managed.
    
- Sophos may not be updated on every computer.
    
- Other cloud services may be used besides O365.
    
- There is no complete list of medical devices.
    
- Backup restore testing is not mentioned.
    
- There is no offsite backup.
    
- There is no formal incident-response plan.
    
- There is no business-continuity or disaster-recovery plan.
    
- HIPAA compliance has not been formally checked.
    
- The site staff numbers total about 1,800, but the organization says it has about 2,000 employees.
    
- The IT staff count is also unclear.

