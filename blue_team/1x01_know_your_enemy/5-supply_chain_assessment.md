# The Supply Chain Question — MedDefense Vendor Risk Assessment

## Vendor 1: MedTech Solutions

**Service:**
EHR maintenance, software updates and critical support under a four-hour SLA.

**Access Type:**
Network and application access through direct maintenance access to the EHR server.

**Access Scope:**
Confirmed access includes `ehr-srv-01`, the EHR application and vendor-managed EHR audit logs. Direct database access is not documented. However, `ehr-db-01` accepts PostgreSQL connections from the entire internal network, so a compromised maintenance session could potentially reach the EHR database unless a separate access rule exists.

**Compromise Scenario:**
An attacker compromises a MedTech technician account or support system and uses the trusted maintenance connection to enter `ehr-srv-01`. From there, the attacker accesses patient data, modifies the EHR application or attempts to connect to `ehr-db-01`. Because MedDefense has a flat network, the attacker could also scan for domain controllers, backups and other internal servers.

**Existing Controls:**
The 1x00 Control Matrix shows:

* SSH password authentication is disabled on `ehr-srv-01`.
* Vendor users are covered by the MedDefense password policy.
* EHR audit logs exist.
* Firewall and authentication logs are available locally.

These controls are weakened because MedDefense has no MFA, no centralized monitoring and no internal segmentation. EHR audit exports can also take 48 hours to obtain from the vendor.

**Risk Assessment:** **Critical**
MedTech has trusted access to MedDefense’s most important clinical application. A compromise could expose patient data, interrupt treatment and provide a path into the wider network.

---

## Vendor 2: Microsoft

**Service:**
Microsoft 365 E3, including organization-wide email, SharePoint and OneDrive. Microsoft may also support identity through Entra ID if it is enabled.

**Access Type:**
Cloud application, data and potentially identity access.

**Access Scope:**
Microsoft hosts employee email, shared documents and OneDrive files. If Entra ID is connected to MedDefense authentication, the service may also manage user identities, login sessions and administrative roles.

**Compromise Scenario:**
An attacker who gains control of the Microsoft tenant or a privileged cloud administrator account could read email, download SharePoint and OneDrive files, create phishing messages from trusted accounts and change cloud permissions. If Entra ID is used for identity, the attacker may also reset accounts or create new privileged identities.

**Existing Controls:**
The 1x00 Control Matrix includes the MedDefense password policy and Microsoft’s built-in platform protections. Entra ID MFA is available under the existing licence, but MedDefense has not enabled MFA. O365 email, SharePoint and OneDrive data are also excluded from MedDefense’s backup system because staff assume Microsoft handles the backups.

**Risk Assessment:** **High**
The service contains organization-wide communication and business data. The impact becomes **Critical** if Entra ID is MedDefense’s main identity provider because a compromise could affect both data and authentication.

---

## Vendor 3: Sophos

**Service:**
Endpoint protection for managed Windows workstations.

**Access Type:**
Endpoint and application management through the Sophos agent and Sophos Central console.

**Access Scope:**
Sophos software is installed on approximately 372 Windows workstations and can receive updates, security policies and configuration changes. Windows servers, Linux servers, mobile devices and physician iPads are not covered.

**Compromise Scenario:**
If Sophos’s update infrastructure or MedDefense’s Sophos Central account is compromised, an attacker could push a malicious update or configuration to hundreds of workstations. The attacker could then collect credentials and move from an infected workstation to servers because the network is flat.

**Existing Controls:**
The Sophos agent provides malware detection and quarantine. Its scope limits the direct blast radius because it is not installed on MedDefense servers. However, only 341 devices have current signatures, 31 have outdated signatures and 15 are not reporting.

**Risk Assessment:** **Critical**
Sophos has trusted, privileged software on hundreds of devices. A malicious update could compromise a large part of the organization at the same time and provide multiple paths into the server network.

---

## Vendor 4: Siemens

**Service:**
MRI scanner maintenance, workstation servicing and firmware updates.

**Access Type:**
Physical, application and local network access during maintenance.

**Access Scope:**
Siemens technicians can work on the MRI scanner and its control workstation, `WS-RAD-01`. The workstation runs Windows XP and is connected to the same network as general workstations, servers and other medical devices. Remote Siemens access is not documented.

**Compromise Scenario:**
A compromised Siemens service laptop, update package or technician account introduces malware to the MRI workstation during maintenance. The Windows XP system is easy to compromise, and the attacker then pivots through the flat network toward `pacs-srv-01`, Active Directory or other clinical systems.

**Existing Controls:**
Physical access and on-site PACS access provide some restriction. The 1x00 controls also include endpoint protection on supported Windows workstations, but an old Windows XP medical workstation may not be fully supported. There is no dedicated medical-device VLAN, and the server-room and technical-area physical controls are weak.

**Risk Assessment:** **High**
The vendor’s direct access is limited to a specific clinical system, but the obsolete workstation and lack of network segmentation could turn a local compromise into a wider incident. MRI downtime would also interrupt patient services.

---

## Vendor 5: Greenfield Building Management

**Service:**
HQ network infrastructure, internet connectivity, building security and shared building services.

**Access Type:**
Network and physical infrastructure access.

**Access Scope:**
Greenfield manages the building network that carries MedDefense’s HQ VLAN. Approximately 120 workstations and 25–30 laptops use this environment. HQ connects to Central Hospital through a site-to-site VPN.

**Compromise Scenario:**
An attacker compromises Greenfield’s network administration system or gains control of a building switch. The attacker enters or monitors the MedDefense VLAN, compromises an HQ workstation and then moves through the site-to-site VPN to Central. The FortiGate currently permits all services from the HQ VPN to the internal server subnet, increasing the possible reach.

**Existing Controls:**
MedDefense has its own VLAN and uses a site-to-site VPN to Central. The FortiGate provides a final network boundary and logs VPN traffic. However, the VPN rule allows all services, MedDefense cannot inspect Greenfield’s security controls and the organization has no centralized log monitoring.

**Risk Assessment:** **High**
Greenfield does not directly manage patient applications, but its infrastructure is a trusted route to HQ and Central. A compromise could affect executive, finance, HR, legal and IT users before moving toward hospital servers.

## Supply Chain Risk Summary

**MedTech Solutions presents the most direct risk to MedDefense** because it has trusted maintenance access to the EHR application, which supports clinical care and processes regulated patient data. A compromised MedTech connection could reach `ehr-srv-01` immediately and potentially reach `ehr-db-01` and other internal systems because the database is broadly accessible and the network is not segmented. Sophos has the broadest endpoint blast radius, but MedTech provides the shortest path to MedDefense’s most critical clinical asset.

The first organization-wide control should be a **formal third-party access management standard**. Every vendor should receive a unique account protected by MFA, least-privilege permissions, time-limited access and centralized session logging. Vendor access should be disabled when it is not actively required, and contracts should require rapid breach notification. This would reduce exposure from compromised vendor credentials and give MedDefense evidence of exactly what each vendor accessed.

