# The What-If — Threat Landscape Change Assessment

## Scenario A: University Clinical Trial Partnership

MedDefense launches a cardiac clinical trial involving 500 patients, proprietary treatment protocols and three international research partners. Trial data is stored on a new server at MedDefense Central.

### New Threat Actors

**Nation-state APT actors become a significant threat.** MedDefense was previously a low-priority nation-state target because it had no research program. The clinical trial creates valuable intellectual property, patient data and international research connections that may attract state-sponsored espionage.

Other possible actors include:

* Organized criminals seeking valuable medical and identity data
* Corporate espionage actors targeting the proprietary treatment
* Malicious insiders with access to research results
* Hacktivists if the experimental treatment becomes publicly controversial

The intelligence dossier specifically states that nation-state actors target clinical trials, pharmaceutical research and healthcare organizations connected to research partners.

### Changed Vectors

**More relevant vectors:**

* Spearphishing against cardiologists, researchers and university partners
* Compromised partner or university accounts
* Supply-chain access through research software and institutions
* Cloud collaboration platforms and shared file repositories
* Direct exploitation of the new research server
* Insider copying of protocols or trial data
* Credential theft and long-term hidden access

**Less relevant vectors:**

No existing vector becomes significantly less relevant. Ransomware, phishing and opportunistic exploitation remain serious threats.

### Shifted Priorities

The current Top 5 would change as follows:

1. **Ransomware remains #1** because the new research data creates additional extortion value.
2. **Nation-state APT moves from Low to High and enters at approximately #2.**
3. **Supply-chain compromise moves up** because four research organizations now exchange data and credentials.
4. **Negligent insider remains High** because researchers may copy data to unmanaged tools for convenience.
5. **Opportunistic exploitation remains High** if the new server is exposed or poorly patched.

Malicious insider risk also increases, but may remain below nation-state and supply-chain risk.

### New Gaps

The partnership would create several new gaps:

* No research-data classification and handling standard
* No dedicated segmented research network
* No documented security requirements for university partners
* No research-specific access-control model
* No DLP for proprietary research and trial data
* No centralized monitoring for the new server
* No process for removing partner access when the trial ends
* No formal data-sharing and cross-border transfer assessment
* No research incident-response procedure

The existing flat network under **M-01** would be especially dangerous because a compromised international partner account or research server could provide access to the wider MedDefense environment.

### Net Assessment

**Overall exposure increases significantly because MedDefense becomes a healthcare research target while retaining its existing ransomware, monitoring and segmentation weaknesses.**

---

## Scenario B: EHR Migration to MedTech Cloud SaaS

MedDefense decommissions `ehr-srv-01` and `ehr-db-01`. All patient-record access is provided through a cloud-hosted MedTech Solutions SaaS platform.

### New Threat Actors

This change does not create a completely new actor category, but it changes which actors have the strongest opportunity.

The main actors become:

* Organized criminals targeting cloud credentials and patient data
* External attackers targeting MedTech as a supply-chain provider
* Malicious insiders at MedDefense or MedTech
* Opportunistic credential-stuffing attackers
* Advanced actors targeting MedTech because one compromise could expose several healthcare customers

MedDefense becomes more dependent on MedTech’s security operations rather than its own server protections.

### Changed Vectors

**More relevant vectors:**

* Phishing for MedTech SaaS credentials
* MFA fatigue and session-token theft
* Credential stuffing against cloud accounts
* Compromise of MedTech administrators or infrastructure
* SaaS configuration errors
* Insecure APIs and third-party integrations
* Large cloud exports by insiders
* Vendor outages and denial-of-service attacks
* Compromised browser sessions on clinical workstations

**Less relevant vectors:**

* Direct exploitation of `ehr-srv-01`
* Direct internal access to PostgreSQL port 5432
* Lateral movement from the flat network directly into the EHR database
* Encryption of the EHR database through the local backup NAS
* Physical compromise of the former EHR servers

However, the flat network remains a risk to PACS, Active Directory, billing, backups and medical devices.

### Shifted Priorities

The Top 5 would change as follows:

1. **Ransomware remains a Critical threat**, but it is less likely to encrypt the primary EHR database directly. Attackers may instead compromise identities, workstations or connected systems and steal cloud-hosted data.
2. **Supply-chain compromise rises from #4 to approximately #2** because MedTech becomes the sole host and security boundary for the EHR.
3. **Negligent insider remains High** because cloud access makes large exports possible from any authorized location.
4. **Malicious insider risk remains High or increases**, particularly for SaaS administrators and users with export rights.
5. **Opportunistic exploitation moves down slightly** for the EHR because the local servers and PostgreSQL service are removed, although other vulnerable MedDefense systems remain.

### New Gaps

New cloud-related gaps would include:

* No documented SaaS security assessment
* No contractual requirement for rapid breach notification
* No independent backup or export of EHR data
* Unclear data ownership and data-residency requirements
* No cloud disaster-recovery or vendor-exit plan
* No centralized collection of MedTech audit logs
* No conditional access or device-compliance requirement
* Excessive SaaS administrator permissions
* No control over MedTech subcontractors
* Dependence on the vendor’s availability and recovery process

**M-05 becomes even more important** because every EHR login is now remote and password compromise can provide direct cloud access. **M-04 also remains important** because MedDefense needs timely access to cloud audit events instead of waiting for vendor exports. The current assessment confirms that MedDefense has no MFA and no centralized monitoring.

### Net Assessment

**Overall exposure shifts rather than disappears: the local EHR attack surface decreases, but identity, cloud concentration and MedTech supply-chain risk become much more important.**

---

## Scenario C: Public Disclosure of the January Attack

A national news story reveals that MedDefense experienced a ransomware incident on `billing-srv-01`. Former patients publicly question whether their information is safe.

### New Threat Actors

**Hacktivists become more relevant** because MedDefense now has a visible public controversy. Groups may claim that the hospital concealed the incident or failed to protect patient data.

Additional interested actors may include:

* Opportunistic attackers who now view MedDefense as a confirmed weak target
* Ransomware groups expecting that unresolved weaknesses remain
* Scammers impersonating MedDefense and contacting concerned patients
* Data-extortion groups making false or real claims about stolen records
* Malicious insiders who may leak additional information
* Credential-phishing groups exploiting public fear

The dossier previously rated hacktivism Low because MedDefense had no public controversy. It also notes that hacktivists commonly use DDoS, defacement and data leaks for publicity.

### Changed Vectors

**More relevant vectors:**

* DDoS attacks against the public website and patient portal
* Website defacement
* Brand impersonation and fake patient-notification emails
* Typosquatting domains
* Smishing directed at former patients
* Credential stuffing against the patient portal
* Phishing emails using details from the published incident
* Social engineering of staff, journalists and patients
* Data-leak claims intended to create fear or extort payment

**Less relevant vectors:**

No major technical vector disappears. However, the immediate focus shifts toward public systems, communications and identity-based attacks.

### Shifted Priorities

The Top 5 would change as follows:

1. **Ransomware remains #1 and its likelihood may increase** because public reporting confirms that MedDefense has already been successfully attacked.
2. **Opportunistic attackers move from #3 to approximately #2** because media coverage identifies MedDefense as a potentially weak organization.
3. **Negligent insiders remain High**, especially during the stressful response period when staff may make communication mistakes.
4. **Hacktivists rise from Low and enter the Top 5**, likely at #4 or #5.
5. **Supply-chain or malicious-insider risk moves down in relative ranking**, although its absolute risk does not decrease.

### New Gaps

The public disclosure creates or exposes several gaps:

* No tested crisis-communication plan
* No coordinated process for patient questions and media requests
* No external attack-surface monitoring
* No typosquatting or fraudulent-domain monitoring
* No DDoS protection plan
* No brand-impersonation response procedure
* No dark-web or threat-intelligence monitoring
* No prepared patient breach-notification process
* No documented coordination between Security, Legal and Communications
* No evidence-based public explanation of the January incident

The story may also increase pressure on **M-04**, because MedDefense currently cannot confidently determine whether additional attackers are scanning, accessing or exfiltrating data. The original assessment states that the crypto-miner operated for at least two weeks before discovery and that security logs are not reviewed centrally.

### Net Assessment

**Overall exposure increases and becomes more visible because MedDefense is now attractive to hacktivists, scammers and opportunistic attackers while public confidence is already weakened.**

