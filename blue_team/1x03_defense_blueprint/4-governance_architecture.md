# 4. Governance Architecture

## Part 1 — RACI Matrix

**R = Responsible**  
**A = Accountable**  
**C = Consulted**  
**I = Informed**

|Security Activity|CEO|Deputy CISO|IT Director|Dept Heads|Security Analyst|
|---|---|---|---|---|---|
|Security budget approval|A|R|C|C|I|
|Vulnerability remediation|I|C|A|C|R|
|Incident response execution|I|A|R|C|R|
|Security policy approval|A|R|C|C|C|
|Risk acceptance decisions|A|R|C|C|I|
|Security awareness training|I|A|C|R|R|
|Vendor risk assessment|I|A|C|C|R|
|Audit coordination|I|A|C|C|R|

The matrix gives each activity one clear accountable owner while allowing several people to support the work.

## Part 2 — Role Definitions

### Data Owner — Department Heads

Department heads are responsible for the business use of data in their departments. They decide who requires access and how sensitive the data is. For example, the Head of Cardiology owns the business decisions for cardiology data but must still follow MedDefense policies.

### Data Controller — MedDefense Health Systems

MedDefense is the Data Controller because it decides why and how patient and employee personal data is processed. The CEO has executive accountability for ensuring that the organization meets its legal responsibilities.

### Data Processor — External Service Providers

Cloud providers, billing companies and other vendors may process personal data for MedDefense. They must follow MedDefense’s instructions and the requirements written in their contracts.

### Data Custodian/Steward — IT Director and IT Team

Sarah Park and the IT team are the Data Custodians. They store, back up, protect and technically manage the data, but they do not decide who should have business access to it.

## Part 3 — The CISO Question

The vacant CISO position creates unclear authority, slow decisions and weak accountability. It also makes it harder to report security risk to the Board, coordinate departments and prove proper governance to regulators. MedDefense should use a **vCISO for the first six months** because the full security budget is limited to **$120,000**, and a full-time CISO could consume a large part of that amount. The vCISO should provide strategy, Board reporting and governance support, while James manages daily security operations and prepares to take greater responsibility later.
