## Incident Classification Table

| Incident                                    | Primary CIA Pillar  | Why                                                                                                                                         | Secondary Pillar | Connection                                                                                                              |
| ------------------------------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------- |
| **A – Ransomware on billing server**        | **Availability**    | The billing server was unavailable for 4 days, so the finance team could not process insurance claims.                                      | **Integrity**    | The ransomware changed the server’s data by encrypting it, and the available backup was outdated.                       |
| **B – Patient portal access-control issue** | **Confidentiality** | Patients could view other patients’ lab results without authorization.                                                                      | None confirmed   | The incident describes unauthorized access, but it does not say that the results were changed or made unavailable.      |
| **C – Incorrect pharmacy dosages**          | **Integrity**       | A faulty database script changed medication dosage values without authorization or proper validation.                                       | **Availability** | The pharmacy system could not be safely trusted for about 6 hours, which affected its normal use.                       |
| **D – Public website defacement**           | **Integrity**       | The homepage was changed without authorization and replaced with a political message.                                                       | **Availability** | The normal website content was unavailable until the site was restored.                                                 |
| **E – EHR outage**                          | **Availability**    | The EHR system was unavailable for 9 hours, so physicians had to use paper records.                                                         | None confirmed   | The incident does not state that patient data was exposed or changed.                                                   |
| **F – Personal laptop on internal network** | **Confidentiality** | The unmanaged laptop had access to the same network segment as the HR file share, creating a risk of unauthorized access to sensitive data. | **Availability** | Torrent traffic could consume network resources and reduce network performance, although no actual outage was reported. |

### Simple summary

* **Confidentiality:** Incident B and Incident F
* **Integrity:** Incident C and Incident D
* **Availability:** Incident A and Incident E

Some incidents affect more than one CIA pillar.

