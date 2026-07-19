# The Medical IoT

## BD Alaris Assessment

**Finding:** 010  
**Devices:** BD Alaris pumps, `10.10.3.40–46`  
**Reported CVE:** CVE-2020-25165

The BD bulletin describes a network-session weakness between older Alaris PC Units and the Alaris Systems Manager. An attacker on the wireless network could interrupt communications and cause loss of network functions, although the pump would continue operating with its current settings.

BD recommends upgrading affected Alaris PC Units to software version **12.1.1 or later**, where approved, and contacting BD to arrange the update.

The scan reports firmware **12.1.2**, which is newer than the fixed version. Therefore, CVE-2020-25165 may be a false positive or the scanner may have identified the wrong firmware. MedDefense has also not implemented the recommended network isolation because the pumps remain on the flat network and use default credentials.

---

## Philips IntelliVue Assessment

**Finding:** 016  
**Devices:** Philips IntelliVue monitors, `10.10.3.10–32`

The exposed interfaces may carry:

- patient identifiers
    
- vital signs
    
- ECG data
    
- oxygen saturation
    
- blood pressure
    
- alarms
    
- trends and waveforms
    
- HL7 messages sent to the EHR
    

Philips systems use HL7 to exchange clinical data with hospital systems.

An attacker with network access could view patient information, collect clinical data, interrupt communications, scan device interfaces or attempt to change settings if the interface allows it. The risk is increased because the monitors are accessible from the entire flat network without proper authentication.

Finding 024 is also related because DICOM patient identifiers and medical images travel without encryption between the MRI workstation and PACS server.

---

## Patient Safety Dimension

Medical-device vulnerabilities can affect both information security and patient care. A compromised workstation may expose data or interrupt office work. A compromised infusion pump could interrupt drug delivery, remove network-based safety functions or force staff to enter settings manually. The worst case is incorrect or delayed treatment that causes direct harm to a patient.

---

## Remediation Challenge

Medical devices are harder to patch because:

1. **Regulatory approval:** Updates may require vendor testing or regulatory authorization.
    
2. **Operational availability:** Devices may be in continuous clinical use and cannot be restarted easily.
    
3. **Vendor dependency:** Hospitals often cannot install normal operating-system patches without the manufacturer.
    
4. **Patient-safety testing:** Updates must be tested to ensure they do not change device behaviour.
    
5. **Long life cycles:** Medical devices may remain in service much longer than normal IT equipment.
    

MedDefense should verify the real Alaris firmware, replace default credentials, isolate all medical devices in dedicated VLANs and allow only required clinical traffic.
