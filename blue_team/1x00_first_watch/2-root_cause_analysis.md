# The Symptom Trap

## 1. What is the `kworker` process doing?

The process is not a real Linux `kworker`.

Real `kworker` processes:

- run as root;
    
- appear inside brackets, such as `[kworker]`;
    
- are part of the Linux kernel.
    

This process:

- runs as `www-data`;
    
- is stored in `/var/www/html/.cache/kworker`;
    
- uses about 94% of the CPU;
    
- connects to Monero mining pools.
    

The connection:

```text
stratum+tcp://pool.monero.org:4443
```

shows that the process is using the **Stratum mining protocol** to connect to a Monero cryptocurrency mining pool.

Its purpose is to use MedDefense’s server CPU to mine cryptocurrency for an attacker.

This is a malicious crypto-miner disguised as a normal system process.

---

## 2. Real Security Compromise

The visible symptom is poor performance, which affects **Availability**.

However, two other CIA pillars were already compromised first.

|CIA Pillar|Explanation|
|---|---|
|**Integrity**|An attacker placed and executed an unauthorized program on the server. The server’s files, processes and normal operation were changed.|
|**Confidentiality**|The attacker gained unauthorized access to the server. This means they may have been able to view billing data, credentials, configuration files or other sensitive information.|
|**Availability**|The miner uses almost all CPU resources, making the billing application slow and difficult to use.|

The main problem is therefore not only performance. The server has been compromised.

---

## 3. Why the Hardware Upgrade Does Not Fix the Problem

Upgrading the server to more CPU and memory will not remove the security problem.

The miner would still be present unless it is found and removed.

A stronger server may even allow the attacker to mine more cryptocurrency.

Restarting the server also does not solve the root cause because:

- the malicious file remains on the server;
    
- it may start again after reboot;
    
- the vulnerability used by the attacker may still be open.
    

The real solution should include:

- isolating the server;
    
- investigating how the attacker entered;
    
- removing the malware;
    
- checking for other malicious files or accounts;
    
- patching Apache and the operating system;
    
- changing exposed credentials;
    
- reviewing logs;
    
- rebuilding the server securely if necessary.
    

---

## 4. Connection to the January Ransomware Incident

The same server was affected by ransomware in January and now contains a crypto-miner.

This suggests that the server may still have the same security weakness.

The server was rebuilt, but the original entry point may not have been fixed.

Marcus suspected that the attacker entered through an unpatched Apache vulnerability.

The most important question is:

> How did attackers gain access to billing-srv-01, and was the original vulnerability actually removed during the rebuild?

Other useful questions are:

- Was Apache patched after the ransomware incident?
    
- Was the server fully investigated before being returned to service?
    
- Were credentials changed?
    
- Were other systems checked for compromise?
    
- Is the malware persistent?
    
- Did both attacks use the same vulnerability?
    

## Conclusion

The CPU problem is only a symptom.

The real issue is an active server compromise involving unauthorized access and unauthorized modification. A hardware upgrade would not fix it because the attacker’s access method and malware would still remain.
