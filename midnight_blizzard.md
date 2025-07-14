
## 📌 P1 Sub‑premises: Scanning & targeting

### SP1.1: They scan via Shodan, etc.
**Mitigations:**
- **Network segmentation & firewalls**: Restrict internet access to internal services—only allow necessary traffic to internet-facing assets.
- **Limit exposure of management interfaces**: Move admin panels to internal networks or protect with VPN.
- **Vulnerability scanning/hardening**: Continuously audit exposed ports & services.

### SP1.2: Bruteforce public apps
**Mitigations:**
- **Multi-factor authentication (MFA)**: Add phishing-resistant MFA on all public services.
- **Account lockouts/rate limits**: Prevent automated credential guessing.
- **WAF protection & strong password policies**: Shield public web applications and enforce password complexity.

### SP1.3: Probe CVEs
**Mitigations:**
- **Patch management**: Prioritize fixing known exploitable vulnerabilities.
- **WAF signatures**: Block known CVE exploit payloads.
- **Host-based defense**: Use HIPS/EDR to detect malicious behavior post‑exploit.

---

## 📌 P2 Sub‑premises: Initial access via flaws

### SP2.1: Exploit CVEs (e.g., Dahua)
**Mitigations:**
- **Timely patching**: Apply fixes for vulnerabilities like CVE‑2021‑33044.
- **Vulnerability management**: Regular scans and rapid patch cycles.
- **Virtual patching**: Use WAF or runtime shielding if patching is delayed.

### SP2.2: Use public red‑teaming tools
**Mitigations:**
- **Logging & alerting**: Monitor for scanning/tool signatures (Nmap, masscan, etc.).
- **Threat hunting**: Proactively check logs for reconnaissance activity.
- **Network monitoring**: Detect unusual external scanning.

### SP2.3: Default credentials on IoT
**Mitigations:**
- **Change defaults** upon installation.
- **Enforce strong authentication & MFA** on IoT devices.
- **Asset inventory**: Identify and secure or replace insecure devices.

---

## 📌 P3 Sub‑premises: Deploy destructive malware

### SP3.1: Track record (NotPetya etc.)
**Mitigations:**
- **Backups**: Maintain offline, immutable backups and test restores regularly.
- **Segmentation**: Limit malware spread via properly segmented networks.
- **EDR & anomaly detection**: Detect destructive behavior early.

### SP3.2: WhisperGate malware
**Mitigations:**
- **Indicator sharing & detection**: Consume IOCs from threat intel feeds.
- **Endpoint protection**: Deploy anti-wiper and behavior-based blocking tools.
- **Disaster recovery plans**: Maintain comprehensive incident response readiness.

### SP3.3: Espionage‑sabotage motive
**Mitigations:**
- **Risk‑based controls**: Protect critical infrastructure with focused safeguards.
- **Industrial network defenses**: Apply ICS-specific security (segmentation, monitoring).
- **Active cyber posture**: Regular tabletop exercises and incident readiness drills.

---

## 📌 P4 Sub‑premises: Data exfiltration

### SP4.1: IT/OT exfil capability
**Mitigations:**
- **DLP systems**: Monitor abnormal data flows out of network.
- **Network segmentation**: Separate IT from OT, restrict exfiltration pathways.
- **Egress filtering**: Block or log large or anomalous external uploads.

### SP4.2: Dump configs & credentials
**Mitigations:**
- **Credential vaulting**: Use secure stores; avoid plaintext credentials.
- **Least privilege**: Limit account permissions; avoid root/admin by default.
- **Monitor credential access/dumps**: Employ EDR/SIEM to alert on such activity.

### SP4.3: Snake‑like exfiltration
**Mitigations:**
- **Threat intel & IOC matching**: Apply known indicators for Snake/FSB malware.
- **Data flow baselines**: Detect anomalies between OT, IT, and internet.
- **Active auditing**: Monitor critical file accesses and transfers frequently.

---

## 📌 P5 Sub‑premises: Persistence & multi‑stage

### SP5.1: Long‑term access
**Mitigations:**
- **Rotation policies**: Regularly change credentials; disable stale accounts.
- **Access logging**: Alert on unusual or infrequently used credentials.
- **MFA enforcement**: Reduce risk from compromised credentials.

### SP5.2: LOTL techniques
**Mitigations:**
- **Application whitelisting**: Restrict execution to approved binaries/scripts.
- **Monitor native tool usage**: Detect certutil, PowerShell, and similar usage patterns.
- **Endpoint detection tuned to LOTL**: Observe living-off-the-land behaviors.

### SP5.3: Lateral movement & credential dumping
**Mitigations:**
- **Micro-segmentation**: Limit internal movement across network segments.
- **Credential isolation**: Separate privileged accounts from regular use.
- **Monitor lateral traffic**: Track abnormal SMB, RDP, and domain access.

### SP5.4: Multi‑stage chain
**Mitigations:**
- **Zero-trust segmentation**: Require authentication at each access hop.
- **Attack path analysis**: Identify and break typical compromise chains.
- **Red team validation**: Test internal defenses through simulated adversary activity.
