## A1. Kubelet allows anonymous access

- **Negation (A1‑N):**  
  Disable anonymous access (`--anonymous‑auth=false`), enforce authentication, RBAC, and certificate rotation.

- **Bypass (A1‑B):**  
  An attacker can compromise a pod and exploit the metadata server to fetch TLS bootstrap credentials (via CSR) to impersonate the kubelet.

- **Mitigations (A1‑M):**  
  - Use **Workload Identity**, disable node service‐account metadata access  
  - Block metadata server egress via iptables or NetworkPolicy  
  - Audit CSR submissions and alert unusual approvals  
  - Enforce GKE **private nodes** and **Shielded Nodes** :contentReference[oaicite:0]{index=0}

---

## A2. TeamTNT scans kubelet ports (10250/10255)

- **Negation (A2‑N):**  
  Close kubelet ports; use private clusters, authorized networks, and firewall rules.

- **Bypass (A2‑B):**  
  Misconfigured LoadBalancer pods may still allow internal access from external traffic.

- **Mitigations (A2‑M):**  
  - Also block egress pod traffic to kubelet via Calico NetworkPolicy :contentReference[oaicite:1]{index=1}  
  - Use internal-only load balancers or restrict `loadBalancerSourceRanges` :contentReference[oaicite:2]{index=2}  
  - Disable read-only port 10255

---

## A3. Successful scan leads to pod RCE

- **Negation (A3‑N):**  
  Enforce kubelet auth, RBAC on exec/run endpoints.

- **Bypass (A3‑B):**  
  Attackers escape from misconfigured pods (privileged, hostNetwork) to gain exec.

- **Mitigations (A3‑M):**  
  - Enforce **Pod Security Admission**: no privileged pods or hostNetwork  
  - Use **GKE Sandbox** or gVisor  
  - Continuous vulnerability scanning/patching of workloads

---

## B1. TeamTNT focuses on deploying cryptominers

- **Negation (B1‑N):**  
  Use image signing and **Binary Authorization** to restrict cryptomining binaries.

- **Bypass (B1‑B):**  
  Attackers drop malicious scripts (wget/curl) at runtime; use LD_PRELOAD to inject miner.

- **Mitigations (B1‑M):**  
  - Enforce **Binary Authorization** :contentReference[oaicite:3]{index=3}  
  - Deploy Falco/Prisma runtime detection for `LD_PRELOAD` and script drop  
  - File integrity monitoring; CPU anomaly alerts

---

## B2. Miner (xmrig) dropped via bash scripts

- **Negation (B2‑N):**  
  Use distroless/minimal images; disable exec API; read‐only containers.

- **Bypass (B2‑B):**  
  Attacker builds custom precompiled pod image including miner binary.

- **Mitigations (B2‑M):**  
  - Remove shell tools; use distroless  
  - Enforce read-only filesystem; disable `exec`/`attach` RBAC  
  - Block known miner ports via pod-level NetworkPolicy :contentReference[oaicite:4]{index=4}

---

## B3. LD_PRELOAD used for stealth

- **Negation (B3‑N):**  
  Detect/prevent LD_PRELOAD in containers and on host.

- **Bypass (B3‑B):**  
  Attacker installs kernel rootkits at host level.

- **Mitigations (B3‑M):**  
  - Use **Shielded GKE nodes** with Secure Boot :contentReference[oaicite:5]{index=5}  
  - Enable boot and integrity monitoring  
  - Periodically audit `/etc/ld.so.preload` and host binaries

---

## C1. Scanning for cloud credentials in pods

- **Negation (C1‑N):**  
  Use Workload Identity; disable default service account keys; enforce minimal IAM.

- **Bypass (C1‑B):**  
  Pod compromises node metadata or escalates to host to fetch credentials.

- **Mitigations (C1‑M):**  
  - Block metadata IP (169.254.169.254) access via NetworkPolicy/firewall  
  - Audit access to metadata server  
  - Remove node service account credentials; use Workload Identity only :contentReference[oaicite:6]{index=6}

---

## C2. Scripts enumerate metadata & files

- **Negation (C2‑N):**  
  Protect file paths; block metadata; revoke pod identity tokens.

- **Bypass (C2‑B):**  
  Use container escape to run script at host level.

- **Mitigations (C2‑M):**  
  - No privileged pods, hostProcess, hostPath  
  - Keep OS/kernel patched  
  - Monitor for breakout attempts (e.g., Falco hostescape rules)

---

## C3. Credentials exfiltrated via C2 to external C2

- **Negation (C3‑N):**  
  Block egress traffic; blacklist `.teamtnt` domains.

- **Bypass (C3‑B):**  
  Use DNS tunneling or HTTPS to permitted domains.

- **Mitigations (C3‑M):**  
  - Implement egress proxies, SSL inspection  
  - Enforce DNS anomaly detection  
  - Use VPC Service Controls, Data Loss Prevention, alert on unusual traffic

---

## D1. TeamTNT targets Azure/GCP credentials

*(Covered by C1–C3 mitigations and general IAM lockdown)*

---

## ✅ Final Security Posture

1. **Kubelet & API Hardening**  
   - `--anonymous-auth=false`, private control plane, authorized networks, RBAC, CSR auditing.

2. **Networking & Egress Control**  
   - Private clusters, Calico NetworkPolicy for metadata, kubelet and miner port egress.  
   - Internal LB only, egress proxies and DNS inspection.

3. **Image & Runtime Security**  
   - Binary Authorization, distroless/read-only images, Falco runtime alerts, file integrity checks.

4. **IAM & Metadata Protection**  
   - Workload Identity, disable node SA keys, block metadata access, IAM least privilege.

5. **Node Integrity & Isolation**  
   - Shielded Nodes with Secure Boot, host escape prevention, continuous patching.

6. **Monitoring & Detection**  
   - Audit logs (CSR, exec, metadata access), behavioral analytics (CPU, egress, DNS), anomaly alerts.
