# Microsoft Azure

## A1. Kubelet allows anonymous access

- **Negation (A1‑N):**  
  Disable anonymous kubelet access and enforce authenticated, authorized requests (TLS, RBAC).

- **Bypass (A1‑B):**  
  A compromised pod uses Azure Instance Metadata Service (IMDS) v1 to request a kubelet client cert via CSR.

- **Mitigations (A1‑M):**  
  - Enforce **IMDSv2 only**, disable IMDSv1 hops  
  - Use **Azure AD-integrated AKS authentication**, RBAC policies :contentReference[oaicite:0]{index=0}  
  - Enable **Kubernetes audit logging** for CSR requests  
  - Deploy **private AKS clusters** with no public API endpoint :contentReference[oaicite:1]{index=1}

---

## A2. TeamTNT scans kubelet ports (10250/10255)

- **Negation (A2‑N):**  
  Remove internet exposure of kubelet ports via private clusters, NSGs, and control-plane firewalls.

- **Bypass (A2‑B):**  
  Misconfigured internal services (LoadBalancers, Azure API) allow pod-to-node access.

- **Mitigations (A2‑M):**  
  - Configure Azure CNI with **Calico or Azure NPM** to enforce egress policies :contentReference[oaicite:2]{index=2}  
  - Enable **Azure Policy/NFGs** to restrict pod egress on kubelet ports :contentReference[oaicite:3]{index=3}  
  - Use internal-only load balancers with `loadBalancerSourceRanges` :contentReference[oaicite:4]{index=4}

---

## A3. Pod RCE via kubelet exec/attach

- **Negation (A3‑N):**  
  Enforce tight RBAC on exec/attach, disable anonymous kubelet access.

- **Bypass (A3‑B):**  
  Attackers exploit privileged pods or hostProcess capabilities to break out.

- **Mitigations (A3‑M):**  
  - Implement **Pod Security Standards**: no privileged, hostNetwork, or hostPath :contentReference[oaicite:5]{index=5}  
  - Use **Azure Policy** to block disallowed pod features :contentReference[oaicite:6]{index=6}  
  - Optionally deploy **gVisor** or Azure Fargate for stronger pod isolation

---

## B1. TeamTNT deploys cryptominers

- **Negation (B1‑N):**  
  Use Azure Container Registry (ACR) image signing and enforce Binary Authorization.

- **Bypass (B1‑B):**  
  Attackers download and deploy cryptominer binaries via scripts at runtime.

- **Mitigations (B1‑M):**  
  - Apply **ACR trust policies** to allow only signed images  
  - Enforce **Pod Security Standards** to prevent runtime downloading  
  - Deploy runtime detection tools (e.g., Defender for Containers, Sysdig) :contentReference[oaicite:7]{index=7}

---

## B2. Miner dropped via bash scripts

- **Negation (B2‑N):**  
  Deploy **distroless/read-only container images**, disable exec/attach APIs.

- **Bypass (B2‑B):**  
  Attackers build malicious images with miners baked in.

- **Mitigations (B2‑M):**  
  - Enforce immutable image tags and CI/CD pipeline approval checks  
  - Block traffic to mining ports (e.g., 3333) via NetworkPolicy :contentReference[oaicite:8]{index=8}  
  - Use **Azure Policy** to prevent unapproved images

---

## B3. Stealth via LD_PRELOAD/libhiding

- **Negation (B3‑N):**  
  Monitor for and block LD_PRELOAD usage within containers and nodes.

- **Bypass (B3‑B):**  
  Kernel-level rootkits on Azure VM nodes hide malicious activity.

- **Mitigations (B3‑M):**  
  - Use **hardened AKS node OS** (Azure Linux hardened, Bottlerocket) :contentReference[oaicite:9]{index=9}  
  - Regularly apply node image updates and CVE patches :contentReference[oaicite:10]{index=10}  
  - Enable **Azure Defender for Hosts** and monitoring for kernel anomalies

---

## C1. Scanning for Azure credentials in pods

- **Negation (C1‑N):**  
  Use **Managed Identity for Pods** and disable legacy service-account tokens.

- **Bypass (C1‑B):**  
  Pod accesses IMDS to retrieve node or other managed identity tokens.

- **Mitigations (C1‑M):**  
  - Block `169.254.169.254` with NetworkPolicy or Azure Firewall :contentReference[oaicite:11]{index=11}  
  - Enforce **least-privilege** on identities and roles :contentReference[oaicite:12]{index=12}  
  - Audit token access via Azure Monitor logs

---

## C2. Scripts enumerate metadata & files

- **Negation (C2‑N):**  
  Secure mount paths; no hostPath mounts; disable runtime bash.

- **Bypass (C2‑B):**  
  Container escape leads to host-level metadata/file access.

- **Mitigations (C2‑M):**  
  - Enforce **restricted pod specs** (no hostPath/hostNetwork, no privileges) :contentReference[oaicite:13]{index=13}  
  - Scan for CVEs and patch nodes immediately :contentReference[oaicite:14]{index=14}  
  - Deploy host-escape detection (Falco, Defender)

---

## C3. Credentials exfiltrated via C2 to external C2

- **Negation (C3‑N):**  
  Block pod egress to the internet; blacklist suspicious domains.

- **Bypass (C3‑B):**  
  Attackers tunnel via DNS or HTTPS through allowed destinations.

- **Mitigations (C3‑M):**  
  - Use **Azure Firewall/NAT Gateway + TLS inspection proxies** :contentReference[oaicite:15]{index=15}  
  - Enable **Azure DNS Analytics & Defender** for exfil detection :contentReference[oaicite:16]{index=16}  
  - Alert on suspicious egress patterns (high DNS volume, odd HTTP headers)

---

## D1. TeamTNT targets Azure credentials more broadly

All mitigations in sections C1–C3 cover this threat vector.

---

## ✅ Final AKS Security Posture

1. **Cluster Hardening & Identity**  
   - Private API endpoints; Azure AD authentication & RBAC  
   - Disable IMDSv1; enforce IMDSv2

2. **Network Segmentation**  
   - CNI (Azure NPM or Calico) egress restrictions  
   - NSGs and Azure Firewalls for pod traffic

3. **Image & Runtime Integrity**  
   - ACR signing, immutable pipelines, distroless/read-only containers  
   - Defender for Containers, runtime threat detection

4. **Managed Identities & Secrets**  
   - Use workload-managed identities, block IMDS access  
   - Azure Key Vault integration and audit logs

5. **Node Hardening & Patching**  
   - CIS-hardened images, auto-update, Defender for Hosts  
   - Audit node-level anomalies, integrity logs

6. **Observability & Exfil Protection**  
   - Azure Policies, Defender monitoring, resource and kubernetes audit logs  
   - Guard for unusual CPU usage, metadata access, DNS/HTTPS anomalies

# Amazon Web Services

## A1. Kubelet allows anonymous access

- **Negation (A1‑N):**  
  Disable anonymous kubelet access (`--anonymous-auth=false`), enforce authentication, RBAC, and certificate rotation.

- **Bypass (A1‑B):**  
  A compromised pod can exploit EC2 Metadata Service (IMDS) and CSR to obtain kubelet credentials.

- **Mitigations (A1‑M):**  
  - Configure **IMDSv2** and lock down access (security groups or IMDS hop limit).  
  - Enforce **IAM Roles for Service Accounts (IRSA)** instead of node IAM.  
  - Use EKS’s **HardenEKS** or AWS Best Practices Guide to audit security posture
  - Apply **security groups** to prevent pod-to-host metadata access.  
  - Enable Kubernetes **audit logging**, specifically for CSR approvals.

---

## A2. TeamTNT scans kubelet ports (10250/10255)

- **Negation (A2‑N):**  
  Ensure kubelet ports are not internet-facing—use private clusters, VPC CIDR restrictions, and security groups.

- **Bypass (A2‑B):**  
  Misconfigured LoadBalancer or ClusterIP services may unintentionally expose nodes internally.

- **Mitigations (A2‑M):**  
  - Apply **Calico NetworkPolicy** or security groups to block pod egress to kubelet ports.  
  - Use internal-only LoadBalancers and `loadBalancerSourceRanges`
  - Restrict SSH/RDP to nodes via AWS Security Groups.

---

## A3. Successful scan leads to pod RCE

- **Negation (A3‑N):**  
  Enforce kubelet auth/RBAC, disable unauthenticated `exec/attach`.

- **Bypass (A3‑B):**  
  Vulnerable/misconfigured pods (privileged, hostNetwork) enable exec access.

- **Mitigations (A3‑M):**  
  - Implement **Pod Security Admission**: forbid privileged containers, hostPath mounts, hostNetwork.  
  - Use distroless images without shells.  
  - Employ **gVisor/EKS Fargate** for isolation.  
  - Continuously scan container images for vulnerabilities (via Amazon Inspector, kube-bench)

---

## B1. TeamTNT focuses on deploying cryptominers

- **Negation (B1‑N):**  
  Use image signing and **ECR image policies/Binary Authorization** to block malicious code.

- **Bypass (B1‑B):**  
  Attackers inject mining binaries at runtime via `curl`, library injection.

- **Mitigations (B1‑M):**  
  - Enforce ECR policies to allow only signed, trusted images
  - Deploy **Falco runtime detection** on EKS to detect use of `LD_PRELOAD` or other stealth techniques.  
  - Monitor node CPU/GPU usage and alert anomalies.

---

## B2. Miner dropped via bash scripts

- **Negation (B2‑N):**  
  Use minimal/distroless images, disable `exec` API, mount containers as read-only.

- **Bypass (B2‑B):**  
  Pre-build malicious images containing cryptominers.

- **Mitigations (B2‑M):**  
  - Apply container filesystem as **read-only** and disable `exec` via RBAC.  
  - Block egress traffic on known mining ports (e.g., 3333) via NetworkPolicy.  
  - Enforce immutable image tags and restrict vulnerabilities in CI/CD pipelines.

---

## B3. LD_PRELOAD used for stealth

- **Negation (B3‑N):**  
  Detect/prevent `LD_PRELOAD` usage via host-level security.

- **Bypass (B3‑B):**  
  Malicious actors install kernel-level rootkits to hide malware.

- **Mitigations (B3‑M):**  
  - Launch EKS nodes with **EC2 Image Builder** using hardened CIS AMIs (`e.g. Amazon Linux 2`, Bottlerocket)
  - Enable **Shielded VMs** (if applicable) and secure boot to prevent tampering.  
  - Run **Amazon Inspector** & **CloudWatch** integrity checks on hosts

---

## C1. Scanning for cloud credentials in pods

- **Negation (C1‑N):**  
  Use IAM Roles for Service Accounts (IRSA), disable mounting of service-account tokens.

- **Bypass (C1‑B):**  
  Pod exploits metadata service (169.254.169.254) or node identity leaks.

- **Mitigations (C1‑M):**  
  - Block metadata access via NetworkPolicy/security groups.  
  - Ensure IAM roles are scoped with least privilege.  
  - Disable auto-mount of default SA tokens.  
  - Use Secrets Manager or CSI driver for managed secrets

---

## C2. Scripts enumerate metadata & files

- **Negation (C2‑N):**  
  File paths and metadata access secured; no default hostPath mounts.

- **Bypass (C2‑B):**  
  If attacker achieves container escape, metadata and files become accessible.

- **Mitigations (C2‑M):**  
  - Prevent privileged containers; no hostPath mounts; CVE patching.  
  - Monitor for breakout attempts (Falco, Inspector).  
  - Triangulate node-space intrusions via CloudTrail and audit logs.

---

## C3. Credentials exfiltrated via C2 to external C2

- **Negation (C3‑N):**  
  Egress blocked via Security Groups/VPC; known domains blacklisted.

- **Bypass (C3‑B):**  
  Use DNS tunneling or encrypted HTTPS through allowed zones.

- **Mitigations (C3‑M):**  
  - Set up VPC egress via NAT+proxy with TLS inspection.  
  - Enable DNS logging & anomaly detection with GuardDuty.  
  - Use Security Hub + VPC Service Controls to monitor data flow

---

## D1. TeamTNT targets AWS/GCP credentials

Mitigations are covered above in C1–C3: **IAM isolation**, **metadata lock-down**, **egress controls**, and **credential scope minimization**.

---

## ✅ Final AWS EKS Security Posture

1. **Kubelet & API Hardening**  
   - Private control-plane endpoint, disable anonymous auth, enforce audit logs.

2. **Network & Egress Control**  
   - Security Groups, internal-only endpoints, egress proxies, DNS logging.

3. **Image & Runtime Security**  
   - Signed images, read-only distroless containers, runtime monitoring (Falco, Inspector).

4. **IAM & Metadata Safety**  
   - Use IRSA, restrict default SA tokens, block metadata access.

5. **Node Hardening & Integrity**  
   - CIS AMIs, automated patching, secure boot, node integrity checks.

6. **Monitoring & Anomaly Detection**  
   - Audit CloudTrail, enable GuardDuty/VPC flow logs, CPU anomalies, DNS exfil alerts.



# Google Cloud Platform
## A1. Kubelet allows anonymous access

- **Negation (A1‑N):**  
  Disable anonymous access (`--anonymous‑auth=false`), enforce authentication, RBAC, and certificate rotation.

- **Bypass (A1‑B):**  
  An attacker can compromise a pod and exploit the metadata server to fetch TLS bootstrap credentials (via CSR) to impersonate the kubelet.

- **Mitigations (A1‑M):**  
  - Use **Workload Identity**, disable node service‐account metadata access  
  - Block metadata server egress via iptables or NetworkPolicy  
  - Audit CSR submissions and alert unusual approvals  
  - Enforce GKE **private nodes** and **Shielded Nodes**

---

## A2. TeamTNT scans kubelet ports (10250/10255)

- **Negation (A2‑N):**  
  Close kubelet ports; use private clusters, authorized networks, and firewall rules.

- **Bypass (A2‑B):**  
  Misconfigured LoadBalancer pods may still allow internal access from external traffic.

- **Mitigations (A2‑M):**  
  - Also block egress pod traffic to kubelet via Calico NetworkPolicy
  - Use internal-only load balancers or restrict `loadBalancerSourceRanges`
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
  - Enforce **Binary Authorization**
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
  - Block known miner ports via pod-level NetworkPolicy

---

## B3. LD_PRELOAD used for stealth

- **Negation (B3‑N):**  
  Detect/prevent LD_PRELOAD in containers and on host.

- **Bypass (B3‑B):**  
  Attacker installs kernel rootkits at host level.

- **Mitigations (B3‑M):**  
  - Use **Shielded GKE nodes** with Secure Boot
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
  - Remove node service account credentials; use Workload Identity only

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
