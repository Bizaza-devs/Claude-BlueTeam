---
name: hunt-k8s-runtime
description: Hypothesis-driven hunt across Kubernetes audit logs and container runtime telemetry. Covers exec/attach into pods, privileged / hostPath / hostPID pods, ClusterRoleBinding to cluster-admin, secrets get/list bursts, service-account tokens used from outside the cluster, system:anonymous access, DaemonSet/CronJob/webhook persistence, Falco runtime rules (shell in container, writes below /etc, unexpected outbound, crypto-miner signs) and image provenance (registry allowlists, digests, cosign). Log locations and queries for EKS (CloudWatch /aws/eks/<cluster>/cluster), AKS (kube-audit) and GKE (k8s_cluster) with jq, Logs Insights, KQL and Cloud Logging. Maps to T1609, T1610, T1611, T1552.007, T1528, T1496. Use when asked to "hunt Kubernetes", "who exec'd into pods", "privileged pods", "cryptominer in cluster", or "check EKS/AKS/GKE audit logs".
---

# Hunt: Kubernetes control plane and container runtime

## When to use

- Periodic hunt on EKS, AKS, GKE or self-managed clusters.
- A cloud alert (GuardDuty EKS findings, Defender for Containers, Security Command Center) or Falco event needs cluster-wide scoping.
- Cryptomining, unexpected egress or CPU spikes on nodes.
- After a leaked kubeconfig, CI credential or cloud identity with cluster access.

Node OS persistence: `hunt-linux-persistence`. Cloud IAM around the cluster (who can call `eks:*`, `AKS` RBAC, GKE IAM): `hunt-cloud-control-plane`. Node/container forensics: `linux-forensics`, `memory-forensics`.

## Ground rules

- **Know your audit policy before hunting.** If secrets reads are logged at `Metadata` level or `get`/`list` are excluded, absence of evidence means nothing. Record the policy level per resource in the report.
- **Resolve identities**: a `system:serviceaccount:<ns>:<sa>` user is a workload - name the pod/node it was bound to (bound-token `user.extra` fields) or state that it could not be resolved. Cloud-mapped users (aws-auth/access entries, Entra, Google accounts) must be traced back to the human or pipeline.
- **No TP on a runtime alert without workload context**: image, namespace, owner, whether the behaviour is in the image's normal profile.
- **Preserve before killing.** Deleting a pod destroys its filesystem and memory; a controller will recreate it from the (possibly backdoored) spec anyway. Capture the pod spec (`kubectl get pod -o yaml`), logs, and if needed a container filesystem export or node memory, then cordon/isolate under `/contain` approval.
- **Do not exec into a suspect container to investigate** - it is a change, it is logged as you, and it can trigger actor tripwires. Use node-level, read-only collection.

## Workflow

1. **Inventory**: clusters, versions, audit-log destination and policy, runtime sensor (Falco, Defender, GuardDuty Runtime Monitoring, EDR), admission controllers, registries in use, CIDRs (node, pod, service).
2. **Control-plane hunt** (audit log): exec/attach, privileged workload creation, RBAC escalation, secrets access, anonymous and external SA-token use, webhook and policy tampering.
3. **Persistence objects**: DaemonSets, CronJobs, static pods, mutating webhooks, new service accounts with tokens, CSR approvals.
4. **Runtime hunt**: shells and package managers in containers, writes to sensitive paths, unexpected egress, miner signs, drop-and-execute.
5. **Image provenance**: running images vs allowed registries, digests, signatures.
6. **Stack** by identity, source IP, user-agent, namespace and image across clusters.
7. **Verdict, escalation, detection hand-off.**

## Hypothesis templates

- "An identity outside the platform team exec'd into pods in production namespaces or used port-forward to reach internal services."
- "A workload was created with privileged: true, hostPID/hostNetwork/hostIPC or a hostPath mount of / or the container runtime socket, to escape to the node."
- "A principal bound itself or a service account to cluster-admin (or created a Role with `*` verbs on secrets)."
- "A service-account token was stolen from a pod and used from an IP outside the cluster's node and pod ranges."
- "The API server accepted anonymous requests that returned data."
- "A container is mining cryptocurrency (pool connections, stratum, miner binaries) or contacting unexpected destinations."
- "A running image did not come from an approved registry or does not carry a valid signature."

## ATT&CK sub-technique map (Containers matrix)

| Behaviour | Technique |
|---|---|
| exec / attach into containers | T1609 Container Administration Command |
| Deploy pods, DaemonSets, privileged workloads | T1610 Deploy Container |
| hostPath / privileged / hostPID escape | T1611 Escape to Host |
| Listing pods, nodes, namespaces, RBAC | T1613 Container and Resource Discovery |
| Secrets read via API | T1552.007 Unsecured Credentials: Container API |
| SA token theft / TokenRequest | T1528 Steal Application Access Token |
| CronJob persistence | T1053.007 Scheduled Task/Job: Container Orchestration Job |
| RBAC escalation (ClusterRoleBinding) | T1098.006 Additional Container Cluster Roles (verify in your ATT&CK version) |
| Anonymous / default accounts | T1078.001 Default Accounts |
| Backdoored image | T1525 Implant Internal Image; T1204.003 Malicious Image |
| Cryptomining | T1496 Resource Hijacking |
| Admission/webhook/policy tampering | T1562.001 Disable or Modify Tools |

## Data sources required

| Source | Location | Notes |
|---|---|---|
| EKS audit log | CloudWatch Logs group `/aws/eks/<cluster>/cluster`, streams `kube-apiserver-audit-*` | Control-plane logging type "audit" must be enabled per cluster |
| AKS audit log | Diagnostic settings categories `kube-audit` and `kube-audit-admin` -> Log Analytics (`AzureDiagnostics` or resource-specific `AKSAudit`/`AKSAuditAdmin`) | `kube-audit-admin` excludes get/list - secrets read hunting needs `kube-audit` |
| GKE audit log | Cloud Logging, `resource.type="k8s_cluster"`, Admin Activity and Data Access logs | Reads (get/list) are Data Access - confirm they are enabled |
| Self-managed | `--audit-policy-file`, `--audit-log-path` (JSON lines) or webhook backend | Policy levels: None / Metadata / Request / RequestResponse |
| Runtime | Falco (syscall + k8saudit plugins), Defender for Containers, GuardDuty Runtime Monitoring, EDR on nodes | Kubelet API calls (port 10250) bypass the API-server audit log |
| Registry / admission | Registry audit logs, Kyverno / Gatekeeper / Sigstore policy-controller reports | For provenance |

Key audit fields: `verb`, `user.username`, `user.groups`, `user.extra`, `impersonatedUser`, `sourceIPs`, `userAgent`, `objectRef.{resource,subresource,namespace,name}`, `responseStatus.code`, `requestObject` (only at Request/RequestResponse level), `annotations."authorization.k8s.io/decision"`, `requestReceivedTimestamp`.

## Control-plane queries

### Raw audit log (bash + jq)

```bash
# exec / attach / port-forward. Note: exec over WebSocket may be logged with verb get or create depending on version - match the subresource.
jq -c 'select(.stage=="ResponseComplete" and (.objectRef.subresource=="exec" or .objectRef.subresource=="attach" or .objectRef.subresource=="portforward"))
  | {t:.requestReceivedTimestamp, u:.user.username, ns:.objectRef.namespace, pod:.objectRef.name, sub:.objectRef.subresource,
     ip:.sourceIPs[0], ua:.userAgent, code:.responseStatus.code}' audit.log

# Privileged / host-namespace / hostPath pods created directly (controllers create pods as their own SA - also check
# deployments, daemonsets, statefulsets, jobs, cronjobs via .requestObject.spec.template.spec)
jq -c 'select(.objectRef.resource=="pods" and .verb=="create" and .requestObject != null)
  | .requestObject.spec as $s
  | select($s.hostPID==true or $s.hostNetwork==true or $s.hostIPC==true
           or ([$s.containers[]?.securityContext.privileged] | any)
           or ([$s.volumes[]?.hostPath.path] | map(select(. != null)) | length > 0))
  | {t:.requestReceivedTimestamp, u:.user.username, ns:.objectRef.namespace, name:.objectRef.name,
     hostPaths:[$s.volumes[]?.hostPath.path | select(. != null)], images:[$s.containers[]?.image]}' audit.log

# RBAC escalation: (cluster)rolebindings to cluster-admin / admin, and roles granting * or secrets
jq -c 'select((.objectRef.resource=="clusterrolebindings" or .objectRef.resource=="rolebindings")
              and (.verb=="create" or .verb=="update" or .verb=="patch") and .responseStatus.code < 300)
  | {t:.requestReceivedTimestamp, u:.user.username, binding:.objectRef.name, role:.requestObject.roleRef.name, subjects:.requestObject.subjects}' audit.log

# Secrets read volume per identity (needs get/list logged). Tune: controllers and operators that legitimately read secrets.
jq -r 'select(.objectRef.resource=="secrets" and (.verb=="get" or .verb=="list" or .verb=="watch"))
  | [.user.username, .verb, (.objectRef.namespace // "*"), .sourceIPs[0]] | @tsv' audit.log | sort | uniq -c | sort -nr | head -30

# Anonymous requests that succeeded
jq -c 'select(.user.username=="system:anonymous" and .responseStatus.code < 400)
  | {t:.requestReceivedTimestamp, uri:.requestURI, verb:.verb, ip:.sourceIPs[0], ua:.userAgent}' audit.log

# Service-account identities calling from outside node/pod ranges (replace prefixes with your CIDRs; prefix match is approximate)
jq -r 'select(.user.username | startswith("system:serviceaccount:"))
  | [.user.username, .sourceIPs[0], .userAgent, (.user.extra["authentication.kubernetes.io/pod-name"] // ["-"])[0]] | @tsv' audit.log \
| grep -vE $'\t(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)' | sort | uniq -c | sort -nr | head
```

Also review in the same log: `serviceaccounts/token` creates (TokenRequest) by humans, `certificatesigningrequests` create + `approval` updates, `pods/ephemeralcontainers` patches (`kubectl debug`), `nodes/proxy` access, `mutatingwebhookconfigurations`/`validatingwebhookconfigurations` changes or deletes, `impersonate` verbs, and DaemonSets/CronJobs created in `kube-system`.

### EKS (CloudWatch Logs Insights, log group /aws/eks/<cluster>/cluster)

```text
# exec/attach/port-forward by identity
fields @timestamp, user.username, objectRef.namespace, objectRef.name, objectRef.subresource, sourceIPs.0, userAgent
| filter @logStream like /kube-apiserver-audit/
| filter objectRef.subresource in ["exec", "attach", "portforward"]
| stats count(*) as n by user.username, objectRef.namespace, objectRef.subresource
| sort n desc

# privileged / host-namespace workloads (string match on the serialized request; confirm hits with jq on the raw event)
fields @timestamp, user.username, objectRef.resource, objectRef.namespace, objectRef.name
| filter @logStream like /kube-apiserver-audit/ and verb = "create"
| filter @message like /"privileged":true/ or @message like /"hostPID":true/ or @message like /"hostNetwork":true/ or @message like /"hostPath"/

# cluster-admin bindings
fields @timestamp, user.username, objectRef.name, requestObject.roleRef.name
| filter objectRef.resource = "clusterrolebindings" and verb in ["create", "update", "patch"]
| filter requestObject.roleRef.name = "cluster-admin"
```

EKS maps IAM principals to Kubernetes users (aws-auth ConfigMap or access entries); the audit event's `user.extra` carries the IAM ARN - join with CloudTrail (`hunt-cloud-control-plane`) for the human behind it. Changes to `aws-auth` (`configmaps`, name `aws-auth`, namespace `kube-system`) and EKS access-entry APIs in CloudTrail are themselves persistence.

### AKS (KQL)

```kql
// Diagnostic category kube-audit in AzureDiagnostics (log_s holds the audit event JSON). Resource-specific AKSAudit
// exposes the same data as columns - adapt field access if you use it.
AzureDiagnostics
| where TimeGenerated > ago(7d) and Category == "kube-audit"
| extend A = parse_json(log_s)
| extend Verb = tostring(A.verb), User = tostring(A.user.username), Resource = tostring(A.objectRef.resource),
         Sub = tostring(A.objectRef.subresource), Ns = tostring(A.objectRef.namespace), Name = tostring(A.objectRef.name),
         SrcIP = tostring(A.sourceIPs[0]), Code = toint(A.responseStatus.code), UA = tostring(A.userAgent)
| where Sub in ("exec","attach","portforward")
   or (Resource == "clusterrolebindings" and Verb in ("create","update","patch") and tostring(A.requestObject.roleRef.name) == "cluster-admin")
   or (User == "system:anonymous" and Code < 400)
   or (Resource == "pods" and Verb == "create" and (log_s has "\"privileged\":true" or log_s has "\"hostPID\":true" or log_s has "\"hostPath\""))
| project TimeGenerated, Verb, User, Resource, Sub, Ns, Name, SrcIP, UA, Code
```

```kql
// Secrets read bursts per identity per hour (requires kube-audit, not kube-audit-admin). Tune controller allowlist.
AzureDiagnostics
| where TimeGenerated > ago(7d) and Category == "kube-audit"
| extend A = parse_json(log_s)
| where tostring(A.objectRef.resource) == "secrets" and tostring(A.verb) in ("get","list","watch")
| summarize Reads = count(), Namespaces = dcount(tostring(A.objectRef.namespace)), IPs = make_set(tostring(A.sourceIPs[0]), 5)
    by User = tostring(A.user.username), bin(TimeGenerated, 1h)
| where Namespaces > 3 or Reads > 100
```

### GKE (Cloud Logging query language)

```text
# exec into pods, cluster-admin bindings, anonymous access, privileged pods (methodName format: io.k8s.<group>.<version>.<resource>.<verb>)
resource.type="k8s_cluster"
(protoPayload.methodName="io.k8s.core.v1.pods.exec.create"
 OR protoPayload.methodName="io.k8s.core.v1.pods.attach.create"
 OR protoPayload.methodName="io.k8s.authorization.rbac.v1.clusterrolebindings.create"
 OR protoPayload.authenticationInfo.principalEmail="system:anonymous"
 OR (protoPayload.methodName="io.k8s.core.v1.pods.create" AND protoPayload.request.spec.containers.securityContext.privileged=true))
```

Secrets reads (`io.k8s.core.v1.secrets.get`/`list`) are Data Access entries. Verify exact methodName strings against a known event in your project before relying on them.

## Runtime queries

### Falco rules (YAML)

Falco's stable ruleset already ships rules such as "Terminal shell in container" and "Drop and execute new binary in container"; enable and tune those first. The rules below add hunt-oriented coverage using default macros (`spawned_process`, `container`, `open_write`, `outbound`).

```yaml
- list: bt_container_pkg_writers
  items: [apt, apt-get, dpkg, yum, dnf, rpm, apk]

- rule: BT Write Below Etc In Container
  desc: A process in a container opened a file under /etc for writing after start (images should be immutable)
  condition: open_write and container and fd.name startswith /etc/ and not proc.name in (bt_container_pkg_writers)
  output: "Write below /etc in container (file=%fd.name proc=%proc.cmdline user=%user.name image=%container.image.repository:%container.image.tag pod=%k8s.pod.name ns=%k8s.ns.name)"
  priority: WARNING
  tags: [container, persistence, T1610]

- list: bt_egress_restricted_namespaces
  items: [payments, identity]          # replace: namespaces whose pods should never reach the internet

- rule: BT Unexpected Outbound From Restricted Namespace
  desc: Outbound connection to a public address from a pod in an egress-restricted namespace
  condition: outbound and container and k8s.ns.name in (bt_egress_restricted_namespaces)
  output: "Outbound from restricted ns (dest=%fd.name proc=%proc.cmdline image=%container.image.repository pod=%k8s.pod.name ns=%k8s.ns.name)"
  priority: WARNING
  tags: [container, network, T1071]

- list: bt_miner_pool_ports
  items: [3333, 4444, 5555, 7777, 14444, 45700]   # common pool ports - tune; legit services may use them

- rule: BT Possible Cryptominer Activity
  desc: Connection to common mining-pool ports or stratum command lines in a container
  condition: >
    container and ((outbound and fd.sport in (bt_miner_pool_ports))
    or (spawned_process and (proc.cmdline contains "stratum+tcp" or proc.cmdline contains "stratum+ssl" or proc.name in (xmrig, xmr-stak, minerd))))
  output: "Possible miner (proc=%proc.cmdline dest=%fd.name image=%container.image.repository pod=%k8s.pod.name ns=%k8s.ns.name)"
  priority: CRITICAL
  tags: [container, impact, T1496]
```

```yaml
# k8saudit plugin rule (source k8s_audit; managed-cluster variants of the plugin exist for EKS and GKE). Tune allowlist.
- list: bt_exec_allowed_users
  items: [platform-oncall@example.com]

- rule: BT Exec Or Attach Into Pod
  desc: Interactive access to a pod by an identity outside the allowlist
  condition: ka.target.resource = pods and ka.target.subresource in (exec, attach) and not ka.user.name in (bt_exec_allowed_users)
  output: "Pod exec/attach (user=%ka.user.name ns=%ka.target.namespace pod=%ka.target.name verb=%ka.verb uri=%ka.uri)"
  priority: NOTICE
  source: k8s_audit
  tags: [k8s, execution, T1609]
```

Miner corroboration beyond Falco: sustained CPU at limits on pods that are normally idle, DNS lookups for pool domains, binaries in `/tmp` or `/dev/shm` inside containers, and GuardDuty/Defender cryptomining findings.

## Image provenance

```bash
# Running images not from approved registries (include init and ephemeral containers). Replace the registry regex.
kubectl get pods -A -o json | jq -r '.items[] | .metadata.namespace as $ns | .metadata.name as $p
  | ((.spec.containers // []) + (.spec.initContainers // []) + (.spec.ephemeralContainers // []))[] | [$ns, $p, .image] | @tsv' \
| grep -vE $'\t(registry\\.example\\.com/|[0-9]{12}\\.dkr\\.ecr\\.[a-z0-9-]+\\.amazonaws\\.com/)'

# Mutable tags and actual running digests (tag drift = the image behind a tag changed)
kubectl get pods -A -o json | jq -r '.items[] | .status.containerStatuses[]? | [.image, .imageID] | @tsv' | sort -u | grep -E ':latest|\t$'

# Signature verification of a running digest (key-based shown; keyless needs --certificate-identity and --certificate-oidc-issuer)
cosign verify --key cosign.pub registry.example.com/app@sha256:<digest>
```

Also hunt: namespaces exempted from admission policy; deletes/patches of `validatingwebhookconfigurations`, `mutatingwebhookconfigurations`, Kyverno `ClusterPolicy` or Gatekeeper constraints; images pulled from public registries by build or debug pods; new image digests appearing on one cluster only.

## Baselining and stacking

- **Who execs**: per identity and namespace over 30 days - exec in production by non-oncall identities is a lead.
- **Secrets readers**: controllers and operators (cert-manager, external-secrets, ingress controllers, Argo CD) read secrets constantly; baseline them by SA and exclude by exact SA name, never by namespace wildcard.
- **Source IPs per SA**: should be pod/node CIDRs; anything else is token reuse.
- **User-agents**: `kubectl/` from CI vs. humans vs. libraries (`python-requests`, `Go-http-client`) - new UA for an identity is a lead.
- **Image set per namespace** and **egress destinations per workload** for runtime deviations.

## Verdict and escalation

| Verdict | Evidence that moves it there |
|---|---|
| True Positive | Suspicious control-plane action by an identity used from unexpected source / outside change process, or runtime behaviour outside the image profile (miner, shell + egress, host escape) |
| Benign True Positive | On-call debugging with ticket, platform automation, approved security tooling (scanners exec'ing, privileged agents like CNI, CSI, log shippers) |
| False Positive | Mis-parsed field, health-check or controller noise matching a string pattern |
| Needs more data | Audit level too low (no requestObject), SA token not resolvable to a pod, no runtime sensor on the node |

Escalate to `incident-response` on: any TP; any cluster-admin binding outside change control; any SA token used from outside the cluster; successful anonymous data access; any privileged/hostPath workload not in the platform allowlist; miner activity (also implies credential or image compromise - hunt the entry point). Containment (cordon/drain nodes, NetworkPolicy deny, scale to zero, revoke tokens by rotating SA or signing keys) is approval-gated via `/contain`; collect specs, logs and node evidence first.

## False positives & benign look-alikes

| Look-alike | Why it fires | How to separate |
|---|---|---|
| CNI, CSI, kube-proxy, log/metrics agents, Falco itself | Privileged, hostPath, hostNetwork DaemonSets | Platform-owned namespaces, signed images, Helm release records |
| Operators and GitOps (Argo CD, Flux, cert-manager, external-secrets) | Secrets reads, RBAC writes | Exact SA names, steady pattern |
| On-call engineers using `kubectl exec`/`debug` | Exec, ephemeral containers | Ticket/incident reference, break-glass group |
| CI/CD deploying with cluster-admin | RBAC and workload writes | Pipeline identity and runner IPs (still a hardening finding) |
| Cloud-provider managed components | Calls from provider IP ranges, system users | `eks:`/`aks`/GKE system users, documented by provider |
| Images built with package installs at start (bad practice) | Package manager runs, writes below /etc | Same in every replica since rollout; fix the image |
| Legit services on common miner ports | Outbound to 3333/4444/etc. | Destination is a known internal or vendor service |

## Pitfalls

- Kubelet API (10250), container runtime socket and node SSH actions never reach the API-server audit log - pair with node telemetry.
- `requestObject` is absent at `Metadata` level: you cannot see privileged flags or roleRef without Request-level policy for those resources.
- Pods created by controllers are attributed to the controller's SA; attribute the change to whoever changed the Deployment/DaemonSet.
- AKS `kube-audit-admin` and some managed defaults drop read events; GKE reads are Data Access logs.
- Managed control planes rotate log streams and retain logs only as configured - export early in an incident.
- Short-lived pods: by the time you look, the evidence pod is gone; rely on audit and runtime events, not `kubectl get`.

## Output

Hunt report stub (`cases/<id>/hunts/k8s-runtime-<date>.md`):

```markdown
# Hunt report - Kubernetes control plane and runtime - <date>
- Hypothesis: <filled template>
- ATT&CK: <T-IDs>
- Clusters and coverage: <cluster/version>, audit destination and policy level, runtime sensors, window <UTC>, gaps
- Method: queries <IDs>, allowlists (exec users, privileged workloads, secrets readers) <ref>
- Findings:
  | Time (UTC) | Cluster/ns | Identity (resolved) | Action / runtime event | Source IP / UA | Image (digest) | Verdict |
- Image provenance: unapproved registries, unsigned digests, tag drift
- Escalations and containment requests: <IDs, approvals>
- Detection and hardening opportunities: <hand-offs>
```

Hand-offs: response -> `incident-response`, `/contain`; cloud identity behind cluster users -> `hunt-cloud-control-plane`, `ir-cloud-aws`, `ir-azure-entra`; node persistence -> `hunt-linux-persistence`; network/C2 from pods -> `hunt-c2-beaconing`; forensics -> `linux-forensics`, `memory-forensics`; rules -> `detection-engineering`, `sigma-rules`; prevention (Pod Security Admission, RBAC, admission policy) -> `hardening-cloud`, `hardening-linux`; log gaps -> `logging-coverage`.

## References

- MITRE ATT&CK Containers matrix; T1609 (https://attack.mitre.org/techniques/T1609/), T1610, T1611, T1613, T1552.007, T1528, T1053.007, T1496
- Kubernetes documentation: Auditing (audit policy levels, event fields), RBAC good practices, Pod Security Standards
- NSA/CISA Kubernetes Hardening Guide
- AWS EKS documentation: control plane logging; GuardDuty EKS protection and Runtime Monitoring
- Microsoft Learn: AKS resource logs (kube-audit, kube-audit-admin); Defender for Containers
- Google Cloud documentation: GKE audit logging
- Falco documentation: default macros and rules, k8saudit plugin fields; Sigstore cosign documentation
