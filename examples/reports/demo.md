# Hetzner Security Audit

## At a glance

| | |
|---|---|
| Scope | 7 servers · 1 network |
| Confirmed (evidence complete) | 23 findings |
| Needs host/runtime validation | 10 hypotheses |
| Rejected by the verifier | 0 |
| Collection gaps | none |

### What this audit knows

| Coverage | | Basis |
|---|---|---|
| Cost | 0% | catalog price found per server |
| CPU utilization | 0% | provider CPU metrics (RAM/disk never) |
| Ownership | 0% | owner or project label |
| Provider backups | 0% | of 2 stateful servers |
| Host/runtime evidence | 57% | host firewall, listeners, service config |

- Snapshot: 2026-09-22 00:00 UTC · collector fixture
- Scope: Hetzner Cloud control plane only (API, GET requests). No SSH, no host or application evidence.

## Recommended actions

### 1. Close public exposure: SSH reachable from the public internet

**Saving:** TBD · **Evidence:** MEDIUM (cloud path observed; host firewall, listener, and auth not observed) · **Risk of acting:** low

An inbound rule admits a public source to TCP/22.

**Next step:** Remove the 0.0.0.0/0 rule in IaC or restrict it to known sources; then confirm the service is unreachable from outside.

### 2. Close public exposure: Docker daemon reachable from the public internet

**Saving:** TBD · **Evidence:** HIGH (provider and host/runtime evidence agree) · **Risk of acting:** low

An inbound rule admits a public source to TCP/2375.

**Next step:** Remove the 0.0.0.0/0 rule in IaC or restrict it to known sources; then confirm the service is unreachable from outside.

### 3. Close public exposure: Kubernetes API reachable from the public internet

**Saving:** TBD · **Evidence:** HIGH (provider and host/runtime evidence agree) · **Risk of acting:** low

An inbound rule admits a public source to TCP/6443.

**Next step:** Remove the 0.0.0.0/0 rule in IaC or restrict it to known sources; then confirm the service is unreachable from outside.

### 4. Close public exposure: PostgreSQL reachable from the public internet

**Saving:** TBD · **Evidence:** HIGH (provider and host/runtime evidence agree) · **Risk of acting:** low

An inbound rule admits a public source to TCP/5432.

**Next step:** Remove the 0.0.0.0/0 rule in IaC or restrict it to known sources; then confirm the service is unreachable from outside.

### 5. Close public exposure: Redis reachable from the public internet

**Saving:** TBD · **Evidence:** HIGH (provider and host/runtime evidence agree) · **Risk of acting:** low

An inbound rule admits a public source to TCP/6379.

**Next step:** Remove the 0.0.0.0/0 rule in IaC or restrict it to known sources; then confirm the service is unreachable from outside.

### 6. Close public exposure: Internet-facing server has no observed firewall control

**Saving:** TBD · **Evidence:** MEDIUM (cloud path observed; host firewall, listener, and auth not observed) · **Risk of acting:** low

A public interface exists, but neither an attached Hetzner firewall nor an observed host firewall is present.

**Next step:** Remove the 0.0.0.0/0 rule in IaC or restrict it to known sources; then confirm the service is unreachable from outside.

### 7. Close public exposure: Internet-facing server has no observed firewall control

**Saving:** TBD · **Evidence:** MEDIUM (cloud path observed; host firewall, listener, and auth not observed) · **Risk of acting:** low

A public interface exists, but neither an attached Hetzner firewall nor an observed host firewall is present.

**Next step:** Remove the 0.0.0.0/0 rule in IaC or restrict it to known sources; then confirm the service is unreachable from outside.

### 8. Define and test backups for 5 stateful servers

**Saving:** TBD · **Evidence:** LOW (absence of evidence; depends on collector coverage and owner intent) · **Risk of acting:** low

Provider backups are off.

**Next step:** Record which mechanism protects each volume and run one restore test; enable provider backups (+20% of the server price) where none exists.

## Findings by status

### Confirmed

- **CRITICAL** · HETZ-DKR-002 · Container can control the Docker daemon (2 assets) · evidence HIGH
- **CRITICAL** · HETZ-NET-002 · Docker daemon reachable from the public internet · evidence HIGH
- **CRITICAL** · HETZ-NET-002 · Kubernetes API reachable from the public internet · evidence HIGH
- **CRITICAL** · HETZ-NET-004 · Redis reachable from the public internet · evidence HIGH
- **CRITICAL** · HETZ-PG-001 · Broad PostgreSQL trust authentication bypasses credentials · evidence HIGH
- **CRITICAL** · HETZ-RDS-001 · Redis accepts non-local clients without an authentication control · evidence HIGH
- **HIGH** · HETZ-DKR-001 · Privileged container crosses the host isolation boundary (2 assets) · evidence HIGH
- **HIGH** · HETZ-DKR-003 · Container shares the host PID namespace (2 assets) · evidence HIGH
- **HIGH** · HETZ-NET-003 · PostgreSQL reachable from the public internet · evidence HIGH
- **HIGH** · HETZ-PG-002 · Unexpected PostgreSQL roles hold superuser capability · evidence HIGH
- **HIGH** · HETZ-XLY-001 · staging workload can reach prod postgres · evidence HIGH
- **HIGH** · HETZ-XLY-001 · dev workload can reach prod redis · evidence HIGH
- **HIGH** · HETZ-XLY-001 · staging workload can reach prod redis · evidence HIGH
- **HIGH** · HETZ-XLY-001 · dev workload can reach prod postgres · evidence HIGH
- **MEDIUM** · HETZ-DKR-004 · Container shares the host network namespace (2 assets) · evidence HIGH
- **MEDIUM** · HETZ-IAC-001 · Runtime network access diverges from declared infrastructure (2 assets) · evidence HIGH
- **MEDIUM** · HETZ-VULN-001 · Vulnerable component in non-public workload (2 assets) · evidence HIGH

### Needs host or runtime validation

- HETZ-BCP-001 · Production stateful asset lacks observed backup coverage (5 assets) · evidence LOW (absence of evidence; depends on collector coverage and owner intent)
- HETZ-NET-001 · SSH reachable from the public internet · evidence MEDIUM (cloud path observed; host firewall, listener, and auth not observed)
- HETZ-NET-005 · Internet-facing server has no observed firewall control (2 assets) · evidence MEDIUM (cloud path observed; host firewall, listener, and auth not observed)
- HETZ-PG-001 · Broad PostgreSQL trust authentication bypasses credentials · evidence LOW (absence of evidence; depends on collector coverage and owner intent)
- HETZ-VULN-001 · Vulnerable component in non-public workload · evidence LOW (absence of evidence; depends on collector coverage and owner intent)

### Collection gaps

- Every Hetzner endpoint was collected.

## Evidence scope

- Collected at: 2026-09-22T00:00:00+00:00
- Collector: normalized snapshot
- Collector version: unknown
- Run ID: unknown

## Collection gaps

- None reported by the collector.

## HIGH · HETZ-DKR-001 · Privileged container crosses the host isolation boundary (2 assets)

- **Status:** confirmed
- **Confidence:** 0.97
- **Assets:** demo-ops-agent, demo-stage-worker

**Observation:** Runtime inspection reports privileged=true.

**Expected:** The workload has only capabilities required by its declared function.

**Actual:** privileged=true

**Attack path:** each listed asset → container_runtime → host

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** Container compromise can expand to host or sibling-workload control.

**Remediation:** Disable privileged and grant a narrower capability or mediated service.

## CRITICAL · HETZ-DKR-002 · Container can control the Docker daemon (2 assets)

- **Status:** confirmed
- **Confidence:** 0.97
- **Assets:** demo-ops-agent, demo-stage-worker

**Observation:** Runtime inspection reports docker_socket=true.

**Expected:** The workload has only capabilities required by its declared function.

**Actual:** docker_socket=true

**Attack path:** each listed asset → container_runtime → host

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** Container compromise can expand to host or sibling-workload control.

**Remediation:** Disable docker_socket and grant a narrower capability or mediated service.

## HIGH · HETZ-DKR-003 · Container shares the host PID namespace (2 assets)

- **Status:** confirmed
- **Confidence:** 0.97
- **Assets:** demo-ops-agent, demo-stage-worker

**Observation:** Runtime inspection reports host_pid=true.

**Expected:** The workload has only capabilities required by its declared function.

**Actual:** host_pid=true

**Attack path:** each listed asset → container_runtime → host

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** Container compromise can expand to host or sibling-workload control.

**Remediation:** Disable host_pid and grant a narrower capability or mediated service.

## MEDIUM · HETZ-DKR-004 · Container shares the host network namespace (2 assets)

- **Status:** confirmed
- **Confidence:** 0.97
- **Assets:** demo-ops-agent, demo-stage-worker

**Observation:** Runtime inspection reports host_network=true.

**Expected:** The workload has only capabilities required by its declared function.

**Actual:** host_network=true

**Attack path:** each listed asset → container_runtime → host

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** Container compromise can expand to host or sibling-workload control.

**Remediation:** Disable host_network and grant a narrower capability or mediated service.

## MEDIUM · HETZ-IAC-001 · Runtime network access diverges from declared infrastructure (2 assets)

- **Status:** confirmed
- **Confidence:** 0.98
- **Assets:** demo-admin, demo-public-pg

**Observation:** Declared and observed source ranges differ for a security-sensitive port.

**Expected:** TCP/22 sources equal the declared set \['100.64.0.0/10'\].

**Actual:** Unexpected observed sources: \['0.0.0.0/0'\].

**Attack path:** 0.0.0.0/0 → tcp/22 → provider-policy:server:admin

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** The provider policy no longer enforces the reviewed source restriction; downstream reachability requires separate host and service evidence.

**Remediation:** Reconcile the runtime firewall to reviewed IaC, then import or remove manual drift.

## CRITICAL · HETZ-NET-002 · Docker daemon reachable from the public internet

- **Status:** confirmed
- **Confidence:** 0.88
- **Assets:** demo-docker-api

**Observation:** An inbound rule admits a public source to TCP/2375.

**Expected:** Management and data services are reachable only from declared trusted sources.

**Actual:** TCP/2375 admits \['0.0.0.0/0'\].

**Attack path:** internet → tcp/2375 → demo-docker-api

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** An unauthenticated network peer can reach a sensitive service boundary.

**Remediation:** Restrict the rule to a VPN, bastion, or explicit workload CIDR and verify host controls.

## CRITICAL · HETZ-NET-002 · Kubernetes API reachable from the public internet

- **Status:** confirmed
- **Confidence:** 0.88
- **Assets:** demo-kube-api

**Observation:** An inbound rule admits a public source to TCP/6443.

**Expected:** Management and data services are reachable only from declared trusted sources.

**Actual:** TCP/6443 admits \['::/0'\].

**Attack path:** internet → tcp/6443 → demo-kube-api

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** An unauthenticated network peer can reach a sensitive service boundary.

**Remediation:** Restrict the rule to a VPN, bastion, or explicit workload CIDR and verify host controls.

## HIGH · HETZ-NET-003 · PostgreSQL reachable from the public internet

- **Status:** confirmed
- **Confidence:** 0.88
- **Assets:** demo-public-pg

**Observation:** An inbound rule admits a public source to TCP/5432.

**Expected:** Management and data services are reachable only from declared trusted sources.

**Actual:** TCP/5432 admits \['0.0.0.0/0'\].

**Attack path:** internet → tcp/5432 → demo-public-pg

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** An unauthenticated network peer can reach a sensitive service boundary.

**Remediation:** Restrict the rule to a VPN, bastion, or explicit workload CIDR and verify host controls.

## CRITICAL · HETZ-NET-004 · Redis reachable from the public internet

- **Status:** confirmed
- **Confidence:** 0.88
- **Assets:** demo-public-redis

**Observation:** An inbound rule admits a public source to TCP/6379.

**Expected:** Management and data services are reachable only from declared trusted sources.

**Actual:** TCP/6379 admits \['0.0.0.0/0'\].

**Attack path:** internet → tcp/6379 → demo-public-redis

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** An unauthenticated network peer can reach a sensitive service boundary.

**Remediation:** Restrict the rule to a VPN, bastion, or explicit workload CIDR and verify host controls.

## CRITICAL · HETZ-PG-001 · Broad PostgreSQL trust authentication bypasses credentials

- **Status:** confirmed
- **Confidence:** 0.99
- **Assets:** demo-prod-postgres

**Observation:** pg_hba.conf trusts a broad network range.

**Expected:** Remote database connections use authenticated, encrypted methods scoped to required clients.

**Actual:** HBA rule 0 uses trust for 0.0.0.0/0.

**Attack path:** 0.0.0.0/0 → demo-prod-postgres → postgres authentication

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** A reachable client can select an allowed database role without presenting a password.

**Remediation:** Replace trust with scram-sha-256 or certificate authentication and scope the CIDR.

## HIGH · HETZ-PG-002 · Unexpected PostgreSQL roles hold superuser capability

- **Status:** confirmed
- **Confidence:** 0.93
- **Assets:** demo-prod-postgres

**Observation:** Role inventory marks superuser roles outside the declared allowlist.

**Expected:** Only explicitly designated break-glass or administrative roles are superusers.

**Actual:** Unexpected superusers: \['app', 'migration'\].

**Attack path:** database credentials → app → migration → demo-prod-postgres

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** The roles can bypass database authorization and alter security-sensitive configuration.

**Remediation:** Revoke SUPERUSER and grant the minimum object and administrative privileges.

## CRITICAL · HETZ-RDS-001 · Redis accepts non-local clients without an authentication control

- **Status:** confirmed
- **Confidence:** 0.99
- **Assets:** demo-prod-redis

**Observation:** Broad bind, disabled protected mode, and absent ACL/password evidence coincide.

**Expected:** Redis is limited to trusted clients and requires a scoped ACL identity.

**Actual:** bind is broad; protected-mode=no; no authentication configured.

**Attack path:** reachable network peer → demo-prod-redis → redis command surface

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** A client can read, alter, or destroy cached or persistent data.

**Remediation:** Bind to the required interface, enable protected mode, and configure least-privilege ACLs.

## MEDIUM · HETZ-VULN-001 · Vulnerable component in non-public workload

- **Status:** confirmed
- **Confidence:** 0.84
- **Assets:** demo-stage-worker

**Observation:** grype reports CVE-DEMO-0002 in openssl-demo.

**Expected:** Deployed components have no applicable high-impact known vulnerabilities.

**Actual:** Installed 2.0; fixed 2.1; internet_reachable=False.

**Attack path:** demo-stage-worker → local vulnerable component

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** Impact depends on exploit preconditions; reachability changes priority but not vulnerable status.

**Remediation:** Upgrade to the fixed version and verify whether the affected component is loaded or reachable.

## MEDIUM · HETZ-VULN-001 · Vulnerable component in non-public workload

- **Status:** confirmed
- **Confidence:** 0.84
- **Assets:** demo-ops-agent

**Observation:** trivy reports CVE-DEMO-0003 in curl-demo.

**Expected:** Deployed components have no applicable high-impact known vulnerabilities.

**Actual:** Installed 3.0; fixed 3.1; internet_reachable=False.

**Attack path:** demo-ops-agent → local vulnerable component

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** Impact depends on exploit preconditions; reachability changes priority but not vulnerable status.

**Remediation:** Upgrade to the fixed version and verify whether the affected component is loaded or reachable.

## HIGH · HETZ-XLY-001 · staging workload can reach prod postgres

- **Status:** confirmed
- **Confidence:** 0.96
- **Assets:** demo-stage-worker, demo-prod-postgres

**Observation:** A cross-environment attack-graph path contradicts an explicit isolation declaration.

**Expected:** staging and prod data planes are isolated.

**Actual:** A TCP/5432 path exists: container:stage-worker -\> network:shared -\> postgres:prod

**Attack path:** demo-stage-worker → demo-shared → demo-prod-postgres

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** Compromise of a lower-trust environment can become unauthorized database or cache access.

**Remediation:** Separate environment networks and enforce target-side allowlists for the exact clients.

## HIGH · HETZ-XLY-001 · dev workload can reach prod redis

- **Status:** confirmed
- **Confidence:** 0.96
- **Assets:** demo-ops-agent, demo-prod-redis

**Observation:** A cross-environment attack-graph path contradicts an explicit isolation declaration.

**Expected:** dev and prod data planes are isolated.

**Actual:** A TCP/6379 path exists: container:ops-agent -\> network:shared -\> redis:prod

**Attack path:** demo-ops-agent → demo-shared → demo-prod-redis

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** Compromise of a lower-trust environment can become unauthorized database or cache access.

**Remediation:** Separate environment networks and enforce target-side allowlists for the exact clients.

## HIGH · HETZ-XLY-001 · staging workload can reach prod redis

- **Status:** confirmed
- **Confidence:** 0.96
- **Assets:** demo-stage-worker, demo-prod-redis

**Observation:** A cross-environment attack-graph path contradicts an explicit isolation declaration.

**Expected:** staging and prod data planes are isolated.

**Actual:** A TCP/6379 path exists: container:stage-worker -\> network:shared -\> redis:prod

**Attack path:** demo-stage-worker → demo-shared → demo-prod-redis

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** Compromise of a lower-trust environment can become unauthorized database or cache access.

**Remediation:** Separate environment networks and enforce target-side allowlists for the exact clients.

## HIGH · HETZ-XLY-001 · dev workload can reach prod postgres

- **Status:** confirmed
- **Confidence:** 0.96
- **Assets:** demo-ops-agent, demo-prod-postgres

**Observation:** A cross-environment attack-graph path contradicts an explicit isolation declaration.

**Expected:** dev and prod data planes are isolated.

**Actual:** A TCP/5432 path exists: container:ops-agent -\> network:shared -\> postgres:prod

**Attack path:** demo-ops-agent → demo-shared → demo-prod-postgres

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** Compromise of a lower-trust environment can become unauthorized database or cache access.

**Remediation:** Separate environment networks and enforce target-side allowlists for the exact clients.

## UNSCORED · HETZ-BCP-001 · Production stateful asset lacks observed backup coverage (5 assets)

- **Status:** needs_validation
- **Confidence:** 0.69
- **Assets:** demo-analytics-postgres, demo-prod-postgres, demo-prod-redis, demo-public-pg, demo-public-redis

**Observation:** The asset is declared production and stateful, but no backup configuration is observed.

**Expected:** Production state has a tested, declared recovery mechanism.

**Actual:** backup_enabled=false or absent.

**Attack path:** each listed asset → data loss → unrecoverable state

**Verification:** Absence evidence depends on complete collector coverage; validate the missing control with the owner.

**Impact:** Deletion, corruption, or compromise may cause unrecoverable service data loss.

**Remediation:** Enable provider or application-consistent backups and record a restore test.

## UNSCORED · HETZ-NET-001 · SSH reachable from the public internet

- **Status:** needs_validation
- **Confidence:** 0.69
- **Assets:** demo-admin

**Observation:** An inbound rule admits a public source to TCP/22.

**Expected:** Management and data services are reachable only from declared trusted sources.

**Actual:** TCP/22 admits \['0.0.0.0/0'\].

**Attack path:** internet → tcp/22 → demo-admin

**Verification:** The provider rule is attached, but listener and host-firewall evidence are incomplete; validate end-to-end reachability safely.

**Impact:** An unauthenticated network peer can reach a sensitive service boundary.

**Remediation:** Restrict the rule to a VPN, bastion, or explicit workload CIDR and verify host controls.

## UNSCORED · HETZ-NET-005 · Internet-facing server has no observed firewall control (2 assets)

- **Status:** needs_validation
- **Confidence:** 0.69
- **Assets:** demo-no-firewall-a, demo-no-firewall-b

**Observation:** A public interface exists, but neither an attached Hetzner firewall nor an observed host firewall is present.

**Expected:** Every public server has an independently evidenced ingress control.

**Actual:** Public IP present; firewall attachment and host firewall evidence absent.

**Attack path:** internet → each listed asset

**Verification:** Absence evidence depends on complete collector coverage; validate the missing control with the owner.

**Impact:** Services that bind broadly may be reachable without a network policy boundary.

**Remediation:** Attach a least-privilege Hetzner firewall or provide verified host-firewall evidence.

## UNSCORED · HETZ-PG-001 · Broad PostgreSQL trust authentication bypasses credentials

- **Status:** needs_validation
- **Confidence:** 0.69
- **Assets:** demo-analytics-postgres

**Observation:** pg_hba.conf trusts a broad network range.

**Expected:** Remote database connections use authenticated, encrypted methods scoped to required clients.

**Actual:** HBA rule 0 uses trust for ::/0.

**Attack path:** ::/0 → demo-analytics-postgres → postgres authentication

**Verification:** The HBA rule is unsafe if selected, but no source-to-PostgreSQL network path is evidenced.

**Impact:** A reachable client can select an allowed database role without presenting a password.

**Remediation:** Replace trust with scram-sha-256 or certificate authentication and scope the CIDR.

## UNSCORED · HETZ-VULN-001 · Vulnerable component in non-public workload

- **Status:** needs_validation
- **Confidence:** 0.69
- **Assets:** demo-internal-api

**Observation:** trivy reports CVE-DEMO-0001 in libdemo.

**Expected:** Deployed components have no applicable high-impact known vulnerabilities.

**Actual:** Installed 1.0; fixed 1.1; internet_reachable=False.

**Attack path:** demo-internal-api → local vulnerable component

**Verification:** Scanner signal is not enough to confirm runtime applicability; safely verify: runtime_present, affected_code_path.

**Impact:** Impact depends on exploit preconditions; reachability changes priority but not vulnerable status.

**Remediation:** Upgrade to the fixed version and verify whether the affected component is loaded or reachable.
