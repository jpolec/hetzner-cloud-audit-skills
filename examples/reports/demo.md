# Hetzner Security Audit

## Summary

- Confirmed: 26
- Needs validation: 7
- Rejected: 0

## HIGH · HETZ-DKR-001 · Privileged container crosses the host isolation boundary

**Status:** confirmed  
**Confidence:** 0.97  
**Assets:** container:stage-worker

**Observation:** Runtime inspection reports privileged=true.

**Expected:** The workload has only capabilities required by its declared function.

**Actual:** privileged=true

**Attack path:** container:stage-worker → container_runtime → host

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** Container compromise can expand to host or sibling-workload control.

**Remediation:** Disable privileged and grant a narrower capability or mediated service.

## HIGH · HETZ-DKR-001 · Privileged container crosses the host isolation boundary

**Status:** confirmed  
**Confidence:** 0.97  
**Assets:** container:ops-agent

**Observation:** Runtime inspection reports privileged=true.

**Expected:** The workload has only capabilities required by its declared function.

**Actual:** privileged=true

**Attack path:** container:ops-agent → container_runtime → host

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** Container compromise can expand to host or sibling-workload control.

**Remediation:** Disable privileged and grant a narrower capability or mediated service.

## CRITICAL · HETZ-DKR-002 · Container can control the Docker daemon

**Status:** confirmed  
**Confidence:** 0.97  
**Assets:** container:ops-agent

**Observation:** Runtime inspection reports docker_socket=true.

**Expected:** The workload has only capabilities required by its declared function.

**Actual:** docker_socket=true

**Attack path:** container:ops-agent → container_runtime → host

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** Container compromise can expand to host or sibling-workload control.

**Remediation:** Disable docker_socket and grant a narrower capability or mediated service.

## CRITICAL · HETZ-DKR-002 · Container can control the Docker daemon

**Status:** confirmed  
**Confidence:** 0.97  
**Assets:** container:stage-worker

**Observation:** Runtime inspection reports docker_socket=true.

**Expected:** The workload has only capabilities required by its declared function.

**Actual:** docker_socket=true

**Attack path:** container:stage-worker → container_runtime → host

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** Container compromise can expand to host or sibling-workload control.

**Remediation:** Disable docker_socket and grant a narrower capability or mediated service.

## HIGH · HETZ-DKR-003 · Container shares the host PID namespace

**Status:** confirmed  
**Confidence:** 0.97  
**Assets:** container:stage-worker

**Observation:** Runtime inspection reports host_pid=true.

**Expected:** The workload has only capabilities required by its declared function.

**Actual:** host_pid=true

**Attack path:** container:stage-worker → container_runtime → host

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** Container compromise can expand to host or sibling-workload control.

**Remediation:** Disable host_pid and grant a narrower capability or mediated service.

## HIGH · HETZ-DKR-003 · Container shares the host PID namespace

**Status:** confirmed  
**Confidence:** 0.97  
**Assets:** container:ops-agent

**Observation:** Runtime inspection reports host_pid=true.

**Expected:** The workload has only capabilities required by its declared function.

**Actual:** host_pid=true

**Attack path:** container:ops-agent → container_runtime → host

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** Container compromise can expand to host or sibling-workload control.

**Remediation:** Disable host_pid and grant a narrower capability or mediated service.

## MEDIUM · HETZ-DKR-004 · Container shares the host network namespace

**Status:** confirmed  
**Confidence:** 0.97  
**Assets:** container:ops-agent

**Observation:** Runtime inspection reports host_network=true.

**Expected:** The workload has only capabilities required by its declared function.

**Actual:** host_network=true

**Attack path:** container:ops-agent → container_runtime → host

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** Container compromise can expand to host or sibling-workload control.

**Remediation:** Disable host_network and grant a narrower capability or mediated service.

## MEDIUM · HETZ-DKR-004 · Container shares the host network namespace

**Status:** confirmed  
**Confidence:** 0.97  
**Assets:** container:stage-worker

**Observation:** Runtime inspection reports host_network=true.

**Expected:** The workload has only capabilities required by its declared function.

**Actual:** host_network=true

**Attack path:** container:stage-worker → container_runtime → host

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** Container compromise can expand to host or sibling-workload control.

**Remediation:** Disable host_network and grant a narrower capability or mediated service.

## HIGH · HETZ-IAC-001 · Runtime network access diverges from declared infrastructure

**Status:** confirmed  
**Confidence:** 0.98  
**Assets:** server:admin

**Observation:** Declared and observed source ranges differ for a security-sensitive port.

**Expected:** TCP/22 sources equal the declared set ['100.64.0.0/10'].

**Actual:** Unexpected observed sources: ['0.0.0.0/0'].

**Attack path:** 0.0.0.0/0 → tcp/22 → server:admin

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** A change outside the reviewed IaC path bypasses the intended access boundary.

**Remediation:** Reconcile the runtime firewall to reviewed IaC, then import or remove manual drift.

## HIGH · HETZ-IAC-001 · Runtime network access diverges from declared infrastructure

**Status:** confirmed  
**Confidence:** 0.98  
**Assets:** server:public-pg

**Observation:** Declared and observed source ranges differ for a security-sensitive port.

**Expected:** TCP/5432 sources equal the declared set ['10.0.0.0/8'].

**Actual:** Unexpected observed sources: ['0.0.0.0/0'].

**Attack path:** 0.0.0.0/0 → tcp/5432 → server:public-pg

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** A change outside the reviewed IaC path bypasses the intended access boundary.

**Remediation:** Reconcile the runtime firewall to reviewed IaC, then import or remove manual drift.

## HIGH · HETZ-NET-001 · SSH reachable from the public internet

**Status:** confirmed  
**Confidence:** 0.88  
**Assets:** server:admin

**Observation:** An inbound rule admits a public source to TCP/22.

**Expected:** Management and data services are reachable only from declared trusted sources.

**Actual:** TCP/22 admits ['0.0.0.0/0'].

**Attack path:** internet → tcp/22 → server:admin

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** An unauthenticated network peer can reach a sensitive authentication boundary.

**Remediation:** Restrict the rule to a VPN, bastion, or explicit workload CIDR and verify host controls.

## CRITICAL · HETZ-NET-002 · Docker daemon reachable from the public internet

**Status:** confirmed  
**Confidence:** 0.88  
**Assets:** server:docker-api

**Observation:** An inbound rule admits a public source to TCP/2375.

**Expected:** Management and data services are reachable only from declared trusted sources.

**Actual:** TCP/2375 admits ['0.0.0.0/0'].

**Attack path:** internet → tcp/2375 → server:docker-api

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** An unauthenticated network peer can reach a sensitive authentication boundary.

**Remediation:** Restrict the rule to a VPN, bastion, or explicit workload CIDR and verify host controls.

## CRITICAL · HETZ-NET-002 · Kubernetes API reachable from the public internet

**Status:** confirmed  
**Confidence:** 0.88  
**Assets:** server:kube-api

**Observation:** An inbound rule admits a public source to TCP/6443.

**Expected:** Management and data services are reachable only from declared trusted sources.

**Actual:** TCP/6443 admits ['::/0'].

**Attack path:** internet → tcp/6443 → server:kube-api

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** An unauthenticated network peer can reach a sensitive authentication boundary.

**Remediation:** Restrict the rule to a VPN, bastion, or explicit workload CIDR and verify host controls.

## HIGH · HETZ-NET-003 · PostgreSQL reachable from the public internet

**Status:** confirmed  
**Confidence:** 0.88  
**Assets:** server:public-pg

**Observation:** An inbound rule admits a public source to TCP/5432.

**Expected:** Management and data services are reachable only from declared trusted sources.

**Actual:** TCP/5432 admits ['0.0.0.0/0'].

**Attack path:** internet → tcp/5432 → server:public-pg

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** An unauthenticated network peer can reach a sensitive authentication boundary.

**Remediation:** Restrict the rule to a VPN, bastion, or explicit workload CIDR and verify host controls.

## CRITICAL · HETZ-NET-004 · Redis reachable from the public internet

**Status:** confirmed  
**Confidence:** 0.88  
**Assets:** server:public-redis

**Observation:** An inbound rule admits a public source to TCP/6379.

**Expected:** Management and data services are reachable only from declared trusted sources.

**Actual:** TCP/6379 admits ['0.0.0.0/0'].

**Attack path:** internet → tcp/6379 → server:public-redis

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** An unauthenticated network peer can reach a sensitive authentication boundary.

**Remediation:** Restrict the rule to a VPN, bastion, or explicit workload CIDR and verify host controls.

## CRITICAL · HETZ-PG-001 · Broad PostgreSQL trust authentication bypasses credentials

**Status:** confirmed  
**Confidence:** 0.99  
**Assets:** postgres:prod

**Observation:** pg_hba.conf trusts a broad network range.

**Expected:** Remote database connections use authenticated, encrypted methods scoped to required clients.

**Actual:** HBA rule 0 uses trust for 0.0.0.0/0.

**Attack path:** 0.0.0.0/0 → postgres:prod → postgres authentication

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** A reachable client can select an allowed database role without presenting a password.

**Remediation:** Replace trust with scram-sha-256 or certificate authentication and scope the CIDR.

## CRITICAL · HETZ-PG-001 · Broad PostgreSQL trust authentication bypasses credentials

**Status:** confirmed  
**Confidence:** 0.99  
**Assets:** postgres:analytics

**Observation:** pg_hba.conf trusts a broad network range.

**Expected:** Remote database connections use authenticated, encrypted methods scoped to required clients.

**Actual:** HBA rule 0 uses trust for ::/0.

**Attack path:** ::/0 → postgres:analytics → postgres authentication

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** A reachable client can select an allowed database role without presenting a password.

**Remediation:** Replace trust with scram-sha-256 or certificate authentication and scope the CIDR.

## HIGH · HETZ-PG-002 · Unexpected PostgreSQL roles hold superuser capability

**Status:** confirmed  
**Confidence:** 0.93  
**Assets:** postgres:prod

**Observation:** Role inventory marks superuser roles outside the declared allowlist.

**Expected:** Only explicitly designated break-glass or administrative roles are superusers.

**Actual:** Unexpected superusers: ['app', 'migration'].

**Attack path:** database credentials → app → migration → postgres:prod

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** The roles can bypass database authorization and alter security-sensitive configuration.

**Remediation:** Revoke SUPERUSER and grant the minimum object and administrative privileges.

## CRITICAL · HETZ-RDS-001 · Redis accepts non-local clients without an authentication control

**Status:** confirmed  
**Confidence:** 0.99  
**Assets:** redis:prod

**Observation:** Broad bind, disabled protected mode, and absent ACL/password evidence coincide.

**Expected:** Redis is limited to trusted clients and requires a scoped ACL identity.

**Actual:** bind is broad; protected-mode=no; no authentication configured.

**Attack path:** reachable network peer → redis:prod → redis command surface

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** A client can read, alter, or destroy cached or persistent data.

**Remediation:** Bind to the required interface, enable protected mode, and configure least-privilege ACLs.

## MEDIUM · HETZ-VULN-001 · Vulnerable component in non-public workload

**Status:** confirmed  
**Confidence:** 0.84  
**Assets:** container:stage-worker

**Observation:** grype reports CVE-DEMO-0002 in openssl-demo.

**Expected:** Deployed components have no applicable high-impact known vulnerabilities.

**Actual:** Installed 2.0; fixed 2.1; internet_reachable=False.

**Attack path:** container:stage-worker → local vulnerable component

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** Impact depends on exploit preconditions; reachability changes priority but not vulnerable status.

**Remediation:** Upgrade to the fixed version and verify whether the affected component is loaded or reachable.

## MEDIUM · HETZ-VULN-001 · Vulnerable component in non-public workload

**Status:** confirmed  
**Confidence:** 0.84  
**Assets:** container:internal-api

**Observation:** trivy reports CVE-DEMO-0001 in libdemo.

**Expected:** Deployed components have no applicable high-impact known vulnerabilities.

**Actual:** Installed 1.0; fixed 1.1; internet_reachable=False.

**Attack path:** container:internal-api → local vulnerable component

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** Impact depends on exploit preconditions; reachability changes priority but not vulnerable status.

**Remediation:** Upgrade to the fixed version and verify whether the affected component is loaded or reachable.

## MEDIUM · HETZ-VULN-001 · Vulnerable component in non-public workload

**Status:** confirmed  
**Confidence:** 0.84  
**Assets:** container:ops-agent

**Observation:** trivy reports CVE-DEMO-0003 in curl-demo.

**Expected:** Deployed components have no applicable high-impact known vulnerabilities.

**Actual:** Installed 3.0; fixed 3.1; internet_reachable=False.

**Attack path:** container:ops-agent → local vulnerable component

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** Impact depends on exploit preconditions; reachability changes priority but not vulnerable status.

**Remediation:** Upgrade to the fixed version and verify whether the affected component is loaded or reachable.

## HIGH · HETZ-XLY-001 · staging workload can reach prod postgres

**Status:** confirmed  
**Confidence:** 0.96  
**Assets:** container:stage-worker, postgres:prod

**Observation:** A cross-environment attack-graph path contradicts an explicit isolation declaration.

**Expected:** staging and prod data planes are isolated.

**Actual:** A TCP/5432 path exists: container:stage-worker -> network:shared -> postgres:prod

**Attack path:** container:stage-worker → network:shared → postgres:prod

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** Compromise of a lower-trust environment can become unauthorized database or cache access.

**Remediation:** Separate environment networks and enforce target-side allowlists for the exact clients.

## HIGH · HETZ-XLY-001 · dev workload can reach prod redis

**Status:** confirmed  
**Confidence:** 0.96  
**Assets:** container:ops-agent, redis:prod

**Observation:** A cross-environment attack-graph path contradicts an explicit isolation declaration.

**Expected:** dev and prod data planes are isolated.

**Actual:** A TCP/6379 path exists: container:ops-agent -> network:shared -> redis:prod

**Attack path:** container:ops-agent → network:shared → redis:prod

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** Compromise of a lower-trust environment can become unauthorized database or cache access.

**Remediation:** Separate environment networks and enforce target-side allowlists for the exact clients.

## HIGH · HETZ-XLY-001 · staging workload can reach prod redis

**Status:** confirmed  
**Confidence:** 0.96  
**Assets:** container:stage-worker, redis:prod

**Observation:** A cross-environment attack-graph path contradicts an explicit isolation declaration.

**Expected:** staging and prod data planes are isolated.

**Actual:** A TCP/6379 path exists: container:stage-worker -> network:shared -> redis:prod

**Attack path:** container:stage-worker → network:shared → redis:prod

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** Compromise of a lower-trust environment can become unauthorized database or cache access.

**Remediation:** Separate environment networks and enforce target-side allowlists for the exact clients.

## HIGH · HETZ-XLY-001 · dev workload can reach prod postgres

**Status:** confirmed  
**Confidence:** 0.96  
**Assets:** container:ops-agent, postgres:prod

**Observation:** A cross-environment attack-graph path contradicts an explicit isolation declaration.

**Expected:** dev and prod data planes are isolated.

**Actual:** A TCP/5432 path exists: container:ops-agent -> network:shared -> postgres:prod

**Attack path:** container:ops-agent → network:shared → postgres:prod

**Verification:** Evidence is internally consistent and no observed compensating control refutes the path.

**Impact:** Compromise of a lower-trust environment can become unauthorized database or cache access.

**Remediation:** Separate environment networks and enforce target-side allowlists for the exact clients.

## MEDIUM · HETZ-BCP-001 · Production stateful asset lacks observed backup coverage

**Status:** needs_validation  
**Confidence:** 0.69  
**Assets:** postgres:prod

**Observation:** The asset is declared production and stateful, but no backup configuration is observed.

**Expected:** Production state has a tested, declared recovery mechanism.

**Actual:** backup_enabled=false or absent.

**Attack path:** postgres:prod → data loss → unrecoverable state

**Verification:** Absence evidence depends on complete collector coverage; validate the missing control with the owner.

**Impact:** Deletion, corruption, or compromise may cause unrecoverable service data loss.

**Remediation:** Enable provider or application-consistent backups and record a restore test.

## MEDIUM · HETZ-BCP-001 · Production stateful asset lacks observed backup coverage

**Status:** needs_validation  
**Confidence:** 0.69  
**Assets:** postgres:analytics

**Observation:** The asset is declared production and stateful, but no backup configuration is observed.

**Expected:** Production state has a tested, declared recovery mechanism.

**Actual:** backup_enabled=false or absent.

**Attack path:** postgres:analytics → data loss → unrecoverable state

**Verification:** Absence evidence depends on complete collector coverage; validate the missing control with the owner.

**Impact:** Deletion, corruption, or compromise may cause unrecoverable service data loss.

**Remediation:** Enable provider or application-consistent backups and record a restore test.

## MEDIUM · HETZ-BCP-001 · Production stateful asset lacks observed backup coverage

**Status:** needs_validation  
**Confidence:** 0.69  
**Assets:** redis:prod

**Observation:** The asset is declared production and stateful, but no backup configuration is observed.

**Expected:** Production state has a tested, declared recovery mechanism.

**Actual:** backup_enabled=false or absent.

**Attack path:** redis:prod → data loss → unrecoverable state

**Verification:** Absence evidence depends on complete collector coverage; validate the missing control with the owner.

**Impact:** Deletion, corruption, or compromise may cause unrecoverable service data loss.

**Remediation:** Enable provider or application-consistent backups and record a restore test.

## MEDIUM · HETZ-BCP-001 · Production stateful asset lacks observed backup coverage

**Status:** needs_validation  
**Confidence:** 0.69  
**Assets:** server:public-pg

**Observation:** The asset is declared production and stateful, but no backup configuration is observed.

**Expected:** Production state has a tested, declared recovery mechanism.

**Actual:** backup_enabled=false or absent.

**Attack path:** server:public-pg → data loss → unrecoverable state

**Verification:** Absence evidence depends on complete collector coverage; validate the missing control with the owner.

**Impact:** Deletion, corruption, or compromise may cause unrecoverable service data loss.

**Remediation:** Enable provider or application-consistent backups and record a restore test.

## MEDIUM · HETZ-BCP-001 · Production stateful asset lacks observed backup coverage

**Status:** needs_validation  
**Confidence:** 0.69  
**Assets:** server:public-redis

**Observation:** The asset is declared production and stateful, but no backup configuration is observed.

**Expected:** Production state has a tested, declared recovery mechanism.

**Actual:** backup_enabled=false or absent.

**Attack path:** server:public-redis → data loss → unrecoverable state

**Verification:** Absence evidence depends on complete collector coverage; validate the missing control with the owner.

**Impact:** Deletion, corruption, or compromise may cause unrecoverable service data loss.

**Remediation:** Enable provider or application-consistent backups and record a restore test.

## MEDIUM · HETZ-NET-005 · Internet-facing server has no observed firewall control

**Status:** needs_validation  
**Confidence:** 0.69  
**Assets:** server:no-firewall-a

**Observation:** A public interface exists, but neither an attached Hetzner firewall nor an observed host firewall is present.

**Expected:** Every public server has an independently evidenced ingress control.

**Actual:** Public IP present; firewall attachment and host firewall evidence absent.

**Attack path:** internet → server:no-firewall-a

**Verification:** Absence evidence depends on complete collector coverage; validate the missing control with the owner.

**Impact:** Services that bind broadly may be reachable without a network policy boundary.

**Remediation:** Attach a least-privilege Hetzner firewall or provide verified host-firewall evidence.

## MEDIUM · HETZ-NET-005 · Internet-facing server has no observed firewall control

**Status:** needs_validation  
**Confidence:** 0.69  
**Assets:** server:no-firewall-b

**Observation:** A public interface exists, but neither an attached Hetzner firewall nor an observed host firewall is present.

**Expected:** Every public server has an independently evidenced ingress control.

**Actual:** Public IP present; firewall attachment and host firewall evidence absent.

**Attack path:** internet → server:no-firewall-b

**Verification:** Absence evidence depends on complete collector coverage; validate the missing control with the owner.

**Impact:** Services that bind broadly may be reachable without a network policy boundary.

**Remediation:** Attach a least-privilege Hetzner firewall or provide verified host-firewall evidence.
