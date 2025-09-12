<img width="500" height="500" alt="Keydra_1024" src="https://github.com/user-attachments/assets/eff841b4-b4d6-4b7f-8226-1e6c318ddfaa" />
<img width="500" height="500" alt="Aegis_1024" src="https://github.com/user-attachments/assets/189fb8a6-e981-40d3-a9da-2acc889e6394" />

# Keydra & Aegis

Keydra and its companion tool Aegis provide secure, lightweight secrets and certificate management for both hosts and clients.

Keydra → Secrets Vault & Rotation  
Aegis → Certificates & SSH Management

---

## Keydra Features
Keydra is a secrets vault that can store and rotate API keys, tokens, passwords, and keys.  
Planned and supported features include:  
- Dynamic secrets → Generate short-lived DB credentials, cloud access keys, and tokens on demand.  
- Pluggable storage backends → File, SQLite, PostgreSQL, or distributed KV stores (Consul, etcd).  
- Access control policies → Role-based access control (RBAC) and fine-grained permissions.  
- Audit logging → Every secret access, issuance, and rotation event is logged.  
- CLI + API support → Use through command line or REST API.  
- Secret injection → Inject secrets into environment variables or files without exposing them directly.  
- Rotation hooks → Trigger webhooks or scripts when secrets rotate.  
- Kubernetes integration → Inject secrets into pods (CSI driver/sidecar planned).  

---

## Aegis Features
Aegis is a certificates management platform, designed to renew, monitor, and issue certificates, and to support SSH certificate authorities (CAs).  
Planned and supported features include:  
- Automatic certificate renewal (similar to Let’s Encrypt).  
- ACME protocol support for TLS certificates.  
- SSH CA tooling  
  - Issue short-lived SSH certs.  
  - Role-based SSH access (student vs. admin).  
  - Expiry and revocation.  
- PKI management  
  - Bootstrap small CAs.  
  - Issue and revoke X.509 certificates.  
  - Manage CRLs (certificate revocation lists).  
- Certificate monitoring → Alerts/logs when certs are near expiration.  
- Multi-tenancy → Isolated CAs and policies for multiple labs, teams, or environments.  

---

## Roadmap
- API auditing & dashboards (Grafana/Prometheus integration).  
- Pluggable authentication backends (LDAP, OIDC, GitHub login).  
- Competition / CTF mode → Sandbox for teams to practice attacking and defending secrets systems.  
- Lightweight deployment → Easy to run locally or in lab environments.
