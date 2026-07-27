# SOC Case File — ACME Steel
**Case ID:** CASE-2026-0727-001
**Created:** 2026-07-27 02:14 UTC
**Analyst:** Autonomous SOC Investigation Agent
**Verdict:** 🔴 ESCALATE

---

## Alert Summary
| Field | Detail |
|---|---|
| Rule Triggered | Multiple failed SSH logins followed by success |
| Source IP | 203.0.113.47 |
| Destination Host | prod-db-01 |
| Failed Attempts | 47 in 90 seconds |
| Outcome | Successful authentication as `svc_backup` |
| Time | 2026-07-27 02:14 UTC |

---

## Investigation Findings

### 1. Source IP Reputation — 203.0.113.47
- **Verdict: MALICIOUS**
- Flagged as a known brute-force source in threat intelligence feeds
- Associated with **3 prior incidents** at ACME Steel
- This IP has a documented history of adversarial activity against the organisation

### 2. Destination Asset — prod-db-01
- **Criticality: HIGH**
- Role: **Production Customer Database**
- Owner: **Data Platform Team**
- Compromise of this host could result in exposure of customer PII/financial data, regulatory breach (GDPR, PCI-DSS), and significant operational disruption

---

## Attack Chain Assessment

The evidence is consistent with a **successful SSH brute-force attack**:

1. **Credential stuffing / brute-force:** 47 failed login attempts in 90 seconds indicates automated tooling
2. **Successful breach:** Attacker authenticated as `svc_backup` — a service account, which may have weaker password controls and broad data-access privileges
3. **Off-hours timing:** 02:14 UTC is outside normal business hours, a classic indicator of adversarial activity attempting to avoid detection
4. **Repeat offender IP:** The source has been seen in 3 prior ACME incidents, suggesting a persistent, targeted threat actor

### Key Risk: `svc_backup` Account
Service accounts used for backup operations typically have:
- Read access to **all** database contents
- Possible write/delete permissions
- Credentials that are rarely rotated

Immediate containment is critical before data exfiltration or destruction can occur.

---

## Recommended Immediate Actions

1. 🔴 **BLOCK** 203.0.113.47 at the perimeter firewall immediately
2. 🔴 **TERMINATE** the active SSH session on prod-db-01 for `svc_backup`
3. 🔴 **DISABLE / ROTATE** credentials for the `svc_backup` account
4. 🔴 **ISOLATE** prod-db-01 from the network pending forensic review if active post-exploitation activity is detected
5. 🟠 **FORENSICS:** Review auth logs, bash history, and database query logs on prod-db-01 for post-login activity
6. 🟠 **NOTIFY:** Data Platform Team owner and CISO/IR lead immediately
7. 🟠 **REVIEW:** All other systems where `svc_backup` credentials are used
8. 🟡 **THREAT HUNT:** Scan for lateral movement from prod-db-01 to other internal hosts

---

## Verdict Rationale
**ESCALATE** — Confirmed malicious source IP with prior incident history successfully breached a HIGH criticality production database server via brute-force during off-hours. Active incident response must be initiated without delay.
