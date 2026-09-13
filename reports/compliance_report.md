# Continuous Compliance Assessment Report

> Portfolio simulation using fictional evidence. Automated results are indicators, not an official CMMC determination.

## Executive snapshot

- Checks evaluated: **7**
- PASS: **2**
- FAIL: **5**

## Findings

### FAIL - AC.L2-3.1.1 - Authorized system access

- **NIST SP 800-171 Rev. 2:** 3.1.1
- **Severity:** HIGH
- **Evidence:** EV-ID-2026-09-13 - Simulated Microsoft Entra ID export
- **Rationale:** 1 enabled account(s) are associated with non-active personnel.
- **Affected:** former.contractor@frdc.example
- **Remediation:** Disable or formally reauthorize the accounts, validate the identity lifecycle process, and preserve closure evidence.

### FAIL - AC.L2-3.1.5 - Least privilege for privileged access

- **NIST SP 800-171 Rev. 2:** 3.1.5
- **Severity:** HIGH
- **Evidence:** EV-ID-2026-09-13 - Simulated Microsoft Entra ID export
- **Rationale:** 1 privileged assignment(s) exceeded the fictional 30-day inactivity threshold.
- **Affected:** stale.admin@frdc.example
- **Remediation:** Review business need, remove unnecessary standing privilege, and document approval for any retained privileged access.

### FAIL - IA.L2-3.5.3 - Multifactor authentication

- **NIST SP 800-171 Rev. 2:** 3.5.3
- **Severity:** CRITICAL
- **Evidence:** EV-ID-2026-09-13 - Simulated Microsoft Entra ID export
- **Rationale:** 1 enabled privileged account(s) lack MFA registration evidence.
- **Affected:** daniel.ross@frdc.example
- **Remediation:** Require MFA for the affected privileged accounts and verify enforcement through Conditional Access or equivalent controls.

### FAIL - AU.L2-3.3.1 - System auditing

- **NIST SP 800-171 Rev. 2:** 3.3.1
- **Severity:** HIGH
- **Evidence:** EV-AU-2026-09-13 - Simulated Azure / Sentinel logging export
- **Rationale:** One or more required logging sources do not meet the fictional organization's defined logging/retention policy.
- **Affected:** DefenderAlerts: retention 30d < policy 90d
- **Remediation:** Enable the required log sources and align configured retention with the organization's approved audit-retention policy.

### PASS - SC.L2-3.13.16 - CUI confidentiality at rest - endpoint encryption signal

- **NIST SP 800-171 Rev. 2:** 3.13.16
- **Severity:** CRITICAL
- **Evidence:** EV-SEC-2026-09-13 - Simulated Intune / Defender / Azure network export
- **Rationale:** All in-scope sample devices have disk-encryption evidence.
- **Affected:** None
- **Remediation:** Continue monitoring encryption compliance and investigate configuration drift.

### PASS - SI.L2-3.14.2 - Malicious code protection - endpoint protection signal

- **NIST SP 800-171 Rev. 2:** 3.14.2
- **Severity:** HIGH
- **Evidence:** EV-SEC-2026-09-13 - Simulated Intune / Defender / Azure network export
- **Rationale:** All in-scope sample devices report endpoint-protection enabled.
- **Affected:** None
- **Remediation:** Continue health monitoring, signature/platform updates, and exception review.

### FAIL - SC.L2-3.13.1 - Boundary protection - public administrative exposure signal

- **NIST SP 800-171 Rev. 2:** 3.13.1
- **Severity:** CRITICAL
- **Evidence:** EV-SEC-2026-09-13 - Simulated Intune / Defender / Azure network export
- **Rationale:** Public inbound administrative exposure was identified in the sample network-rule evidence.
- **Affected:** nsg-cui-admin: public inbound port 3389
- **Remediation:** Remove direct public administrative exposure, use approved controlled administration paths, and document any time-bound exception with compensating controls.

## Human review required

Automated checks can improve evidence freshness and repeatability, but a CMMC assessment requires evaluation of applicable assessment objectives and may require examine, interview, and test evidence beyond these signals.
