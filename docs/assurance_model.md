# Automated Assurance Model

## Purpose

This project treats automation as an **assurance signal**, not as a substitute for control-owner accountability or assessor judgment.

A continuous-compliance check can answer a narrow technical question repeatedly and consistently—for example, whether an enabled privileged account lacks MFA evidence—but the broader control conclusion may depend on policy, scope, architecture, interviews, exception handling, and additional testing.

## Four assurance layers

### 1. Control design

Does the organization have a control that, if performed as intended, is capable of reducing the relevant risk?

Examples:
- an approved identity-lifecycle process;
- a requirement for MFA;
- a logging and retention standard;
- a defined boundary-security standard.

Automation normally cannot prove control design by itself.

### 2. Implementation

Is the control configured or deployed in the environment?

Examples:
- MFA is configured for privileged identities;
- endpoint protection is enabled;
- disk encryption is active;
- required log sources are connected.

Automation is often strong at checking implementation state.

### 3. Operating effectiveness

Did the control operate consistently over the required period and population?

Examples:
- all terminations were disabled on time;
- all privileged accounts were reviewed quarterly;
- no required log source fell below retention policy during the period;
- exceptions were approved and expired correctly.

Operating effectiveness usually requires historical evidence, sampling, event history, or trend data beyond a point-in-time configuration snapshot.

### 4. Control conclusion

Can a reviewer conclude that the applicable control objective is satisfied?

This requires considering all applicable evidence and assessment objectives. A technical `PASS` in this repository means only that the **specific automated rule passed for the evidence evaluated**. It does not represent an official CMMC `MET` determination.

## Evidence-quality dimensions

Every automated evidence source should be evaluated for:

- **relevance** — does it actually address the control objective?
- **reliability** — is the source authoritative and protected from inappropriate alteration?
- **completeness** — does it cover the full in-scope population and assessment period?
- **timeliness** — is it recent enough for the intended conclusion?
- **traceability** — can a reviewer reproduce where it came from and how it was evaluated?

## Exceptions

A failed automated check should not automatically trigger a final compliance conclusion. The result may represent:

1. a true control deficiency;
2. an approved and time-bound exception;
3. a scoping error;
4. stale or incomplete evidence;
5. a false positive in the evaluation rule; or
6. an alternative implementation that requires human review.

A production workflow should therefore route exceptions to a documented owner and preserve the final disposition.

## Continuous-monitoring principle

The objective is not to automate every GRC decision. The objective is to move repetitive, high-volume, machine-verifiable evidence checks from periodic manual review toward **continuous or higher-frequency assurance**, leaving human reviewers to focus on judgment, exceptions, risk acceptance, control design, and remediation decisions.
