# Five-Minute Demo Walkthrough

## 1. Start with the business problem

Periodic GRC reviews often rely on point-in-time screenshots and manual evidence gathering. This project shows how selected cloud-security checks can be evaluated repeatedly from structured evidence while preserving reviewer judgment.

## 2. Show the evidence inputs

Open `data/sample/`:

- `identity_evidence.json` represents an Entra identity export;
- `audit_evidence.json` represents logging / retention state; and
- `security_evidence.json` represents endpoint and network-security state.

Each source includes an evidence identifier, source, timestamp, policy assumptions, and the objects evaluated.

## 3. Show the control mapping

Open `mappings/control_map.json`.

The automation is not claiming that a single technical state equals full framework compliance. Each rule is explicitly mapped to the control objective it supports so the reviewer can understand why the signal matters.

## 4. Run the assessment

```bash
python run_assessment.py
```

Expected portfolio result:

```text
Assessment complete: 2 PASS / 5 FAIL
```

The demo intentionally contains both passing and failing signals.

## 5. Show a failed signal

The sample identity evidence contains a terminated contractor account that remains enabled. The engine generates a failed authorized-access signal and records:

- mapped control;
- evidence source;
- rationale;
- affected object;
- severity; and
- recommended remediation.

This illustrates the difference between simply finding a technical condition and creating a remediation-ready GRC finding.

## 6. Show a passing signal

The sample endpoints all report disk encryption enabled, so the endpoint-encryption signal passes. The documentation still explains that the signal alone does not prove the full confidentiality-at-rest control objective because other storage locations, key management, scope, and operating evidence may also matter.

## 7. Show the boundary-protection finding

The sample network evidence includes public inbound RDP (`3389`) to an administrative resource. The rule flags it as a boundary-protection signal requiring investigation and removal or documented exception handling.

## 8. Show assurance boundaries

Open `docs/assurance_model.md` and `reports/control_coverage_matrix.csv`.

The important GRC-engineering concept is that automation can improve **frequency and consistency** without replacing human judgment about:

- control design;
- scope;
- evidence sufficiency;
- exceptions and compensating controls;
- operating effectiveness; and
- final compliance conclusions.

## 9. Show validation

Run:

```bash
python -m unittest discover -s tests -v
```

The unit tests validate the expected number of checks, expected failures, expected passes, and presence of framework mappings. GitHub Actions runs the tests and assessment automatically on repository activity.

## 10. Explain the production roadmap

The safe portfolio version uses offline JSON evidence. A production-style next step would replace those files with read-only collectors from Microsoft Graph, Azure Resource Graph, Azure Policy, Defender for Cloud, and Log Analytics / Sentinel while adding identity, secrets, provenance, historical snapshots, and exception workflows.
