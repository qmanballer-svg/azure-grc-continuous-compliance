# Portfolio Overview

This project demonstrates a practical **GRC engineering / continuous compliance** pattern: take machine-readable cloud-security evidence, evaluate repeatable control signals, map results to control objectives, and produce findings that a human GRC or security reviewer can investigate and remediate.

## Five-minute review path

1. [`README.md`](README.md) — purpose, architecture, and mapped controls.
2. [`src/compliance_engine.py`](src/compliance_engine.py) — the Python control-check engine.
3. [`data/sample/`](data/sample/) — simulated identity, logging, endpoint, and network evidence.
4. [`mappings/control_map.json`](mappings/control_map.json) — mapping from automated rules to CMMC / NIST SP 800-171 Rev. 2.
5. [`reports/control_coverage_matrix.csv`](reports/control_coverage_matrix.csv) — what each check can and cannot prove.
6. [`evidence/generated/findings.json`](evidence/generated/findings.json) — machine-readable findings.
7. [`reports/compliance_report.md`](reports/compliance_report.md) — human-readable assessment output.
8. [`docs/assurance_model.md`](docs/assurance_model.md) — design vs. implementation vs. operating effectiveness vs. final control conclusion.
9. [`.github/workflows/validate.yml`](.github/workflows/validate.yml) — automated unit-test and assessment validation.

## Current demo coverage

The current version evaluates seven signals across:

- authorized account lifecycle;
- privileged-access hygiene;
- privileged MFA;
- audit logging and retention;
- endpoint encryption;
- endpoint protection; and
- public administrative network exposure.

The sample intentionally produces both passing and failing signals so reviewers can see how the pipeline behaves in each case.

## What this demonstrates

- Python-based compliance automation;
- evidence provenance and normalized data models;
- control-to-technical-signal mapping;
- repeatable testing rather than screenshot-only evidence;
- machine-readable JSON / CSV findings;
- executive-readable reporting;
- unit tests and CI validation;
- explicit separation between an automated signal and an auditor/assessor conclusion;
- a roadmap from offline sample data to Microsoft Graph, Azure Resource Graph, Azure Policy, Defender for Cloud, and Sentinel/Log Analytics.

## Why this matters for GRC

Many controls contain repetitive evidence checks that can be evaluated more frequently than a quarterly or annual manual review. Automating those checks can improve evidence freshness and identify drift earlier, while human reviewers retain responsibility for scope, control design, evidence sufficiency, exceptions, compensating controls, risk acceptance, and final conclusions.

This repository is a fictional portfolio simulation. It contains no live credentials, customer data, or production evidence.
