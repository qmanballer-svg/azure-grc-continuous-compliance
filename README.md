# Azure GRC Continuous Compliance Monitor

A hands-on **GRC engineering** portfolio project that demonstrates how cloud security evidence can be collected, normalized, evaluated, mapped to control objectives, and turned into remediation-ready findings.

> **Portfolio simulation:** The sample tenant, users, configurations, evidence, findings, and risk data are fictional. No real employer, customer, government, CUI, confidential, or proprietary information is included.

## Start here

For a fast project review, see [`PORTFOLIO_OVERVIEW.md`](PORTFOLIO_OVERVIEW.md). For a practical walkthrough of how to explain and demonstrate the project, see [`docs/demo_walkthrough.md`](docs/demo_walkthrough.md).

## Why this project exists

Traditional GRC often relies on screenshots, interviews, spreadsheets, and periodic manual testing. This project shows how part of that workflow can be automated while preserving human review and evidence traceability.

The demo implements this pipeline:

**cloud evidence → normalization → automated checks → control mapping → findings → remediation report**

## What it demonstrates

- GRC engineering and continuous-control-monitoring concepts
- Python-based compliance automation
- Azure / Microsoft security evidence modeling
- CMMC Level 2 / NIST SP 800-171 Rev. 2 control mapping
- evidence traceability and machine-readable findings
- risk-aware remediation reporting
- unit testing and GitHub Actions validation
- separation between automated checks and assessor judgment
- design vs. implementation vs. operating-effectiveness thinking

## Demo controls

The current demo evaluates seven evidence-driven checks:

| Check | Portfolio mapping | What the automation evaluates |
|---|---|---|
| Authorized account status | AC.L2-3.1.1 / NIST 3.1.1 | Enabled accounts must belong to active personnel |
| Privileged least privilege | AC.L2-3.1.5 / NIST 3.1.5 | Stale privileged role assignments are flagged |
| Privileged MFA | IA.L2-3.5.3 / NIST 3.5.3 | Enabled privileged users must have MFA-registration evidence |
| Audit logging & retention | AU.L2-3.3.1 / NIST 3.3.1 | Required log sources are enabled and meet the fictional retention standard |
| Endpoint encryption | SC.L2-3.13.16 / NIST 3.13.16 | In-scope sample endpoints report disk-encryption evidence |
| Endpoint protection | SI.L2-3.14.2 / NIST 3.14.2 | In-scope sample endpoints report endpoint protection enabled |
| Public admin exposure | SC.L2-3.13.1 / NIST 3.13.1 | Defined administrative ports are checked for direct public exposure |

The current sample produces **2 PASS / 5 FAIL** signals so reviewers can see both compliant-state and exception/finding behavior.

**Important:** An automated PASS does not by itself establish that a CMMC requirement is MET. CMMC assessment objectives may require examine, interview, and test evidence beyond what a single automated signal can prove.

## Repository structure

```text
.
├── README.md
├── PORTFOLIO_OVERVIEW.md
├── DISCLAIMER.md
├── run_assessment.py
├── src/
│   └── compliance_engine.py
├── data/sample/
│   ├── identity_evidence.json
│   ├── audit_evidence.json
│   └── security_evidence.json
├── mappings/
│   └── control_map.json
├── evidence/generated/
│   └── findings.json
├── reports/
│   ├── compliance_report.md
│   ├── findings.csv
│   └── control_coverage_matrix.csv
├── docs/
│   ├── architecture.md
│   ├── evidence_model.md
│   ├── assurance_model.md
│   ├── demo_walkthrough.md
│   └── roadmap.md
├── tests/
│   └── test_engine.py
└── .github/workflows/
    └── validate.yml
```

## Run the demo

Requires Python 3.10+ and no third-party packages.

```bash
python run_assessment.py
```

Then review:

- `evidence/generated/findings.json`
- `reports/findings.csv`
- `reports/compliance_report.md`
- `reports/control_coverage_matrix.csv`

Run tests:

```bash
python -m unittest discover -s tests -v
```

## Sample environment

The fictional environment represents a Microsoft-centric CUI enclave using:

- Microsoft Entra ID
- Azure
- Microsoft 365
- Microsoft Intune-style endpoint state
- Microsoft Defender
- Microsoft Sentinel / centralized logging

The current version intentionally uses **offline exported JSON evidence** so the repository can be reviewed safely without cloud credentials. The roadmap documents how the same checks could later be connected to Microsoft Graph, Azure Resource Graph, Azure Policy, Defender for Cloud, and Log Analytics.

## Assessment philosophy

Automation is used to improve repeatability and evidence freshness, not to replace assessor judgment. Each finding records:

- check ID
- mapped practice / requirement
- evidence source
- evaluation result
- rationale
- affected objects
- severity
- remediation recommendation

The project also documents the assurance boundary between **control design, technical implementation, operating effectiveness, and the final control conclusion** in [`docs/assurance_model.md`](docs/assurance_model.md).

## Framework note

CMMC Level 2 currently maps to the 110 security requirements in NIST SP 800-171 Rev. 2. NIST SP 800-171 Rev. 3 is the newer NIST publication, so real organizations should verify contractual and CMMC applicability before selecting the governing baseline.

## Author

**Qasim Shirazi**  
Cybersecurity GRC | Cloud Security Governance | GRC Engineering

## References

- DoD CMMC resources: https://dodcio.defense.gov/CMMC/Resources-Documentation/
- NIST SP 800-171 Rev. 2: https://csrc.nist.gov/pubs/sp/800/171/r2/upd1/final
- NIST SP 800-171 Rev. 3: https://csrc.nist.gov/pubs/sp/800/171/r3/final
