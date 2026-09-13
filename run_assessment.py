from __future__ import annotations

import csv
import json
from pathlib import Path

from src.compliance_engine import evaluate

ROOT = Path(__file__).resolve().parent


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def main() -> None:
    identity = load_json(ROOT / "data/sample/identity_evidence.json")
    audit = load_json(ROOT / "data/sample/audit_evidence.json")
    security = load_json(ROOT / "data/sample/security_evidence.json")
    mappings = load_json(ROOT / "mappings/control_map.json")

    findings = evaluate(identity, audit, security, mappings)
    rows = [f.to_dict() for f in findings]

    evidence_dir = ROOT / "evidence/generated"
    report_dir = ROOT / "reports"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    with (evidence_dir / "findings.json").open("w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)

    csv_fields = [
        "check_id", "status", "cmmc", "nist_800_171_rev2", "title", "severity",
        "evidence_id", "evidence_source", "rationale", "affected_objects", "remediation"
    ]
    with (report_dir / "findings.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=csv_fields)
        writer.writeheader()
        for row in rows:
            row = dict(row)
            row["affected_objects"] = "; ".join(row["affected_objects"])
            writer.writerow(row)

    failures = [r for r in rows if r["status"] == "FAIL"]
    passes = [r for r in rows if r["status"] == "PASS"]

    lines = [
        "# Continuous Compliance Assessment Report",
        "",
        "> Portfolio simulation using fictional evidence. Automated results are indicators, not an official CMMC determination.",
        "",
        "## Executive snapshot",
        "",
        f"- Checks evaluated: **{len(rows)}**",
        f"- PASS: **{len(passes)}**",
        f"- FAIL: **{len(failures)}**",
        "",
        "## Findings",
        "",
    ]

    for r in rows:
        lines += [
            f"### {r['status']} - {r['cmmc']} - {r['title']}",
            "",
            f"- **NIST SP 800-171 Rev. 2:** {r['nist_800_171_rev2']}",
            f"- **Severity:** {r['severity'].upper()}",
            f"- **Evidence:** {r['evidence_id']} - {r['evidence_source']}",
            f"- **Rationale:** {r['rationale']}",
            f"- **Affected:** {', '.join(r['affected_objects']) if r['affected_objects'] else 'None'}",
            f"- **Remediation:** {r['remediation']}",
            "",
        ]

    lines += [
        "## Human review required",
        "",
        "Automated checks can improve evidence freshness and repeatability, but a CMMC assessment requires evaluation of applicable assessment objectives and may require examine, interview, and test evidence beyond these signals.",
        "",
    ]

    (report_dir / "compliance_report.md").write_text("\n".join(lines), encoding="utf-8")

    print(f"Assessment complete: {len(passes)} PASS / {len(failures)} FAIL")
    print("Generated evidence/generated/findings.json")
    print("Generated reports/findings.csv")
    print("Generated reports/compliance_report.md")


if __name__ == "__main__":
    main()
