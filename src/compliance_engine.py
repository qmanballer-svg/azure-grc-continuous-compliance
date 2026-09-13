from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Dict, List


@dataclass
class Finding:
    check_id: str
    status: str
    cmmc: str
    nist_800_171_rev2: str
    title: str
    severity: str
    evidence_id: str
    evidence_source: str
    rationale: str
    affected_objects: List[str]
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _base(mapping: Dict[str, str], evidence: Dict[str, Any], check_id: str) -> Dict[str, Any]:
    return {
        "check_id": check_id,
        "cmmc": mapping["cmmc"],
        "nist_800_171_rev2": mapping["nist_800_171_rev2"],
        "title": mapping["title"],
        "severity": mapping["severity"],
        "evidence_id": evidence["evidence_id"],
        "evidence_source": evidence["source"],
    }


def check_authorized_accounts(identity: Dict[str, Any], mapping: Dict[str, str]) -> Finding:
    offenders = [
        u["user_principal_name"]
        for u in identity["users"]
        if u["account_enabled"] and u["employment_status"] != "active"
    ]
    base = _base(mapping, identity, "authorized_account_status")
    if offenders:
        return Finding(**base, status="FAIL", rationale=f"{len(offenders)} enabled account(s) are associated with non-active personnel.", affected_objects=offenders, remediation="Disable or formally reauthorize the accounts, validate the identity lifecycle process, and preserve closure evidence.")
    return Finding(**base, status="PASS", rationale="All enabled accounts in the sample belong to active personnel.", affected_objects=[], remediation="Continue periodic identity reconciliation and retain evidence of completed reviews.")


def check_privileged_least_privilege(identity: Dict[str, Any], mapping: Dict[str, str]) -> Finding:
    threshold = identity["policy"]["privileged_inactivity_threshold_days"]
    offenders = [u["user_principal_name"] for u in identity["users"] if u["privileged"] and isinstance(u.get("days_since_privileged_use"), int) and u["days_since_privileged_use"] > threshold]
    base = _base(mapping, identity, "privileged_least_privilege")
    if offenders:
        return Finding(**base, status="FAIL", rationale=f"{len(offenders)} privileged assignment(s) exceeded the fictional {threshold}-day inactivity threshold.", affected_objects=offenders, remediation="Review business need, remove unnecessary standing privilege, and document approval for any retained privileged access.")
    return Finding(**base, status="PASS", rationale="No privileged assignments exceeded the fictional inactivity threshold.", affected_objects=[], remediation="Continue periodic privileged-access recertification.")


def check_privileged_mfa(identity: Dict[str, Any], mapping: Dict[str, str]) -> Finding:
    offenders = [u["user_principal_name"] for u in identity["users"] if u["privileged"] and u["account_enabled"] and not u["mfa_registered"]]
    base = _base(mapping, identity, "privileged_mfa")
    if offenders:
        return Finding(**base, status="FAIL", rationale=f"{len(offenders)} enabled privileged account(s) lack MFA registration evidence.", affected_objects=offenders, remediation="Require MFA for the affected privileged accounts and verify enforcement through Conditional Access or equivalent controls.")
    return Finding(**base, status="PASS", rationale="All enabled privileged accounts have MFA registration evidence.", affected_objects=[], remediation="Continue monitoring MFA registration and enforcement coverage.")


def check_audit_logging(audit: Dict[str, Any], mapping: Dict[str, str]) -> Finding:
    required = set(audit["policy"]["required_log_sources"])
    defined_retention = int(audit["policy"]["defined_retention_days"])
    sources = {item["name"]: item for item in audit["log_sources"]}
    problems: List[str] = []
    for name in sorted(required):
        item = sources.get(name)
        if item is None:
            problems.append(f"{name}: missing")
            continue
        if not item.get("enabled", False):
            problems.append(f"{name}: disabled")
        elif int(item.get("retention_days", 0)) < defined_retention:
            problems.append(f"{name}: retention {item.get('retention_days', 0)}d < policy {defined_retention}d")
    base = _base(mapping, audit, "audit_logging_retention")
    if problems:
        return Finding(**base, status="FAIL", rationale="One or more required logging sources do not meet the fictional organization's defined logging/retention policy.", affected_objects=problems, remediation="Enable the required log sources and align configured retention with the organization's approved audit-retention policy.")
    return Finding(**base, status="PASS", rationale="All required sample log sources are enabled and meet the fictional organization's defined retention policy.", affected_objects=[], remediation="Continue validating log-source coverage, content, retention, access protection, and review procedures.")


def check_endpoint_encryption(security: Dict[str, Any], mapping: Dict[str, str]) -> Finding:
    offenders = [d["device_name"] for d in security["devices"] if d.get("in_scope") and not d.get("disk_encrypted", False)]
    base = _base(mapping, security, "endpoint_encryption")
    if offenders:
        return Finding(**base, status="FAIL", rationale=f"{len(offenders)} in-scope device(s) lack endpoint disk-encryption evidence.", affected_objects=offenders, remediation="Enable approved encryption, escrow recovery material appropriately, verify device compliance, and retain configuration evidence.")
    return Finding(**base, status="PASS", rationale="All in-scope sample devices have disk-encryption evidence.", affected_objects=[], remediation="Continue monitoring encryption compliance and investigate configuration drift.")


def check_endpoint_protection(security: Dict[str, Any], mapping: Dict[str, str]) -> Finding:
    offenders = [d["device_name"] for d in security["devices"] if d.get("in_scope") and not d.get("endpoint_protection_enabled", False)]
    base = _base(mapping, security, "endpoint_protection")
    if offenders:
        return Finding(**base, status="FAIL", rationale=f"{len(offenders)} in-scope device(s) lack endpoint-protection evidence.", affected_objects=offenders, remediation="Enable approved anti-malware/endpoint protection, validate health reporting, and investigate exclusions or degraded sensors.")
    return Finding(**base, status="PASS", rationale="All in-scope sample devices report endpoint-protection enabled.", affected_objects=[], remediation="Continue health monitoring, signature/platform updates, and exception review.")


def check_public_admin_exposure(security: Dict[str, Any], mapping: Dict[str, str]) -> Finding:
    forbidden = {int(p) for p in security["policy"]["forbidden_public_inbound_ports"]}
    offenders = []
    for rule in security["network_rules"]:
        if rule.get("direction") == "Inbound" and rule.get("action") == "Allow" and rule.get("source") in {"0.0.0.0/0", "*", "Internet"} and int(rule.get("destination_port", -1)) in forbidden:
            offenders.append(f"{rule['resource']}: public inbound port {rule['destination_port']}")
    base = _base(mapping, security, "public_admin_exposure")
    if offenders:
        return Finding(**base, status="FAIL", rationale="Public inbound administrative exposure was identified in the sample network-rule evidence.", affected_objects=offenders, remediation="Remove direct public administrative exposure, use approved controlled administration paths, and document any time-bound exception with compensating controls.")
    return Finding(**base, status="PASS", rationale="No sample network rule exposes the defined administrative ports directly to the public internet.", affected_objects=[], remediation="Continue continuous rule evaluation and periodic boundary reviews.")


def evaluate(identity: Dict[str, Any], audit: Dict[str, Any], security: Dict[str, Any], mappings: Dict[str, Dict[str, str]]) -> List[Finding]:
    return [
        check_authorized_accounts(identity, mappings["authorized_account_status"]),
        check_privileged_least_privilege(identity, mappings["privileged_least_privilege"]),
        check_privileged_mfa(identity, mappings["privileged_mfa"]),
        check_audit_logging(audit, mappings["audit_logging_retention"]),
        check_endpoint_encryption(security, mappings["endpoint_encryption"]),
        check_endpoint_protection(security, mappings["endpoint_protection"]),
        check_public_admin_exposure(security, mappings["public_admin_exposure"]),
    ]
