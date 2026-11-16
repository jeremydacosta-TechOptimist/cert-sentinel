"""Rule engine for certificate expiry and configuration audits.

Rules are pure functions of a :class:`~certsentinel.x509.Certificate`, the audit
time and an optional expected hostname. Every finding carries a stable rule id,
a severity, the certificate subject and fingerprint prefix, and a human-readable
message. Inventory-wide rules (duplicates and missing issuer certificates) run
once over the complete set so a single-file scan still produces useful output.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence, Tuple

from .x509 import Certificate, LoadError

__all__ = [
    "SEVERITY_ERROR",
    "SEVERITY_WARNING",
    "SEVERITY_NOTICE",
    "SEVERITY_INFO",
    "SEVERITIES",
    "SEVERITY_ORDER",
    "Finding",
    "AuditResult",
    "matches_hostname",
    "check_certificate",
    "check_inventory",
    "audit",
    "fail_on_matches",
]

SEVERITY_ERROR = "error"
SEVERITY_WARNING = "warning"
SEVERITY_NOTICE = "notice"
SEVERITY_INFO = "info"
SEVERITIES: Tuple[str, ...] = (SEVERITY_ERROR, SEVERITY_WARNING, SEVERITY_NOTICE, SEVERITY_INFO)
SEVERITY_ORDER: Dict[str, int] = {
    SEVERITY_INFO: 0,
    SEVERITY_NOTICE: 1,
    SEVERITY_WARNING: 2,
    SEVERITY_ERROR: 3,
}

EXPIRING_WARNING_DAYS = 30
EXPIRING_NOTICE_DAYS = 90
LONG_VALIDITY_DAYS = 398
MIN_RSA_BITS = 2048
MAX_SAN_DISPLAY = 6


@dataclass(frozen=True)
class Finding:
    """One rule violation for one certificate."""

    rule_id: str
    severity: str
    subject: str
    fingerprint: str
    message: str

    def to_dict(self) -> Dict[str, str]:
        """JSON-friendly representation."""

        return {
            "rule": self.rule_id,
            "severity": self.severity,
            "subject": self.subject,
            "fingerprint": self.fingerprint,
            "message": self.message,
        }


@dataclass
class AuditResult:
    """Certificates plus the findings produced by the rule engine."""

    certificates: List[Certificate]
    findings: List[Finding]
    generated_at: datetime
    load_errors: List[LoadError] = field(default_factory=list)

    @property
    def counts(self) -> Dict[str, int]:
        """Finding counts for every severity, including zeros."""

        counts = {severity: 0 for severity in SEVERITIES}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    @property
    def finding_count(self) -> int:
        """Total number of findings."""

        return len(self.findings)

    @property
    def max_severity(self) -> Optional[str]:
        """Highest severity present, or None when there are no findings."""

        if not self.findings:
            return None
        return max((finding.severity for finding in self.findings), key=lambda s: SEVERITY_ORDER[s])

    def has_findings_at_or_above(self, fail_on: str) -> bool:
        """True when a finding is at or above the ``fail_on`` threshold."""

        return _threshold_rank(fail_on) is not None and any(
            SEVERITY_ORDER[finding.severity] >= _threshold_rank(fail_on)
            for finding in self.findings
        )


def _threshold_rank(fail_on: str) -> Optional[int]:
    normalized = fail_on.strip().lower()
    if normalized == "none":
        return None
    if normalized in (SEVERITY_ERROR, SEVERITY_WARNING):
        return SEVERITY_ORDER[normalized]
    raise ValueError(f"unsupported fail-on threshold {fail_on!r}")


def fail_on_matches(result: AuditResult, fail_on: str) -> bool:
    """Convenience wrapper around :meth:`AuditResult.has_findings_at_or_above`."""

    return result.has_findings_at_or_above(fail_on)


def _display_subject(certificate: Certificate) -> str:
    cn = certificate.subject_cn
    if cn:
        return cn
    text = str(certificate.subject)
    return text or "(empty subject)"


def _finding(
    rule_id: str, severity: str, certificate: Certificate, message: str
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        subject=_display_subject(certificate),
        fingerprint=certificate.fingerprint_prefix,
        message=message,
    )


def _format_time(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%d %H:%M UTC")


def _match_dns_name(pattern: str, host: str) -> bool:
    pattern = pattern.rstrip(".").lower()
    host = host.rstrip(".").lower()
    if not pattern or not host:
        return False
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        if not suffix or "*" in suffix:
            return False
        host_labels = host.split(".")
        suffix_labels = suffix.split(".")
        return len(host_labels) == len(suffix_labels) + 1 and host.endswith("." + suffix)
    return False


def matches_hostname(certificate: Certificate, host: str) -> bool:
    """Check ``host`` against the certificate SANs (or CN when no SAN exists).

    IP addresses are compared against iPAddress SANs; DNS names are compared
    case-insensitively against dNSName SANs and a leading ``*.`` pattern matches
    exactly one label. A certificate without a subjectAltName extension falls
    back to its subject common name, matching historical browser behaviour.
    """

    expected = host.strip().rstrip(".")
    if not expected:
        return False
    try:
        expected_ip = ipaddress.ip_address(expected)
    except ValueError:
        expected_ip = None
    if expected_ip is not None:
        for value in certificate.ip_addresses:
            try:
                if ipaddress.ip_address(value) == expected_ip:
                    return True
            except ValueError:
                continue
        return False
    dns_names = certificate.dns_names
    if not dns_names:
        cn = certificate.subject_cn
        return bool(cn) and _match_dns_name(cn, expected)
    return any(_match_dns_name(pattern, expected) for pattern in dns_names)


def _check_identity(certificate: Certificate, expected_host: Optional[str]) -> List[Finding]:
    if expected_host is None:
        return []
    if matches_hostname(certificate, expected_host):
        return []
    candidates = [
        f"DNS:{name}" for name in certificate.dns_names
    ] + [f"IP:{name}" for name in certificate.ip_addresses]
    if not candidates:
        candidates = [f"CN:{certificate.subject_cn}"] if certificate.subject_cn else ["no DNS or IP names"]
    shown = ", ".join(candidates[:MAX_SAN_DISPLAY])
    return [
        _finding(
            "CERT-HOSTNAME-MISMATCH",
            SEVERITY_ERROR,
            certificate,
            f"hostname {expected_host!r} does not match certificate names: {shown}",
        )
    ]


def _check_validity(certificate: Certificate, now: datetime) -> List[Finding]:
    findings: List[Finding] = []
    if now > certificate.not_after:
        days = (now - certificate.not_after).days
        findings.append(
            _finding(
                "CERT-EXPIRED",
                SEVERITY_ERROR,
                certificate,
                f"certificate expired {days} day(s) ago on {_format_time(certificate.not_after)}",
            )
        )
        return findings
    if now < certificate.not_before:
        findings.append(
            _finding(
                "CERT-NOT-YET-VALID",
                SEVERITY_ERROR,
                certificate,
                f"certificate is not valid before {_format_time(certificate.not_before)}",
            )
        )
        return findings
    days_remaining = (certificate.not_after - now).days
    if days_remaining <= EXPIRING_WARNING_DAYS:
        findings.append(
            _finding(
                "CERT-EXPIRING",
                SEVERITY_WARNING,
                certificate,
                f"certificate expires in {days_remaining} day(s) on {_format_time(certificate.not_after)}",
            )
        )
    elif days_remaining <= EXPIRING_NOTICE_DAYS:
        findings.append(
            _finding(
                "CERT-EXPIRING",
                SEVERITY_NOTICE,
                certificate,
                f"certificate expires in {days_remaining} day(s) on {_format_time(certificate.not_after)}",
            )
        )
    return findings


def _check_signature(certificate: Certificate) -> List[Finding]:
    findings: List[Finding] = []
    hash_name = certificate.signature_hash
    if hash_name in ("md2", "md5"):
        findings.append(
            _finding(
                "CERT-WEAK-HASH",
                SEVERITY_ERROR,
                certificate,
                f"signature uses {hash_name.upper()} ({certificate.signature_algorithm})",
            )
        )
    elif hash_name == "sha1":
        findings.append(
            _finding(
                "CERT-WEAK-HASH",
                SEVERITY_WARNING,
                certificate,
                f"signature uses SHA-1 ({certificate.signature_algorithm})",
            )
        )
    if (
        certificate.public_key_algorithm == "RSA"
        and certificate.public_key_bits is not None
        and certificate.public_key_bits < MIN_RSA_BITS
    ):
        findings.append(
            _finding(
                "CERT-SMALL-RSA-KEY",
                SEVERITY_ERROR,
                certificate,
                f"RSA key is {certificate.public_key_bits} bits, below the {MIN_RSA_BITS}-bit minimum",
            )
        )
    return findings


def _check_profile(certificate: Certificate) -> List[Finding]:
    findings: List[Finding] = []
    if certificate.subject == certificate.issuer and not certificate.is_ca:
        findings.append(
            _finding(
                "CERT-SELF-SIGNED",
                SEVERITY_NOTICE,
                certificate,
                "certificate is self-signed (subject equals issuer and no CA constraint)",
            )
        )
    if not certificate.is_ca and not certificate.san:
        findings.append(
            _finding(
                "CERT-NO-SAN",
                SEVERITY_WARNING,
                certificate,
                "non-CA certificate has no subjectAltName extension",
            )
        )
    wildcards = [name for name in certificate.dns_names if name.startswith("*.")]
    if wildcards:
        findings.append(
            _finding(
                "CERT-WILDCARD",
                SEVERITY_NOTICE,
                certificate,
                "certificate uses wildcard DNS name(s): " + ", ".join(wildcards),
            )
        )
    if certificate.validity_days > LONG_VALIDITY_DAYS:
        findings.append(
            _finding(
                "CERT-LONG-VALIDITY",
                SEVERITY_NOTICE,
                certificate,
                f"validity is {certificate.validity_days} days, above the "
                f"{LONG_VALIDITY_DAYS}-day browser limit",
            )
        )
    if certificate.is_ca:
        path_len = certificate.basic_constraints.path_len
        suffix = "" if path_len is None else f" (pathLenConstraint {path_len})"
        findings.append(
            _finding(
                "CERT-CA-CERT",
                SEVERITY_INFO,
                certificate,
                f"certificate is a CA{suffix}",
            )
        )
    return findings


def check_certificate(
    certificate: Certificate,
    now: datetime,
    expected_host: Optional[str] = None,
) -> List[Finding]:
    """Run every per-certificate rule and return the findings."""

    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    now = now.astimezone(timezone.utc)
    findings: List[Finding] = []
    findings.extend(_check_validity(certificate, now))
    findings.extend(_check_signature(certificate))
    findings.extend(_check_profile(certificate))
    findings.extend(_check_identity(certificate, expected_host))
    return findings


def check_inventory(
    certificates: Sequence[Certificate],
    now: datetime,
    expected_host: Optional[str] = None,
) -> List[Finding]:
    """Run per-certificate and inventory-wide rules over all certificates."""

    findings: List[Finding] = []
    for certificate in certificates:
        findings.extend(check_certificate(certificate, now, expected_host))

    # Duplicate fingerprints: every later occurrence is reported.
    first_seen: Dict[str, Certificate] = {}
    for certificate in certificates:
        fingerprint = certificate.sha256_fingerprint
        original = first_seen.get(fingerprint)
        if original is None:
            first_seen[fingerprint] = certificate
            continue
        original_source = original.source or "another input"
        findings.append(
            _finding(
                "CERT-DUPLICATE",
                SEVERITY_WARNING,
                certificate,
                f"duplicate certificate also loaded from {original_source}",
            )
        )

    # Missing issuer certificates: only for non-self-signed certificates.
    subjects = {certificate.subject for certificate in certificates}
    for certificate in certificates:
        if certificate.subject == certificate.issuer:
            continue
        if certificate.issuer in subjects:
            continue
        issuer_cn = certificate.issuer_cn or str(certificate.issuer) or "(unknown)"
        findings.append(
            _finding(
                "CERT-CHAIN-MISSING-ISSUER",
                SEVERITY_WARNING,
                certificate,
                f"issuer certificate {issuer_cn!r} is not present in the scanned inventory",
            )
        )

    findings.sort(
        key=lambda finding: (
            -SEVERITY_ORDER[finding.severity],
            finding.rule_id,
            finding.subject,
            finding.fingerprint,
        )
    )
    return findings


def audit(
    certificates: Sequence[Certificate],
    now: Optional[datetime] = None,
    expected_host: Optional[str] = None,
    load_errors: Optional[Sequence[LoadError]] = None,
) -> AuditResult:
    """Build a full :class:`AuditResult` for an inventory."""

    if now is None:
        now = datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    now = now.astimezone(timezone.utc)
    inventory = list(certificates)
    return AuditResult(
        certificates=inventory,
        findings=check_inventory(inventory, now, expected_host),
        generated_at=now,
        load_errors=list(load_errors or []),
    )
