"""Text, JSON and HTML renderers for certificate audit results.

The three outputs share one data model: :func:`build_report` produces the JSON
document used by ``--json`` and the HTTP-friendly detail view, :func:`render_text`
renders an aligned terminal report, and :func:`render_html` produces a standalone
page with inline CSS and no external assets.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from .checks import SEVERITIES, AuditResult
from .x509 import Certificate

__all__ = [
    "certificate_to_dict",
    "build_report",
    "render_text",
    "render_json",
    "render_html",
]

_TITLE = "cert-sentinel audit"


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds")


def _format_time(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


_SIGNATURE_SHORT_NAMES = {
    "sha256WithRSAEncryption": "sha256RSA",
    "sha384WithRSAEncryption": "sha384RSA",
    "sha512WithRSAEncryption": "sha512RSA",
    "sha224WithRSAEncryption": "sha224RSA",
    "sha1WithRSAEncryption": "sha1RSA",
    "md5WithRSAEncryption": "md5RSA",
    "md2WithRSAEncryption": "md2RSA",
    "ecdsa-with-SHA256": "ecdsa-SHA256",
    "ecdsa-with-SHA384": "ecdsa-SHA384",
    "ecdsa-with-SHA512": "ecdsa-SHA512",
    "ecdsa-with-SHA1": "ecdsa-SHA1",
}


def _signature_label(certificate: Certificate) -> str:
    name = certificate.signature_algorithm
    return _SIGNATURE_SHORT_NAMES.get(name, name)


def _subject_label(certificate: Certificate) -> str:
    cn = certificate.subject_cn
    if cn:
        return cn
    text = str(certificate.subject)
    return text or "(empty subject)"


def _issuer_label(certificate: Certificate) -> str:
    cn = certificate.issuer_cn
    if cn:
        return cn
    return str(certificate.issuer) or "(empty issuer)"


def _key_label(certificate: Certificate) -> str:
    algorithm = certificate.public_key_algorithm
    if algorithm == "EC" and certificate.ec_curve:
        curve = certificate.ec_curve
        if "(" in curve and curve.endswith(")"):
            curve = curve.split("(")[-1][:-1]
        return f"EC {curve}"
    if certificate.public_key_bits is not None:
        return f"{algorithm} {certificate.public_key_bits}"
    return algorithm


def _san_label(certificate: Certificate) -> str:
    if not certificate.san:
        return "-"
    parts = []
    for name in certificate.san:
        prefix = {
            "dns": "DNS",
            "ip": "IP",
            "email": "email",
            "uri": "URI",
            "directory": "dir",
        }.get(name.kind, name.kind)
        parts.append(f"{prefix}:{name.value}")
    return ", ".join(parts)


def certificate_to_dict(certificate: Certificate, now: datetime) -> Dict[str, Any]:
    """Convert a certificate into the JSON inventory representation."""

    return {
        "source": certificate.source,
        "sha256": certificate.sha256_fingerprint,
        "subject": str(certificate.subject),
        "subject_cn": certificate.subject_cn,
        "issuer": str(certificate.issuer),
        "issuer_cn": certificate.issuer_cn,
        "serial": certificate.serial_hex,
        "version": certificate.version,
        "not_before": _iso(certificate.not_before),
        "not_after": _iso(certificate.not_after),
        "days_remaining": certificate.days_remaining(now),
        "validity_days": certificate.validity_days,
        "signature_algorithm": certificate.signature_algorithm,
        "signature_algorithm_oid": certificate.signature_algorithm_oid,
        "signature_hash": certificate.signature_hash,
        "public_key_algorithm": certificate.public_key_algorithm,
        "public_key_bits": certificate.public_key_bits,
        "ec_curve": certificate.ec_curve,
        "is_ca": certificate.is_ca,
        "path_len": certificate.basic_constraints.path_len,
        "key_usage": sorted(certificate.key_usage),
        "extended_key_usage": list(certificate.extended_key_usage),
        "san": [name.to_dict() for name in certificate.san],
        "dns_names": list(certificate.dns_names),
        "ip_addresses": list(certificate.ip_addresses),
        "subject_key_identifier": certificate.subject_key_identifier,
        "authority_key_identifier": certificate.authority_key_identifier,
        "authority_info_access": [
            {"method": entry.method, "location": entry.location.to_dict()}
            for entry in certificate.authority_info_access
        ],
    }


def build_report(result: AuditResult) -> Dict[str, Any]:
    """Build the JSON-ready audit document."""

    return {
        "generated_at": _iso(result.generated_at),
        "certificate_count": len(result.certificates),
        "finding_count": result.finding_count,
        "counts": result.counts,
        "max_severity": result.max_severity,
        "load_errors": [
            {"path": error.path, "message": error.message} for error in result.load_errors
        ],
        "certificates": [
            certificate_to_dict(certificate, result.generated_at)
            for certificate in result.certificates
        ],
        "findings": [finding.to_dict() for finding in result.findings],
    }


def render_json(result: AuditResult) -> str:
    """Render the audit result as indented JSON."""

    return json.dumps(build_report(result), indent=2)


def _truncate(text: str, width: int) -> str:
    if len(text) <= width:
        return text
    return text[: width - 3] + "..."


def render_text(result: AuditResult) -> str:
    """Render an aligned text report for terminals and CI logs."""

    counts = result.counts
    summary_counts = ", ".join(f"{counts[severity]} {severity}" for severity in SEVERITIES)
    lines = [
        f"{_TITLE} - {_format_time(result.generated_at)}",
        f"{len(result.certificates)} certificate(s), {result.finding_count} finding(s): "
        + (summary_counts if result.findings else "none"),
        "",
    ]
    if result.certificates:
        lines.append("CERTIFICATES")
        header = (
            f"{'SUBJECT':<26} {'ISSUER':<26} {'NOT AFTER':<20} "
            f"{'KEY':<11} {'SIGNATURE':<14} {'SHA-256':<16}"
        )
        lines.append(header)
        for certificate in result.certificates:
            lines.append(
                f"{_truncate(_subject_label(certificate), 26):<26} "
                f"{_truncate(_issuer_label(certificate), 26):<26} "
                f"{_truncate(_format_time(certificate.not_after), 20):<20} "
                f"{_truncate(_key_label(certificate), 11):<11} "
                f"{_truncate(_signature_label(certificate), 14):<14} "
                f"{certificate.fingerprint_prefix:<16}"
            )
        lines.append("")
    if result.findings:
        lines.append("FINDINGS")
        lines.append(f"{'SEVERITY':<9}{'RULE':<28}{'CERTIFICATE':<26}MESSAGE")
        for finding in result.findings:
            lines.append(
                f"{finding.severity:<9}{finding.rule_id:<28}"
                f"{_truncate(finding.subject, 26):<26}{finding.message}"
            )
        lines.append("")
    else:
        lines.append("No findings.")
        lines.append("")
    if result.load_errors:
        lines.append("LOAD ERRORS")
        for error in result.load_errors:
            lines.append(f"{error.path}: {error.message}")
        lines.append("")
    return "\n".join(lines).rstrip("\n")


_STYLE = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body {
  margin: 0; padding: 24px;
  background: #0b1220; color: #dbe4f0;
  font: 14px/1.5 "Segoe UI", system-ui, -apple-system, sans-serif;
}
header { margin-bottom: 20px; }
h1 { margin: 0; font-size: 24px; color: #f8fbff; letter-spacing: 0.02em; }
h2 { margin: 0 0 10px; font-size: 15px; color: #9fb3cc; text-transform: uppercase; letter-spacing: 0.08em; }
p.subtitle { margin: 2px 0 0; color: #8da2bd; }
p.meta { margin: 8px 0 0; color: #8da2bd; font-size: 13px; }
section { background: #111c30; border: 1px solid #22334d; border-radius: 8px; padding: 16px; margin-bottom: 18px; overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-variant-numeric: tabular-nums; }
th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid #1d2c44; vertical-align: top; }
th { color: #94a9c4; font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; }
tbody tr:last-child td { border-bottom: none; }
tbody tr:hover { background: #16253d; }
.cards { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 18px; }
.card { background: #111c30; border: 1px solid #22334d; border-radius: 8px; padding: 12px 18px; min-width: 120px; }
.card .value { display: block; font-size: 24px; font-weight: 600; color: #f8fbff; }
.card .label { color: #8da2bd; font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }
.badge { border-radius: 4px; padding: 1px 7px; font-size: 12px; font-weight: 600; }
.error { background: #4a1f25; color: #ff9a9a; }
.warning { background: #4a3a1a; color: #ffce7a; }
.notice { background: #1c3a4a; color: #7fd4f5; }
.info { background: #1c3a2a; color: #7fe0a8; }
.muted { color: #6f829c; }
code { background: #1b2b45; border-radius: 4px; padding: 1px 5px; color: #cfe0f5; }
footer { color: #6f829c; font-size: 12px; margin-top: 22px; }
"""


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def render_html(result: AuditResult, title: str = _TITLE) -> str:
    """Render a standalone HTML audit report with inline CSS."""

    counts = result.counts
    parts: List[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en">')
    parts.append("<head>")
    parts.append('<meta charset="utf-8">')
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    parts.append(f"<title>{_esc(title)}</title>")
    parts.append(f"<style>{_STYLE}</style>")
    parts.append("</head>")
    parts.append("<body>")
    parts.append("<header>")
    parts.append("<h1>cert-sentinel</h1>")
    parts.append('<p class="subtitle">X.509 certificate inventory and expiry audit</p>')
    parts.append(
        f'<p class="meta">Generated {_esc(_format_time(result.generated_at))} &middot; '
        f"{len(result.certificates)} certificate(s) &middot; {result.finding_count} finding(s)</p>"
    )
    parts.append("</header>")

    parts.append('<div class="cards">')
    parts.append(
        f'<div class="card"><span class="value">{len(result.certificates)}</span>'
        '<span class="label">certificates</span></div>'
    )
    for severity in SEVERITIES:
        parts.append(
            f'<div class="card"><span class="value {severity}">{counts[severity]}</span>'
            f'<span class="label">{severity}</span></div>'
        )
    parts.append("</div>")

    parts.append('<section id="findings">')
    parts.append("<h2>Findings</h2>")
    if result.findings:
        parts.append("<table>")
        parts.append(
            "<thead><tr><th>Severity</th><th>Rule</th><th>Certificate</th>"
            "<th>Fingerprint</th><th>Message</th></tr></thead>"
        )
        parts.append("<tbody>")
        for finding in result.findings:
            parts.append(
                "<tr>"
                f'<td><span class="badge {_esc(finding.severity)}">{_esc(finding.severity)}</span></td>'
                f"<td>{_esc(finding.rule_id)}</td>"
                f"<td>{_esc(finding.subject)}</td>"
                f"<td><code>{_esc(finding.fingerprint)}</code></td>"
                f"<td>{_esc(finding.message)}</td>"
                "</tr>"
            )
        parts.append("</tbody>")
        parts.append("</table>")
    else:
        parts.append('<p class="muted">No findings.</p>')
    parts.append("</section>")

    parts.append('<section id="certificates">')
    parts.append("<h2>Certificate inventory</h2>")
    if result.certificates:
        parts.append("<table>")
        parts.append(
            "<thead><tr><th>Subject</th><th>Issuer</th><th>Not before</th><th>Not after</th>"
            "<th>Key</th><th>Signature</th><th>Subject alternative names</th>"
            "<th>Source</th></tr></thead>"
        )
        parts.append("<tbody>")
        for certificate in result.certificates:
            parts.append(
                "<tr>"
                f"<td>{_esc(str(certificate.subject) or '(empty subject)')}</td>"
                f"<td>{_esc(str(certificate.issuer) or '(empty issuer)')}</td>"
                f"<td>{_esc(_format_time(certificate.not_before))}</td>"
                f"<td>{_esc(_format_time(certificate.not_after))}</td>"
                f"<td>{_esc(_key_label(certificate))}</td>"
                f"<td>{_esc(certificate.signature_algorithm)}</td>"
                f"<td>{_esc(_san_label(certificate))}</td>"
                f"<td>{_esc(certificate.source or '-')}</td>"
                "</tr>"
            )
        parts.append("</tbody>")
        parts.append("</table>")
    else:
        parts.append('<p class="muted">No certificates loaded.</p>')
    parts.append("</section>")

    if result.load_errors:
        parts.append('<section id="load-errors">')
        parts.append("<h2>Load errors</h2>")
        parts.append("<table>")
        parts.append("<thead><tr><th>Path</th><th>Error</th></tr></thead><tbody>")
        for error in result.load_errors:
            parts.append(f"<tr><td>{_esc(error.path)}</td><td>{_esc(error.message)}</td></tr>")
        parts.append("</tbody></table>")
        parts.append("</section>")

    parts.append(
        "<footer>cert-sentinel &middot; offline X.509 inventory and expiry audit "
        "&middot; no external assets</footer>"
    )
    parts.append("</body>")
    parts.append("</html>")
    return "\n".join(parts) + "\n"
