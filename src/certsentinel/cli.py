"""Command line interface for ``certsentinel``.

Sub-commands:

``scan``      audit every certificate found under a file or directory
``check``     same as scan, with an expected hostname for TLS identity checks
``endpoint``  fetch one live certificate with ``ssl`` and audit it
``report``    write a standalone HTML audit report
``version``   print ``certsentinel <version>``

Exit codes: 0 clean (or findings below the fail threshold), 1 findings at or
above the fail threshold or a runtime failure, 2 bad usage.
"""

from __future__ import annotations

import argparse
import socket
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional, Sequence, Tuple

from . import __version__
from .checks import AuditResult, audit, fail_on_matches
from .report import render_html, render_json, render_text
from .x509 import Certificate, X509Error, from_der, from_pem, load_paths

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2

FAIL_ON_CHOICES = ("warning", "error", "none")
DEFAULT_FAIL_ON = "warning"
DEFAULT_TIMEOUT = 5.0


class CliUsageError(ValueError):
    """Raised for invalid argument values detected after argparse."""


class EndpointError(ValueError):
    """Raised when a live TLS certificate cannot be retrieved or parsed."""


def parse_now(text: Optional[str]) -> datetime:
    """Parse an ISO-8601 timestamp (``Z`` accepted) into aware UTC."""

    if text is None:
        return datetime.now(timezone.utc)
    value = text.strip()
    if not value:
        raise CliUsageError("--now cannot be empty")
    if value.endswith(("Z", "z")):
        value = value[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise CliUsageError(
            f"invalid --now value {text!r}; use ISO-8601, for example 2026-11-16T12:00:00Z"
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_endpoint(text: str) -> Tuple[str, int]:
    """Parse ``HOST:PORT`` (bracketed IPv6 is accepted) into host and port."""

    value = text.strip()
    if not value:
        raise CliUsageError("endpoint cannot be empty")
    if value.startswith("["):
        closing = value.find("]")
        if closing == -1 or not value[closing + 1 :].startswith(":"):
            raise CliUsageError(f"invalid endpoint {text!r}; expected [IPv6]:PORT")
        host = value[1:closing]
        port_text = value[closing + 2 :]
    else:
        if ":" not in value:
            raise CliUsageError(f"invalid endpoint {text!r}; expected HOST:PORT")
        host, port_text = value.rsplit(":", 1)
    if not host:
        raise CliUsageError(f"invalid endpoint {text!r}; host is empty")
    if not port_text.isdigit():
        raise CliUsageError(f"invalid endpoint {text!r}; port is not a number")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise CliUsageError(f"invalid endpoint {text!r}; port must be within 1..65535")
    return host, port


def fetch_certificate(
    host: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
    sni: Optional[str] = None,
) -> Certificate:
    """Retrieve the certificate a TLS endpoint presents, without verification.

    Without ``sni`` this uses :func:`ssl.get_server_certificate`. With ``sni`` a
    plain :class:`ssl.SSLContext` is used instead so the SNI name can differ from
    the address being connected to.
    """

    if timeout <= 0:
        raise ValueError("timeout must be positive")
    source = f"{host}:{port}"
    if sni:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw_socket:
                with context.wrap_socket(raw_socket, server_hostname=sni) as tls_socket:
                    der = tls_socket.getpeercert(binary_form=True)
        except (OSError, ssl.SSLError) as exc:
            raise EndpointError(f"cannot retrieve certificate from {source}: {exc}") from exc
        if not der:
            raise EndpointError(f"{source} did not present a certificate")
        try:
            certificate = from_der(der)
        except X509Error as exc:
            raise EndpointError(f"invalid certificate from {source}: {exc}") from exc
        return certificate.with_source(source)
    try:
        pem = ssl.get_server_certificate((host, port), timeout=timeout)
    except (OSError, ssl.SSLError) as exc:
        raise EndpointError(f"cannot retrieve certificate from {source}: {exc}") from exc
    try:
        certificates = from_pem(pem)
    except X509Error as exc:
        raise EndpointError(f"invalid certificate from {source}: {exc}") from exc
    if not certificates:
        raise EndpointError(f"{source} did not present a certificate")
    return certificates[0].with_source(source)


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all sub-commands."""

    parser = argparse.ArgumentParser(
        prog="certsentinel",
        description=(
            "Offline X.509 certificate inventory and expiry auditor: parses PEM/DER "
            "certificates with a strict DER parser, evaluates configuration and "
            "expiry rules, and reports findings as text, JSON or standalone HTML."
        ),
        epilog=(
            "exit codes: 0 clean, 1 findings at or above the fail threshold or a "
            "runtime failure, 2 bad usage. Default fail threshold: warning."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="audit certificates in a file or directory",
        description="Load certificates from a file/directory tree and run the audit rules.",
    )
    scan_parser.add_argument("path", metavar="PATH", help="certificate file or directory to scan")
    _add_common_audit_options(scan_parser, allow_host=False)
    scan_parser.set_defaults(handler=cmd_scan)

    check_parser = subparsers.add_parser(
        "check",
        help="audit certificates and verify an expected hostname",
        description="Load certificates and additionally check them against an expected hostname.",
    )
    check_parser.add_argument("path", metavar="PATH", help="certificate file or directory to scan")
    _add_common_audit_options(check_parser, allow_host=True)
    check_parser.set_defaults(handler=cmd_check)

    endpoint_parser = subparsers.add_parser(
        "endpoint",
        help="fetch and audit the certificate of a live TLS endpoint",
        description=(
            "Connect to HOST:PORT without verification, fetch the presented certificate "
            "and audit it. With --sni the TLS handshake uses that server name."
        ),
    )
    endpoint_parser.add_argument("target", metavar="HOST:PORT", help="TLS endpoint to connect to")
    endpoint_parser.add_argument("--sni", metavar="NAME", help="server name for the TLS handshake")
    endpoint_parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        metavar="SECONDS",
        help=f"connection timeout (default: {DEFAULT_TIMEOUT:g})",
    )
    endpoint_parser.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        default=DEFAULT_FAIL_ON,
        help=f"minimum severity that makes the command fail (default: {DEFAULT_FAIL_ON})",
    )
    endpoint_parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    endpoint_parser.set_defaults(handler=cmd_endpoint)

    report_parser = subparsers.add_parser(
        "report",
        help="write a standalone HTML audit report",
        description="Audit certificates and write a self-contained HTML report.",
    )
    report_parser.add_argument("path", metavar="PATH", help="certificate file or directory to scan")
    report_parser.add_argument(
        "--out", required=True, metavar="FILE", help="output HTML file"
    )
    report_parser.add_argument("--host", metavar="NAME", help="expected hostname for identity checks")
    report_parser.add_argument("--now", metavar="ISO8601", help="audit time (default: current UTC time)")
    report_parser.set_defaults(handler=cmd_report)

    version_parser = subparsers.add_parser(
        "version", help="print the certsentinel version", description="Print the certsentinel version."
    )
    version_parser.set_defaults(handler=cmd_version)

    return parser


def _add_common_audit_options(parser: argparse.ArgumentParser, allow_host: bool) -> None:
    if allow_host:
        parser.add_argument("--host", metavar="NAME", help="expected hostname for identity checks")
    parser.add_argument("--now", metavar="ISO8601", help="audit time (default: current UTC time)")
    parser.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        default=DEFAULT_FAIL_ON,
        help=f"minimum severity that makes the command fail (default: {DEFAULT_FAIL_ON})",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")


def _load_audit(path: str, now: datetime, expected_host: Optional[str]) -> AuditResult:
    loaded = load_paths([path])
    return audit(
        loaded.certificates,
        now=now,
        expected_host=expected_host,
        load_errors=loaded.errors,
    )


def _emit(result: AuditResult, args: argparse.Namespace) -> int:
    if args.json:
        print(render_json(result))
    else:
        print(render_text(result))
    if result.load_errors and not result.certificates:
        return EXIT_FINDINGS
    return EXIT_FINDINGS if fail_on_matches(result, args.fail_on) else EXIT_OK


def cmd_scan(args: argparse.Namespace) -> int:
    """Audit a file or directory tree."""

    now = parse_now(args.now)
    result = _load_audit(args.path, now, expected_host=None)
    return _emit(result, args)


def cmd_check(args: argparse.Namespace) -> int:
    """Audit a file or directory tree and verify an expected hostname."""

    now = parse_now(args.now)
    result = _load_audit(args.path, now, expected_host=args.host)
    return _emit(result, args)


def cmd_endpoint(args: argparse.Namespace) -> int:
    """Fetch and audit a live TLS endpoint certificate."""

    host, port = parse_endpoint(args.target)
    if args.timeout <= 0:
        raise CliUsageError("--timeout must be positive")
    certificate = fetch_certificate(host, port, timeout=args.timeout, sni=args.sni)
    result = audit([certificate], expected_host=args.sni or host)
    return _emit(result, args)


def cmd_report(args: argparse.Namespace) -> int:
    """Write a standalone HTML audit report."""

    now = parse_now(args.now)
    result = _load_audit(args.path, now, expected_host=args.host)
    document = render_html(result)
    output = Path(args.out)
    if str(output.parent) not in ("", "."):
        output.parent.mkdir(parents=True, exist_ok=True)
    try:
        output.write_text(document, encoding="utf-8", newline="\n")
    except OSError as exc:
        raise EndpointError(f"cannot write report to {args.out}: {exc}") from exc
    print(f"report written to {args.out} ({len(document)} bytes)")
    if result.load_errors and not result.certificates:
        return EXIT_FINDINGS
    return EXIT_OK


def cmd_version(_args: argparse.Namespace) -> int:
    """Print the packaged version."""

    print(f"certsentinel {__version__}")
    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the CLI and return the process exit code."""

    parser = build_parser()
    args = parser.parse_args(argv)
    handler: Callable[[argparse.Namespace], int] = args.handler
    try:
        return int(handler(args))
    except CliUsageError as exc:
        parser.print_usage(sys.stderr)
        print(f"certsentinel: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except (X509Error, OSError, ValueError) as exc:
        print(f"certsentinel: error: {exc}", file=sys.stderr)
        return EXIT_FINDINGS
    except KeyboardInterrupt:
        print("certsentinel: interrupted", file=sys.stderr)
        return EXIT_FINDINGS
