#!/usr/bin/env python3
"""
antiphish.py

A static anti-phishing analysis tool for URLs and raw email messages.

Two independent analyzers share one explainable scoring model:

    URLAnalyzer   -> inspects a single URL for structural phishing indicators
                      (IP-literal hosts, punycode, typosquatting, suspicious
                      TLDs, credential-trick characters, etc.)

    EmailAnalyzer -> parses a raw .eml-style message: header sender/reply-to
                      mismatches, urgency language, mismatched link text vs.
                      href, suspicious attachment names -- and runs
                      URLAnalyzer against every link found in the body.

Every finding carries a weight and a plain-language reason; the final
verdict is always traceable back to specific evidence, never a bare score.

Usage:
    python3 antiphish.py url "http://paypa1-secure.com/login"
    python3 antiphish.py email suspicious_message.eml
    python3 antiphish.py email suspicious_message.eml --json report.json
"""

from __future__ import annotations

import argparse
import email
import html.parser
import ipaddress
import json
import re
import sys
from dataclasses import dataclass, field
from email.message import Message
from enum import Enum
from pathlib import Path
from urllib.parse import urlparse


# ======================================================================
# Shared data model
# ======================================================================

class RiskLevel(str, Enum):
    """Final verdict bucket, ordered from safest to most dangerous."""
    CLEAN = "Clean"
    LOW = "Low Risk"
    SUSPICIOUS = "Suspicious"
    HIGH_RISK = "High Risk"


@dataclass(frozen=True)
class Finding:
    """One piece of evidence contributing to the risk score."""
    weight: float
    reason: str


@dataclass
class AnalysisResult:
    """The complete, explainable output of an analysis run."""
    subject: str
    findings: list[Finding] = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    @property
    def score(self) -> float:
        return round(sum(f.weight for f in self.findings), 2)

    @property
    def verdict(self) -> RiskLevel:
        return _score_to_verdict(self.score)

    def add(self, weight: float, reason: str) -> None:
        self.findings.append(Finding(weight=weight, reason=reason))

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.weight, reverse=True)

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "score": self.score,
            "verdict": self.verdict.value,
            "findings": [{"weight": f.weight, "reason": f.reason} for f in self.sorted_findings()],
            "extra": self.extra,
        }


_VERDICT_THRESHOLDS: tuple[tuple[float, RiskLevel], ...] = (
    (5.0, RiskLevel.HIGH_RISK),
    (2.5, RiskLevel.SUSPICIOUS),
    (1.0, RiskLevel.LOW),
)


def _score_to_verdict(score: float) -> RiskLevel:
    for threshold, level in _VERDICT_THRESHOLDS:
        if score >= threshold:
            return level
    return RiskLevel.CLEAN


# ======================================================================
# URL analysis
# ======================================================================

SUSPICIOUS_TLDS = frozenset({
    "zip", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "work", "click", "country",
})

URL_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
})

SUSPICIOUS_URL_KEYWORDS = frozenset({
    "login", "verify", "secure", "account", "update", "confirm", "banking",
    "signin", "password", "suspended", "unlock", "billing",
})

# well-known brand names used as the typosquatting reference set (bare
# names, not full domains -- matching is done against individual tokens
# of the registrable domain so "paypa1-secure-login.tk" is still caught)
PROTECTED_BRAND_NAMES = frozenset({
    "paypal", "google", "microsoft", "apple", "amazon",
    "chase", "bankofamerica", "wellsfargo", "netflix",
    "facebook", "instagram", "linkedin", "dropbox",
})

MAX_REASONABLE_URL_LENGTH = 90
MAX_REASONABLE_SUBDOMAINS = 3
MAX_REASONABLE_HYPHENS = 3
TYPOSQUAT_DISTANCE_THRESHOLD = 2


def _levenshtein(a: str, b: str) -> int:
    """Minimum edit distance between two strings (pure stdlib, no deps)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current_row = [i]
        for j, char_b in enumerate(b, start=1):
            insert_cost = current_row[j - 1] + 1
            delete_cost = previous_row[j] + 1
            substitute_cost = previous_row[j - 1] + (char_a != char_b)
            current_row.append(min(insert_cost, delete_cost, substitute_cost))
        previous_row = current_row
    return previous_row[-1]


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _registrable_domain_label(host: str) -> str:
    """Returns the second-level label of a host, e.g. 'paypa1-secure-login'
    for 'paypa1-secure-login.tk', or 'google' for 'www.google.com'."""
    labels = host.split(".")
    return labels[-2] if len(labels) >= 2 else labels[0]


def _closest_brand_match(host: str) -> tuple[str, str, int] | None:
    """Compares each hyphen-separated token of the registrable domain
    label against every protected brand name. Returns
    (token, brand, distance) for the closest non-exact match found, or
    None if no token is within the typosquat distance threshold."""
    domain_label = _registrable_domain_label(host)
    tokens = domain_label.split("-")

    candidates = [
        (token, brand, _levenshtein(token, brand))
        for token in tokens
        for brand in PROTECTED_BRAND_NAMES
        if token != brand
    ]
    if not candidates:
        return None

    token, brand, distance = min(candidates, key=lambda c: c[2])
    return (token, brand, distance) if distance <= TYPOSQUAT_DISTANCE_THRESHOLD else None


class URLAnalyzer:
    """Static structural analysis of a single URL."""

    def analyze(self, url: str) -> AnalysisResult:
        result = AnalysisResult(subject=url)
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = (parsed.hostname or "").lower()

        if not host:
            result.add(1.0, "URL has no resolvable host.")
            return result

        self._check_scheme(parsed, result)
        self._check_ip_literal(host, result)
        self._check_punycode(host, result)
        self._check_credential_trick(url, result)
        self._check_length(url, result)
        self._check_subdomain_count(host, result)
        self._check_hyphen_count(host, result)
        self._check_tld(host, result)
        self._check_shortener(host, result)
        self._check_suspicious_keywords(parsed, result)
        self._check_typosquatting(host, result)
        self._check_nonstandard_port(parsed, result)

        result.extra["host"] = host
        return result

    @staticmethod
    def _check_scheme(parsed, result: AnalysisResult) -> None:
        if parsed.scheme == "http":
            result.add(0.5, "URL uses unencrypted HTTP rather than HTTPS.")

    @staticmethod
    def _check_ip_literal(host: str, result: AnalysisResult) -> None:
        if _is_ip_literal(host):
            result.add(2.0, f"URL host is a raw IP address ({host}) rather than a domain name.")

    @staticmethod
    def _check_punycode(host: str, result: AnalysisResult) -> None:
        if any(label.startswith("xn--") for label in host.split(".")):
            result.add(2.0, "Domain uses punycode encoding — possible homograph/lookalike attack.")

    @staticmethod
    def _check_credential_trick(url: str, result: AnalysisResult) -> None:
        # Anything before an '@' in the authority section is treated as
        # userinfo by browsers, letting attackers hide the real host:
        # http://paypal.com@evil.com/ actually goes to evil.com
        authority = url.split("://", 1)[-1].split("/", 1)[0]
        if "@" in authority:
            result.add(2.5, "URL contains '@' before the host — classic credential-hiding redirect trick.")

    @staticmethod
    def _check_length(url: str, result: AnalysisResult) -> None:
        if len(url) > MAX_REASONABLE_URL_LENGTH:
            result.add(0.5, f"URL is unusually long ({len(url)} characters).")

    @staticmethod
    def _check_subdomain_count(host: str, result: AnalysisResult) -> None:
        labels = host.split(".")
        subdomain_count = max(0, len(labels) - 2)
        if subdomain_count > MAX_REASONABLE_SUBDOMAINS:
            result.add(1.0, f"Domain has an unusually high number of subdomains ({subdomain_count}).")

    @staticmethod
    def _check_hyphen_count(host: str, result: AnalysisResult) -> None:
        hyphens = host.count("-")
        if hyphens > MAX_REASONABLE_HYPHENS:
            result.add(0.5, f"Domain contains an unusually high number of hyphens ({hyphens}).")

    @staticmethod
    def _check_tld(host: str, result: AnalysisResult) -> None:
        tld = host.rsplit(".", 1)[-1]
        if tld in SUSPICIOUS_TLDS:
            result.add(1.0, f"Domain uses a top-level domain commonly abused for phishing ('.{tld}').")

    @staticmethod
    def _check_shortener(host: str, result: AnalysisResult) -> None:
        if host in URL_SHORTENERS:
            result.add(0.5, f"URL uses a link shortener ({host}) that hides the true destination.")

    @staticmethod
    def _check_suspicious_keywords(parsed, result: AnalysisResult) -> None:
        haystack = f"{parsed.path} {parsed.query}".lower()
        hits = sorted(k for k in SUSPICIOUS_URL_KEYWORDS if k in haystack)
        if hits:
            result.add(0.5 * len(hits), f"URL path/query contains credential-harvesting keywords: {', '.join(hits)}.")

    @staticmethod
    def _check_typosquatting(host: str, result: AnalysisResult) -> None:
        match = _closest_brand_match(host)
        if match is None:
            return
        token, brand, distance = match
        result.add(3.0, f"Domain token '{token}' is {distance} character(s) away from known brand '{brand}' — likely typosquatting.")

    @staticmethod
    def _check_nonstandard_port(parsed, result: AnalysisResult) -> None:
        if parsed.port and parsed.port not in (80, 443):
            result.add(1.0, f"URL specifies a non-standard port ({parsed.port}).")


# ======================================================================
# Email analysis
# ======================================================================

URGENCY_PHRASES = frozenset({
    "act now", "immediately", "urgent", "verify your account", "suspended",
    "will be closed", "limited time", "confirm your identity", "unusual activity",
    "click here", "winner", "claim your prize", "final notice",
})

GENERIC_GREETINGS = frozenset({
    "dear customer", "dear user", "dear valued customer", "dear account holder",
    "dear member",
})

DANGEROUS_ATTACHMENT_EXTENSIONS = frozenset({
    "exe", "scr", "js", "vbs", "bat", "cmd", "jar", "docm", "xlsm", "pptm", "ps1",
})

DOUBLE_EXTENSION_PATTERN = re.compile(
    r"\.(pdf|doc|docx|jpg|png|txt)\.(exe|scr|js|vbs|bat|cmd|jar)$", re.IGNORECASE
)

HREF_PATTERN = re.compile(r'<a\s[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
TAG_STRIP_PATTERN = re.compile(r"<[^>]+>")
PLAIN_URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")


class _LinkTextExtractor(html.parser.HTMLParser):
    """Extracts (href, visible_text) pairs from an HTML body without
    external dependencies (stdlib html.parser only)."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._current_href: str | None = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self._current_href = href
                self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._current_href is not None:
            self.links.append((self._current_href, "".join(self._current_text).strip()))
            self._current_href = None


def _extract_html_links(body: str) -> list[tuple[str, str]]:
    extractor = _LinkTextExtractor()
    extractor.feed(body)
    return extractor.links


def _extract_plain_urls(body: str) -> list[str]:
    return PLAIN_URL_PATTERN.findall(body)


def _domain_of(address: str) -> str:
    """Extracts the domain from an email address like 'Name <a@b.com>'."""
    match = re.search(r"@([\w.-]+)", address)
    return match.group(1).lower() if match else ""


def _get_body_text(message: Message) -> str:
    """Pulls the best-effort readable body (prefers HTML) from a parsed
    email.message.Message, walking multipart structures if present."""
    if message.is_multipart():
        html_part, plain_part = "", ""
        for part in message.walk():
            content_type = part.get_content_type()
            if content_type == "text/html" and not html_part:
                html_part = part.get_payload(decode=True).decode(errors="ignore")
            elif content_type == "text/plain" and not plain_part:
                plain_part = part.get_payload(decode=True).decode(errors="ignore")
        return html_part or plain_part
    payload = message.get_payload(decode=True)
    return payload.decode(errors="ignore") if payload else str(message.get_payload())


def _get_attachment_names(message: Message) -> list[str]:
    names = []
    if message.is_multipart():
        for part in message.walk():
            filename = part.get_filename()
            if filename:
                names.append(filename)
    return names


class EmailAnalyzer:
    """Parses a raw .eml message and scores it for phishing indicators,
    including running URLAnalyzer against every link in the body."""

    def __init__(self, url_analyzer: URLAnalyzer | None = None) -> None:
        self._url_analyzer = url_analyzer or URLAnalyzer()

    def analyze(self, raw_message: str) -> AnalysisResult:
        message = email.message_from_string(raw_message)
        subject = message.get("Subject", "(no subject)")
        result = AnalysisResult(subject=subject)

        self._check_sender_mismatch(message, result)
        self._check_subject_urgency(subject, result)

        body = _get_body_text(message)
        self._check_body_urgency(body, result)
        self._check_generic_greeting(body, result)
        self._check_attachments(message, result)

        url_findings = self._check_links(body, result)
        result.extra["urls_analyzed"] = url_findings
        return result

    @staticmethod
    def _check_sender_mismatch(message: Message, result: AnalysisResult) -> None:
        from_domain = _domain_of(message.get("From", ""))
        reply_to = message.get("Reply-To")
        return_path = message.get("Return-Path")

        if reply_to:
            reply_domain = _domain_of(reply_to)
            if reply_domain and from_domain and reply_domain != from_domain:
                result.add(2.0, f"Reply-To domain ('{reply_domain}') differs from From domain ('{from_domain}').")

        if return_path:
            return_domain = _domain_of(return_path)
            if return_domain and from_domain and return_domain != from_domain:
                result.add(1.5, f"Return-Path domain ('{return_domain}') differs from From domain ('{from_domain}').")

    @staticmethod
    def _check_subject_urgency(subject: str, result: AnalysisResult) -> None:
        hits = _find_phrases(subject, URGENCY_PHRASES)
        if hits:
            result.add(1.0 * len(hits), f"Subject line uses urgency language: {', '.join(hits)}.")

    @staticmethod
    def _check_body_urgency(body: str, result: AnalysisResult) -> None:
        plain_text = TAG_STRIP_PATTERN.sub(" ", body)
        hits = _find_phrases(plain_text, URGENCY_PHRASES)
        if hits:
            result.add(0.5 * len(hits), f"Email body uses urgency/pressure language: {', '.join(hits)}.")

    @staticmethod
    def _check_generic_greeting(body: str, result: AnalysisResult) -> None:
        plain_text = TAG_STRIP_PATTERN.sub(" ", body)
        hits = _find_phrases(plain_text, GENERIC_GREETINGS)
        if hits:
            result.add(0.5, f"Uses a generic, non-personalized greeting ('{hits[0]}').")

    @staticmethod
    def _check_attachments(message: Message, result: AnalysisResult) -> None:
        for filename in _get_attachment_names(message):
            extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            if DOUBLE_EXTENSION_PATTERN.search(filename):
                result.add(3.0, f"Attachment '{filename}' uses a double extension to disguise its real type.")
            elif extension in DANGEROUS_ATTACHMENT_EXTENSIONS:
                result.add(2.0, f"Attachment '{filename}' has a high-risk executable extension ('.{extension}').")

    def _check_links(self, body: str, result: AnalysisResult) -> list[dict]:
        html_links = _extract_html_links(body)
        plain_urls = _extract_plain_urls(body) if not html_links else []
        analyzed: list[dict] = []

        for href, visible_text in html_links:
            self._check_link_text_mismatch(href, visible_text, result)
            sub_result = self._url_analyzer.analyze(href)
            analyzed.append(sub_result.to_dict())
            if sub_result.score > 0:
                result.add(min(sub_result.score, 3.0), f"Embedded link '{href}' has its own phishing indicators (sub-score {sub_result.score}).")

        for url in plain_urls:
            sub_result = self._url_analyzer.analyze(url)
            analyzed.append(sub_result.to_dict())
            if sub_result.score > 0:
                result.add(min(sub_result.score, 3.0), f"Embedded link '{url}' has its own phishing indicators (sub-score {sub_result.score}).")

        return analyzed

    @staticmethod
    def _check_link_text_mismatch(href: str, visible_text: str, result: AnalysisResult) -> None:
        looks_like_url = bool(PLAIN_URL_PATTERN.match(visible_text.strip()))
        if not looks_like_url:
            return
        href_host = (urlparse(href).hostname or "").lower()
        text_host = (urlparse(visible_text.strip()).hostname or "").lower()
        if href_host and text_host and href_host != text_host:
            result.add(3.0, f"Link text shows '{text_host}' but actually points to '{href_host}'.")


def _find_phrases(text: str, phrases: frozenset[str]) -> list[str]:
    lowered = text.lower()
    return sorted(phrase for phrase in phrases if phrase in lowered)


# ======================================================================
# CLI
# ======================================================================

def _print_result(result: AnalysisResult) -> None:
    print("=" * 70)
    print(f" ANTI-PHISHING ANALYSIS — {result.subject}")
    print("=" * 70)
    print(f"VERDICT: {result.verdict.value}  (score: {result.score})")
    print("-" * 70)
    if result.findings:
        for finding in result.sorted_findings():
            print(f"  [+{finding.weight:.1f}] {finding.reason}")
    else:
        print("  No phishing indicators found by static heuristics.")
    print("=" * 70)


def _write_json(result: AnalysisResult, path: Path) -> None:
    path.write_text(json.dumps(result.to_dict(), indent=2))
    print(f"\nFull JSON report written to {path}")


def _run_url_command(args: argparse.Namespace) -> None:
    result = URLAnalyzer().analyze(args.url)
    _print_result(result)
    if args.json:
        _write_json(result, Path(args.json))


def _run_email_command(args: argparse.Namespace) -> None:
    raw_message = Path(args.file_path).read_text(errors="ignore")
    result = EmailAnalyzer().analyze(raw_message)
    _print_result(result)
    if args.json:
        _write_json(result, Path(args.json))


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Static anti-phishing analysis tool.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    url_parser = subparsers.add_parser("url", help="Analyze a single URL.")
    url_parser.add_argument("url", help="The URL to analyze.")
    url_parser.add_argument("--json", metavar="OUTPUT_PATH", help="Write full report as JSON.")
    url_parser.set_defaults(handler=_run_url_command)

    email_parser = subparsers.add_parser("email", help="Analyze a raw .eml email file.")
    email_parser.add_argument("file_path", help="Path to the raw email (.eml) file.")
    email_parser.add_argument("--json", metavar="OUTPUT_PATH", help="Write full report as JSON.")
    email_parser.set_defaults(handler=_run_email_command)

    return parser


def main() -> None:
    parser = _build_arg_parser()
    args = parser.parse_args()
    try:
        args.handler(args)
    except FileNotFoundError as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
