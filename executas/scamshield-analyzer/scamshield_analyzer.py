#!/usr/bin/env python3
"""ScamShield Analyzer - Executa JSON-RPC tool.

The tool is intentionally deterministic. Anna's hosted LLM can summarize the
result, but this module owns the evidence, scoring, recommendations, and stated
limitations so the app never invents scam evidence.
"""

from __future__ import annotations

import json
import ipaddress
import re
import socket
import ssl
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from difflib import SequenceMatcher
from email.utils import parseaddr
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

VERSION = "0.1.1"
TOOL_NAME = "scamshield"

MANIFEST: dict[str, Any] = {
    "display_name": "ScamShield Analyzer",
    "version": VERSION,
    "description": (
        "Evidence-first fraud scanner for messages, websites, emails, QR codes, "
        "job offers, investment pitches, and screenshot OCR text."
    ),
    "author": "ScamShield AI",
    "homepage": "https://github.com/imthegoodboy/ScamShielddd-AI",
    "license": "MIT",
    "tags": ["security", "fraud", "phishing", "consumer-safety"],
    "tools": [
        {
            "name": "investigate",
            "description": (
                "Analyze suspicious content and return an explainable risk score, "
                "reasons, recommendations, limitations, and report text."
            ),
            "parameters": [
                {
                    "name": "mode",
                    "type": "string",
                    "description": (
                        "message | website | email | job | investment | qr | screenshot"
                    ),
                    "required": True,
                },
                {
                    "name": "text",
                    "type": "string",
                    "description": "Pasted message, email body, job offer, decoded QR content, or OCR text.",
                    "required": False,
                    "default": "",
                },
                {
                    "name": "url",
                    "type": "string",
                    "description": "URL or domain to inspect.",
                    "required": False,
                    "default": "",
                },
                {
                    "name": "sender",
                    "type": "string",
                    "description": "Email sender or sender handle when available.",
                    "required": False,
                    "default": "",
                },
                {
                    "name": "subject",
                    "type": "string",
                    "description": "Email subject or short label.",
                    "required": False,
                    "default": "",
                },
                {
                    "name": "filename",
                    "type": "string",
                    "description": "Uploaded screenshot or QR filename.",
                    "required": False,
                    "default": "",
                },
                {
                    "name": "allow_network",
                    "type": "boolean",
                    "description": "When true, perform a bounded HTTPS reachability check.",
                    "required": False,
                    "default": False,
                },
            ],
        }
    ],
    "runtime": {"type": "uv", "min_version": "0.1.0"},
}

KNOWN_BRANDS = [
    "amazon",
    "apple",
    "facebook",
    "google",
    "instagram",
    "linkedin",
    "microsoft",
    "netflix",
    "paypal",
    "paytm",
    "phonepe",
    "sbi",
    "swiggy",
    "telegram",
    "whatsapp",
    "zomato",
]

SUSPICIOUS_TLDS = {
    "biz",
    "click",
    "country",
    "download",
    "fit",
    "gq",
    "icu",
    "loan",
    "men",
    "mom",
    "party",
    "rest",
    "review",
    "ru",
    "stream",
    "tk",
    "top",
    "trade",
    "work",
    "xyz",
}

SHORTENERS = {
    "bit.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "lnkd.in",
    "rebrand.ly",
    "shorturl.at",
    "t.co",
    "tinyurl.com",
    "tiny.cc",
    "wa.link",
}

UNSAFE_HOSTS = {"localhost"}

RISK_KEYWORDS: list[tuple[str, int, str, str]] = [
    (r"\burgent\b|\bimmediately\b|\bact now\b|\blast chance\b|\bwithin\s+\d+\s+(minute|hour|day)s?\b", 14, "Urgency pressure", "Scammers pressure victims to act before verifying."),
    (r"\bwon\b|\bwinner\b|\bprize\b|\blottery\b|\bfree money\b|\bgift card\b|\bcashback\b", 16, "Unexpected reward", "Unexpected money or prizes are common lure patterns."),
    (r"\bpay\b.*\b(fee|charge|deposit|registration|processing)\b|\bregistration fee\b|\bsecurity deposit\b", 22, "Upfront payment request", "Legitimate hiring or prize claims rarely require advance payment."),
    (r"\bpin\b|\botp\b|\bone[- ]time password\b|\bpassword\b|\bverify your account\b|\bkyc\b", 22, "Credential or OTP request", "A request for OTP, PIN, password, or KYC data can enable account takeover."),
    (r"\bremote access\b|\banydesk\b|\bteamviewer\b|\binstall this app\b|\bscreen share\b", 20, "Remote access request", "Remote access requests are high-risk in support and refund scams."),
    (r"\bguaranteed returns?\b|\bdouble your money\b|\bprofit guaranteed\b|\bno risk\b|\b\d+%\s*(daily|weekly|monthly)\b", 26, "Guaranteed-return investment claim", "Guaranteed high returns are a strong Ponzi or investment-scam signal."),
    (r"\bcrypto\b|\bforex\b|\bbinary option\b|\btrading signal\b|\btelegram group\b", 12, "Speculative investment channel", "Scams often route victims into crypto, forex, or signal groups."),
    (r"\binterview letter\b|\bwork from home\b|\bsalary\b.*\b\d{4,}\b|\bjoining kit\b|\bhr\b", 8, "Job-offer language", "Job scams commonly combine attractive salary claims with pressure or fees."),
    (r"\brefund\b|\bchargeback\b|\baccount locked\b|\bsuspended\b|\bunusual activity\b", 12, "Account or refund trigger", "Account-lock and refund messages often lead to phishing or remote-support scams."),
]

LOW_RISK_SIGNALS: list[tuple[str, int, str]] = [
    (r"\binvoice attached\b|\border confirmation\b|\bmeeting agenda\b", -4, "Routine-business wording"),
    (r"\bhttps://\b", -3, "HTTPS link present"),
]


@dataclass
class Finding:
    title: str
    severity: str
    points: int
    evidence: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "points": self.points,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _clean_text(value: Any, max_len: int = 12000) -> str:
    if value is None:
        return ""
    text = str(value)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:max_len]


def _canonical_url(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = f"https://{value}"
    return value


def _registered_domain(host: str) -> str:
    host = (host or "").strip(".").lower()
    if not host:
        return ""
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return host
    two_part_suffixes = {"co.in", "co.uk", "com.au", "com.br", "org.uk"}
    suffix = ".".join(parts[-2:])
    if suffix in two_part_suffixes and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _host_from_any_text(text: str) -> str:
    match = re.search(r"(https?://[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?)", text)
    if not match:
        return ""
    parsed = urlparse(_canonical_url(match.group(1)))
    return parsed.hostname or ""


def _severity(points: int) -> str:
    if points >= 22:
        return "critical"
    if points >= 14:
        return "high"
    if points >= 7:
        return "medium"
    return "low"


def _add_finding(
    findings: list[Finding],
    points: int,
    title: str,
    evidence: str,
    recommendation: str,
) -> None:
    findings.append(
        Finding(
            title=title,
            severity=_severity(points),
            points=points,
            evidence=evidence[:240],
            recommendation=recommendation,
        )
    )


def _extract_entities(text: str) -> dict[str, Any]:
    urls = sorted(set(re.findall(r"https?://[^\s<>()]+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s<>()]*)?", text)))
    phones = sorted(set(re.findall(r"(?:\+?\d[\d\s().-]{7,}\d)", text)))
    emails = sorted(set(re.findall(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", text)))
    amounts = sorted(set(re.findall(r"(?:rs\.?|inr|\$|usd|eur|gbp)\s?[\d,]+(?:\.\d+)?|[\d,]+(?:\.\d+)?\s?(?:rs|inr|usd|eur|gbp)", text, flags=re.I)))
    return {
        "urls": urls[:10],
        "phones": [p.strip() for p in phones[:10]],
        "emails": emails[:10],
        "amounts": amounts[:10],
    }


def _brand_similarity(host: str) -> list[tuple[str, float]]:
    label = (host.split(".")[0] if host else "").lower()
    label_norm = label.translate(str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "@": "a"}))
    matches: list[tuple[str, float]] = []
    for brand in KNOWN_BRANDS:
        if brand in label_norm and label_norm != brand:
            matches.append((brand, 0.96))
            continue
        ratio = SequenceMatcher(None, label_norm, brand).ratio()
        if ratio >= 0.78 and label_norm != brand:
            matches.append((brand, ratio))
    return sorted(matches, key=lambda item: item[1], reverse=True)[:3]


def _analyze_url(url: str, text: str, allow_network: bool, findings: list[Finding]) -> dict[str, Any]:
    candidate = _canonical_url(url) or _canonical_url(_host_from_any_text(text))
    if not candidate:
        return {"checked": False, "limitations": ["No URL or domain was provided."]}

    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower()
    registered = _registered_domain(host)
    labels = [p for p in host.split(".") if p]
    tld = labels[-1] if labels else ""
    preview: dict[str, Any] = {
        "checked": True,
        "input": url or _host_from_any_text(text),
        "normalized_url": candidate,
        "scheme": parsed.scheme,
        "host": host,
        "registered_domain": registered,
        "tld": tld,
        "network_probe": "not_requested",
    }

    if parsed.scheme != "https":
        _add_finding(
            findings,
            10,
            "Link is not HTTPS",
            candidate,
            "Do not enter credentials or payment details on non-HTTPS links.",
        )

    if registered in SHORTENERS or host in SHORTENERS:
        _add_finding(
            findings,
            16,
            "Shortened link hides destination",
            registered or host,
            "Expand the link with a trusted preview tool before opening it.",
        )

    if tld in SUSPICIOUS_TLDS:
        _add_finding(
            findings,
            10,
            "Higher-risk domain ending",
            f".{tld}",
            "Verify the domain through the official brand website or app.",
        )

    if re.search(r"\d", host) and any(brand in host for brand in KNOWN_BRANDS):
        _add_finding(
            findings,
            18,
            "Brand name mixed with digits",
            host,
            "Treat lookalike brand domains as suspicious until independently verified.",
        )

    if host.count("-") >= 2 or len(host) > 42:
        _add_finding(
            findings,
            8,
            "Unusual domain shape",
            host,
            "Check the exact domain spelling before clicking.",
        )

    brand_matches = _brand_similarity(host)
    if brand_matches:
        brand, ratio = brand_matches[0]
        preview["brand_similarity"] = {"brand": brand, "score": round(ratio, 2)}
        _add_finding(
            findings,
            18 if ratio >= 0.9 else 12,
            "Possible brand impersonation",
            f"{host} resembles {brand}",
            "Open the brand by typing its official domain yourself.",
        )

    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
        _add_finding(
            findings,
            14,
            "Raw IP address link",
            host,
            "Avoid login or payment pages hosted directly on IP addresses.",
        )

    query = parse_qs(parsed.query)
    if any(k.lower() in {"token", "otp", "password", "session", "auth"} for k in query):
        _add_finding(
            findings,
            12,
            "Sensitive-looking URL parameter",
            parsed.query[:120],
            "Do not share or forward links containing authentication tokens.",
        )

    if allow_network and parsed.scheme == "https" and host:
        preview["network_probe"] = _probe_https(candidate)

    return preview


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def _public_ip(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return False


def _literal_ip(host: str) -> str:
    value = (host or "").strip("[]")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return ""


def _network_safety_error(url: str) -> str:
    parsed = urlparse(url)
    host = (parsed.hostname or "").strip(".").lower()
    if parsed.scheme != "https":
        return "Network probe only supports HTTPS URLs."
    if not host:
        return "Network probe requires a hostname."
    if host in UNSAFE_HOSTS or host.endswith(".localhost"):
        return "Network probe blocked a local hostname."

    literal = _literal_ip(host)
    if literal:
        return "" if _public_ip(literal) else "Network probe blocked a non-public IP address."

    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        return f"DNS lookup failed: {exc}"

    addresses = sorted({info[4][0] for info in infos if info[4]})
    if not addresses:
        return "DNS lookup returned no addresses."
    if not all(_public_ip(address) for address in addresses):
        return "Network probe blocked a hostname that resolves to non-public IP space."
    return ""


def _probe_https(url: str) -> dict[str, Any]:
    safety_error = _network_safety_error(url)
    if safety_error:
        blocked = safety_error.startswith("Network probe blocked")
        return {"ok": False, "blocked": blocked, "error": safety_error}

    try:
        opener = build_opener(_NoRedirect, HTTPSHandler(context=ssl.create_default_context()))
        req = Request(url, method="HEAD", headers={"User-Agent": "ScamShieldAI/0.1"})
        with opener.open(req, timeout=4) as res:
            return {
                "ok": True,
                "status": int(getattr(res, "status", 0) or 0),
                "final_url": res.geturl(),
            }
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def _analyze_email(sender: str, subject: str, text: str, findings: list[Finding]) -> dict[str, Any]:
    name, address = parseaddr(sender or "")
    domain = address.split("@")[-1].lower() if "@" in address else ""
    combined = " ".join([sender or "", subject or "", text or ""]).lower()
    result = {"sender_name": name, "sender_email": address, "sender_domain": domain}

    if address and domain in {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "proton.me"}:
        brands = [b for b in KNOWN_BRANDS if b in combined]
        if brands:
            _add_finding(
                findings,
                16,
                "Brand claim from consumer email domain",
                f"{address} mentions {brands[0]}",
                "Official support emails should come from the brand's own domain.",
            )

    if address and not domain:
        _add_finding(
            findings,
            10,
            "Sender address is not parseable",
            sender,
            "Ask for an official email from a verifiable company domain.",
        )

    if re.search(r"\.(exe|scr|bat|cmd|js|vbs|iso|img|zip|rar)\b", combined):
        _add_finding(
            findings,
            18,
            "Potentially risky attachment type",
            "Executable or archive extension mentioned",
            "Do not open attachments unless the sender is independently verified.",
        )

    if "reply-to" in combined and domain and "@" in combined:
        _add_finding(
            findings,
            8,
            "Reply-to mismatch should be checked",
            "Email text mentions reply-to details",
            "Compare From, Reply-To, and signed domain before responding.",
        )

    return result


def _analyze_qr(text: str, findings: list[Finding]) -> dict[str, Any]:
    decoded = unquote(text or "")
    result = {"decoded": decoded[:500], "type": "unknown"}
    lower = decoded.lower()
    if lower.startswith(("upi://", "paytmmp://", "phonepe://")) or "pa=" in lower:
        result["type"] = "payment"
        _add_finding(
            findings,
            14,
            "QR code contains payment instructions",
            decoded[:180],
            "Receiving money never requires entering a UPI PIN. Confirm amount and payee before scanning.",
        )
        if any(token in lower for token in ["am=", "amount=", "mam="]):
            _add_finding(
                findings,
                8,
                "QR includes an amount field",
                decoded[:180],
                "Verify the displayed amount before approving any payment.",
            )
    elif lower.startswith(("http://", "https://")) or _host_from_any_text(decoded):
        result["type"] = "link"
    elif decoded:
        result["type"] = "text"
    return result


def _keyword_findings(text: str, findings: list[Finding]) -> None:
    lower = text.lower()
    for pattern, points, title, explanation in RISK_KEYWORDS:
        match = re.search(pattern, lower, flags=re.I)
        if match:
            snippet = _snippet(text, match.start(), match.end())
            _add_finding(
                findings,
                points,
                title,
                snippet,
                explanation,
            )


def _apply_mode_rules(mode: str, text: str, findings: list[Finding]) -> None:
    lower = text.lower()
    if mode == "job":
        if re.search(r"\b(fee|deposit|registration|training charge|kit charge)\b", lower):
            _add_finding(
                findings,
                24,
                "Job offer asks for money",
                "Fee/deposit language found",
                "Do not pay before employment. Verify through the company's official careers site.",
            )
        if re.search(r"\bwork from home\b.*\b\d{4,}\b|\bsalary\b.*\b(50000|60000|70000|lakh)\b", lower):
            _add_finding(
                findings,
                12,
                "Unrealistic salary framing",
                "High salary or work-from-home lure found",
                "Ask for a formal offer from a verified company domain.",
            )
    if mode == "investment":
        if re.search(r"\bguaranteed\b|\bdouble\b|\bfixed return\b|\bno risk\b", lower):
            _add_finding(
                findings,
                26,
                "Investment claim removes normal risk",
                "Guaranteed/no-risk return language found",
                "Do not send money. Verify registration with the relevant financial regulator.",
            )
    if mode == "screenshot" and not text:
        _add_finding(
            findings,
            5,
            "Screenshot text is missing",
            "No OCR text was supplied",
            "Use Anna vision extraction or paste the text visible in the screenshot.",
        )


def _snippet(text: str, start: int, end: int) -> str:
    left = max(0, start - 45)
    right = min(len(text), end + 45)
    snippet = text[left:right].strip()
    return re.sub(r"\s+", " ", snippet)


def _score(findings: list[Finding], text: str) -> int:
    score = 8
    score += sum(max(0, f.points) for f in findings)
    lower = text.lower()
    for pattern, delta, _title in LOW_RISK_SIGNALS:
        if re.search(pattern, lower, flags=re.I):
            score += delta
    if len(text) > 2200:
        score += 3
    if len(findings) >= 5:
        score += 8
    if any(f.points >= 22 for f in findings) and len(findings) >= 2:
        score += 6
    return max(0, min(99, int(score)))


def _verdict(score: int) -> str:
    if score >= 80:
        return "dangerous"
    if score >= 55:
        return "high_risk"
    if score >= 30:
        return "suspicious"
    return "low_risk"


def _headline(verdict: str, mode: str) -> str:
    noun = {
        "website": "website",
        "email": "email",
        "job": "job offer",
        "investment": "investment pitch",
        "qr": "QR code",
        "screenshot": "screenshot",
    }.get(mode, "message")
    if verdict == "dangerous":
        return f"Likely scam {noun}"
    if verdict == "high_risk":
        return f"High-risk {noun}"
    if verdict == "suspicious":
        return f"Suspicious {noun}"
    return f"No strong scam pattern found in this {noun}"


def _recommendations(verdict: str, findings: list[Finding], mode: str) -> list[dict[str, str]]:
    recs: list[dict[str, str]] = []
    titles = {f.title for f in findings}
    if verdict in {"dangerous", "high_risk"}:
        recs.append({"action": "Do not click, pay, or reply", "why": "The evidence has multiple high-risk scam indicators."})
        recs.append({"action": "Verify through an official channel", "why": "Use a bookmarked website, official app, or known phone number."})
    elif verdict == "suspicious":
        recs.append({"action": "Pause and verify first", "why": "The content has enough risk signals to avoid immediate action."})
    else:
        recs.append({"action": "Still verify sensitive requests", "why": "Low risk is not the same as guaranteed safe."})

    if "Credential or OTP request" in titles:
        recs.append({"action": "Never share OTP, PIN, or password", "why": "These can give an attacker direct account access."})
    if "Upfront payment request" in titles or "Job offer asks for money" in titles:
        recs.append({"action": "Do not pay a hiring or release fee", "why": "Advance-payment requests are a core job and prize scam pattern."})
    if mode == "qr":
        recs.append({"action": "Check the payee and amount on your payment app", "why": "QR codes can silently encode a payment request."})
    if verdict in {"dangerous", "high_risk"}:
        recs.append({"action": "Save evidence before deleting", "why": "Screenshots, sender IDs, links, and timestamps help with reports."})
    return recs[:6]


def _limitations(mode: str, allow_network: bool, has_text: bool) -> list[str]:
    notes = [
        "ScamShield uses deterministic pattern analysis and should support, not replace, human verification.",
        "The analyzer does not claim domain age, breach reputation, or community report counts unless a live source provides them.",
    ]
    if mode == "screenshot" and not has_text:
        notes.append("Screenshot OCR was not available to the local analyzer; paste extracted text or use Anna vision synthesis.")
    if not allow_network:
        notes.append("Live HTTPS reachability was not probed because network probing was disabled.")
    return notes


def _report_markdown(result: dict[str, Any]) -> str:
    lines = [
        f"# ScamShield AI report",
        "",
        f"Report ID: {result['id']}",
        f"Created: {result['created_at']}",
        f"Mode: {result['mode']}",
        f"Verdict: {result['headline']}",
        f"Risk score: {result['score']}%",
        "",
        "## Reasons",
    ]
    for finding in result["findings"]:
        lines.append(f"- {finding['severity'].upper()}: {finding['title']} - {finding['evidence']}")
    if not result["findings"]:
        lines.append("- No high-confidence scam indicators were detected.")
    lines.append("")
    lines.append("## Recommended actions")
    for rec in result["recommendations"]:
        lines.append(f"- {rec['action']}: {rec['why']}")
    lines.append("")
    lines.append("## Limitations")
    for note in result["limitations"]:
        lines.append(f"- {note}")
    return "\n".join(lines)


def tool_investigate(
    mode: str,
    text: str = "",
    url: str = "",
    sender: str = "",
    subject: str = "",
    filename: str = "",
    allow_network: bool = False,
) -> dict[str, Any]:
    mode = (mode or "message").strip().lower()
    if mode not in {"message", "website", "email", "job", "investment", "qr", "screenshot"}:
        mode = "message"

    text = _clean_text(text)
    url = _clean_text(url, 2048)
    sender = _clean_text(sender, 512)
    subject = _clean_text(subject, 512)
    filename = _clean_text(filename, 512)
    combined = " ".join(p for p in [subject, sender, url, text, filename] if p)

    findings: list[Finding] = []
    entities = _extract_entities(combined)
    url_preview = _analyze_url(url, combined, bool(allow_network), findings)
    email_preview = _analyze_email(sender, subject, combined, findings) if mode == "email" or sender else {}
    qr_preview = _analyze_qr(text or url, findings) if mode == "qr" else {}
    _keyword_findings(combined, findings)
    _apply_mode_rules(mode, combined, findings)

    # De-duplicate by title + evidence while preserving strongest point value.
    dedup: dict[tuple[str, str], Finding] = {}
    for finding in findings:
        key = (finding.title, finding.evidence)
        prev = dedup.get(key)
        if prev is None or finding.points > prev.points:
            dedup[key] = finding
    findings = sorted(dedup.values(), key=lambda f: f.points, reverse=True)

    score = _score(findings, combined)
    verdict = _verdict(score)
    headline = _headline(verdict, mode)
    result: dict[str, Any] = {
        "id": f"ss-{uuid.uuid4().hex[:12]}",
        "created_at": _now_iso(),
        "mode": mode,
        "score": score,
        "verdict": verdict,
        "headline": headline,
        "summary": _summary(verdict, findings),
        "findings": [f.to_dict() for f in findings[:12]],
        "recommendations": _recommendations(verdict, findings, mode),
        "entities": entities,
        "url_preview": url_preview,
        "email_preview": email_preview,
        "qr_preview": qr_preview,
        "limitations": _limitations(mode, bool(allow_network), bool(text)),
        "confidence": _confidence(score, findings, combined),
        "input_excerpt": combined[:800],
    }
    result["report_markdown"] = _report_markdown(result)
    result["llm_context"] = _llm_context(result)
    return result


def _summary(verdict: str, findings: list[Finding]) -> str:
    if findings:
        top = ", ".join(f.title.lower() for f in findings[:3])
        return f"Top evidence: {top}."
    if verdict == "low_risk":
        return "No high-confidence scam pattern was detected in the supplied content."
    return "The supplied content has suspicious structure but limited concrete evidence."


def _confidence(score: int, findings: list[Finding], text: str) -> str:
    if not text:
        return "low"
    if score >= 70 and len(findings) >= 3:
        return "high"
    if findings:
        return "medium"
    return "low"


def _llm_context(result: dict[str, Any]) -> str:
    top_findings = [
        {
            "title": f["title"],
            "severity": f["severity"],
            "evidence": f["evidence"],
        }
        for f in result["findings"][:6]
    ]
    payload = {
        "mode": result["mode"],
        "score": result["score"],
        "verdict": result["verdict"],
        "headline": result["headline"],
        "summary": result["summary"],
        "findings": top_findings,
        "recommendations": result["recommendations"][:5],
        "limitations": result["limitations"],
        "entities": result["entities"],
    }
    return json.dumps(payload, ensure_ascii=True)


TOOL_DISPATCH = {"investigate": tool_investigate}


def _ok(req_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _err(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _handle_initialize(req_id: Any, params: dict[str, Any]) -> dict[str, Any]:
    proto = params.get("protocolVersion") or "2.0"
    return _ok(
        req_id,
        {
            "protocolVersion": proto if proto in {"1.1", "2.0"} else "2.0",
            "serverInfo": {"name": MANIFEST["display_name"], "version": VERSION},
            "capabilities": {},
        },
    )


def _handle_describe(req_id: Any) -> dict[str, Any]:
    return _ok(req_id, MANIFEST)


def _handle_health(req_id: Any) -> dict[str, Any]:
    return _ok(
        req_id,
        {
            "status": "healthy",
            "version": VERSION,
            "timestamp": _now_iso(),
            "network_default": "disabled",
        },
    )


def _handle_invoke(req_id: Any, params: dict[str, Any]) -> dict[str, Any]:
    tool = params.get("tool")
    args = params.get("arguments") or {}
    if not isinstance(args, dict):
        return _ok(req_id, {"success": False, "error": "arguments must be an object"})
    fn = TOOL_DISPATCH.get(tool)
    if fn is None:
        return _ok(req_id, {"success": False, "error": f"unknown tool: {tool}"})
    try:
        data = fn(**args)
    except Exception as exc:  # noqa: BLE001
        return _ok(req_id, {"success": False, "error": f"{type(exc).__name__}: {exc}"})
    return _ok(req_id, {"success": True, "tool": tool, "data": data})


def _send(message: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(message, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _handle_message(request: dict[str, Any]) -> dict[str, Any] | None:
    req_id = request.get("id")
    method = request.get("method")
    params = request.get("params") or {}
    if method == "initialize":
        return _handle_initialize(req_id, params)
    if method == "describe":
        return _handle_describe(req_id)
    if method == "health":
        return _handle_health(req_id)
    if method == "invoke":
        return _handle_invoke(req_id, params)
    if method == "shutdown":
        return _ok(req_id, {"ok": True})
    return _err(req_id, -32601, f"method not found: {method}")


def main() -> None:
    print(f"[scamshield-analyzer] v{VERSION} ready", file=sys.stderr)
    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            _send(_err(None, -32700, f"parse error: {exc}"))
            continue
        try:
            response = _handle_message(request)
        except Exception as exc:  # noqa: BLE001
            response = _err(request.get("id"), -32603, f"internal error: {exc}")
        if response is not None and response.get("id") is not None:
            _send(response)


if __name__ == "__main__":
    main()
