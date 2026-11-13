#!/usr/bin/env python3
"""Offline email and URL risk triage with look-alike domain detection."""

import argparse
import ipaddress
import re
from email import policy
from email.parser import Parser
from urllib.parse import urlsplit

URL_RE = re.compile(r"""https?://[^\s<>"']+""", re.IGNORECASE)
SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly",
}
RISKY_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1",
    ".hta", ".iso", ".zip", ".rar", ".docm", ".xlsm",
}
URGENCY_TERMS = (
    "urgent", "immediately", "within 24 hours", "account suspended",
    "verify your account", "password expires", "payment failed",
    "wire transfer", "gift card", "act now",
)

# Common high-value targets for typosquatting
TARGET_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com", 
    "paypal.com", "facebook.com", "netflix.com", "icloud.com", 
    "outlook.com", "yahoo.com", " chase.com", "bankofamerica.com"
}

def levenshtein_distance(s1, s2):
    """Calculates the edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if not s2:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def check_lookalike(host):
    """Checks if the host is a look-alike of a target domain."""
    findings = []
    
    for target in TARGET_DOMAINS:
        # 1. Direct Edit Distance (Typosquatting)
        # distance of 1 or 2 is highly suspicious for a domain of this length
        dist = levenshtein_distance(host, target)
        if 0 < dist <= 2:
            findings.append(f"Possible typosquatting: looks like {target} (dist: {dist})")
            break
        
        # 2. Subdomain Deception
        # Flags 'google.com.secure-login.net' because 'google.com' is used as a prefix
        if target in host and host != target:
            findings.append(f"Subdomain deception: target '{target}' found within {host}")
            break
            
    return findings

def add(findings, message):
    if message not in findings:
        findings.append(message)

def analyze_url(raw_url):
    findings = []
    candidate = raw_url.strip().rstrip(".,;:!?)\"]}")
    try:
        parts = urlsplit(candidate)
        host = parts.hostname
        if not host:
            return candidate, ["Could not identify a hostname."]

        host = host.rstrip(".").lower()

        # Check for look-alikes
        lookalike_findings = check_lookalike(host)
        findings.extend(lookalike_findings)

        if parts.scheme.lower() != "https":
            add(findings, "Does not use HTTPS.")
        if parts.username or parts.password:
            add(findings, "Contains username/password text before the hostname.")
        try:
            ipaddress.ip_address(host)
            add(findings, "Uses an IP address instead of a domain name.")
        except ValueError:
            pass

        try:
            ascii_host = host.encode("idna").decode("ascii")
            if "xn--" in ascii_host:
                add(findings, "Hostname contains an internationalized (punycode) label.")
        except UnicodeError:
            add(findings, "Hostname could not be normalized.")

        if host in SHORTENERS:
            add(findings, "Uses a URL-shortening domain; the final destination is hidden.")
        if any(host.endswith(ext) for ext in RISKY_EXTENSIONS):
            add(findings, "URL appears to point to a potentially risky file type.")
        if len(host) > 60:
            add(findings, "Hostname is unusually long.")
        if host.count("-") >= 3:
            add(findings, "Hostname contains several hyphens.")
        if parts.port:
            add(findings, f"Uses a non-default or explicit port ({parts.port}).")

        return candidate, findings
    except ValueError:
        return candidate, ["Could not parse this URL."]

def email_domain(address):
    match = re.search(r"@([^>\s]+)", address or "")
    return match.group(1).strip().lower().rstrip(".") if match else None

def analyze_email(text):
    findings = []
    message = Parser(policy=policy.default).parsestr(text)

    sender = message.get("From", "")
    reply_to = message.get("Reply-To", "")
    sender_domain = email_domain(sender)
    reply_domain = email_domain(reply_to)

    if sender and not sender_domain:
        add(findings, "Could not identify the sender's email domain.")
    if sender_domain and reply_domain and sender_domain != reply_domain:
        add(findings, "Reply-To domain differs from the From domain.")

    auth_results = " ".join(message.get_all("Authentication-Results", []))
    if auth_results:
        for check in ("spf", "dkim", "dmarc"):
            if re.search(rf"\b{check}\s*=\s*fail\b", auth_results, re.I):
                add(findings, f"Email authentication results report {check.upper()} failure.")
    else:
        add(findings, "No Authentication-Results header found; authentication could not be assessed.")

    body = text.lower()
    for term in URGENCY_TERMS:
        if term in body:
            add(findings, f"Message uses pressure or account/payment language: “{term}”.")

    urls = []
    for match in URL_RE.findall(text):
        url, url_findings = analyze_url(match)
        urls.append((url, url_findings))

    return message, findings, urls

def print_findings(title, findings):
    print(title)
    if findings:
        for finding in findings:
            print(f"  - {finding}")
    else:
        print("  - No obvious warning signs found by these checks.")

def main():
    parser = argparse.ArgumentParser(description="Offline email and URL threat triage")
    parser.add_argument("--url", help="URL to analyze")
    parser.add_argument("--email", help="Path to an .eml or text email file; use - for stdin")
    args = parser.parse_args()

    if not args.url and not args.email:
        parser.error("provide --url and/or --email")

    if args.url:
        url, findings = analyze_url(args.url)
        print(f"URL: {url}")
        print_findings("Signals:", findings)

    if args.email:
        if args.email == "-":
            import sys
            text = sys.stdin.read()
        else:
            with open(args.email, encoding="utf-8", errors="replace") as file:
                text = file.read()

        message, findings, urls = analyze_email(text)
        print(f"\nEmail subject: {message.get('Subject', '(none)')}")
        print(f"From: {message.get('From', '(unknown)')}")
        print_findings("Email signals:", findings)

        if urls:
            print("\nURLs found:")
            for url, url_findings in urls:
                print(f"  {url}")
                for finding in url_findings:
                    print(f"    - {finding}")
                if not url_findings:
                    print("    - No obvious warning signs found by these checks.")
        else:
            print("\nNo HTTP or HTTPS URLs found.")

if __name__ == "__main__":
    main()
