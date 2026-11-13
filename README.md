# Email and URL Threat Analysis
This tool is an offline Risk Triage Utility designed to help security analysts or curious users identify common indicators of phishing and social engineering.

Unlike many security tools, it is strictly offline. It does not connect to the internet, does not "ping" the URLs it analyzes, and does not send any data to a cloud service. This makes it safe to use for analyzing potentially malicious links without accidentally triggering a "hit" for the attacker or exposing your IP address.

Here is a detailed breakdown of the analysis it performs:

### 1. URL Threat Analysis

The tool inspects the structure and metadata of a URL to find common "red flags" used by attackers:

Protocol Check: Flags URLs that use http instead of the secure https.

IP-Based Hosting: Flags URLs that use a raw IP address (e.g., http://192.168.1.1/login) instead of a domain name, a common tactic in low-effort phishing.

Punycode Detection: Detects internationalized domain names (IDNs) that use "homoglyphs" (characters from different alphabets that look identical to Latin characters) to trick the user.

URL Shorteners: Flags services like Bitly or TinyURL, which are often used to hide the final destination of a malicious link.

Risky File Extensions: Identifies links pointing directly to executable or script files (e.g., .exe, .vbs, .ps1, .iso).

Structural Anomalies: Flags unusually long hostnames or hostnames with an excessive number of hyphens, which are typical of auto-generated phishing domains.

### 2. Look-Alike Domain Detection

The tool compares the analyzed domain against a list of high-value targets (like Google, Microsoft, and PayPal) using two methods:

Typosquatting (Edit Distance): It uses the Levenshtein distance algorithm to see if a domain is "nearly" identical to a trusted one. For example, if the tool sees g00gle.com, it recognizes that only two characters differ from google.com and flags it.

Subdomain Deception: It detects when a trusted brand is used as a prefix to a different domain (e.g., microsoft.com.security-update.net), a tactic designed to trick users who only read the first part of a URL.

### 3. Email Header & Body Analysis

When analyzing an .eml file or raw email text, the tool looks for signs of identity spoofing and psychological manipulation:

Sender Mismatch: It compares the From address with the Reply-To address. If they point to different domains, it is a strong indicator of a phishing attempt.

Authentication Failures: It scans the Authentication-Results header for fail markers in SPF, DKIM, and DMARC records, which indicate the email may not have been sent by the claimed sender.

Urgency Detection: It scans the email body for "pressure language" (e.g., "account suspended," "act now," "wire transfer") used to rush the victim into making a mistake.

### Important Limitations

It is critical to understand that this tool provides indicators, not a verdict.

No Reputation Checks: It does not check if a URL is on a global "blacklist" because it is offline.

No Sandbox: It does not execute code or follow redirects to see where a shortened link actually leads.

No False-Positive Protection: A legitimate company might occasionally use a URL shortener or have a misconfigured SPF record.

Verdict: Use this tool to decide if a link is "suspicious enough" to warrant further investigation in a secure, isolated environment (like a virtual machine or sandbox).

### Usage:
Navigate to containing directory in terminal and launch it like this:

To analyze a single URL:
```
python threat_triage.py --url "https://g00gle.com"
```

To analyze an email file:
```
python threat_triage.py --email suspicious.eml
```

To pipe email text directly into the tool:
```
cat suspicious.eml | python threat_triage.py --email -
```
