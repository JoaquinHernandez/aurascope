import httpx
from typing import Dict, Any, List
from urllib.parse import urlparse

class WebScanner:
    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout
        self.client = httpx.Client(
            timeout=self.timeout,
            follow_redirects=True,
            verify=True,
            headers={"User-Agent": "AuraScope-SecurityAudit/1.0"}
        )

    def scan_target(self, target_url: str) -> Dict[str, Any]:
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        parsed = urlparse(target_url)
        domain = parsed.netloc

        report = {
            "target": target_url,
            "host": domain,
            "findings": []
        }

        try:
            response = self.client.get(target_url)
            report["status_code"] = response.status_code
            report["findings"].extend(self._audit_security_headers(response.headers))
            report["findings"].extend(self._audit_information_disclosure(response.headers))
        except httpx.RequestError as exc:
            report["findings"].append({
                "severity": "CRITICAL",
                "check": "Target Availability",
                "details": f"Failed connection to {target_url}: {str(exc)}"
            })
            return report

        # Common sensitive endpoints audit
        report["findings"].extend(self._check_sensitive_paths(target_url))
        return report

    def _audit_security_headers(self, headers: httpx.Headers) -> List[Dict[str, str]]:
        findings = []
        required_headers = {
            "Strict-Transport-Security": ("HIGH", "HSTS missing; communication vulnerable to downgrade attacks."),
            "Content-Security-Policy": ("MEDIUM", "CSP header missing; elevated exposure to client-side injection."),
            "X-Frame-Options": ("LOW", "X-Frame-Options missing; potentially susceptible to clickjacking."),
            "X-Content-Type-Options": ("LOW", "X-Content-Type-Options missing; MIME-type sniffing enabled.")
        }

        for header, (severity, issue) in required_headers.items():
            if header.lower() not in [k.lower() for k in headers.keys()]:
                findings.append({
                    "severity": severity,
                    "check": f"Missing Header: {header}",
                    "details": issue
                })
        return findings

    def _audit_information_disclosure(self, headers: httpx.Headers) -> List[Dict[str, str]]:
        findings = []
        disclosure_headers = ["server", "x-powered-by", "x-aspnet-version"]

        for h in disclosure_headers:
            val = headers.get(h)
            if val:
                findings.append({
                    "severity": "LOW",
                    "check": f"Information Disclosure: {h}",
                    "details": f"Header exposes runtime/stack details: '{val}'"
                })
        return findings

    def _check_sensitive_paths(self, base_url: str) -> List[Dict[str, str]]:
        findings = []
        sensitive_paths = ["/.env", "/.git/HEAD", "/robots.txt"]

        for path in sensitive_paths:
            test_url = base_url.rstrip("/") + path
            try:
                res = self.client.get(test_url)
                if res.status_code == 200 and len(res.text) > 0:
                    severity = "CRITICAL" if ".env" in path or ".git" in path else "INFO"
                    findings.append({
                        "severity": severity,
                        "check": f"Exposed Endpoint: {path}",
                        "details": f"Path accessible with HTTP 200 (length: {len(res.text)} bytes)."
                    })
            except httpx.RequestError:
                continue

        return findings
