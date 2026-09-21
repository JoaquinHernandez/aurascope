import os
import json
import httpx
from fastmcp import FastMCP
from core.sys_scanner import SysOpsScanner
from core.web_scanner import WebScanner

mcp = FastMCP("AuraScope-Bridge")
sys_scanner = SysOpsScanner()
web_scanner = WebScanner()

AIAURA_API_ENDPOINT = os.getenv("AIAURA_ENDPOINT", "https://aiaura.me/api/v1/analyze")
AIAURA_API_KEY = os.getenv("AIAURA_API_KEY", "")

@mcp.tool()
def audit_host_system() -> str:
    """Performs a comprehensive audit of local OS configurations and hardware states."""
    data = sys_scanner.scan_all()
    return json.dumps(data, indent=2)

@mcp.tool()
def audit_web_application(target_url: str) -> str:
    """Scans a target web domain for missing security controls, headers, and exposed endpoints."""
    data = web_scanner.scan_target(target_url)
    return json.dumps(data, indent=2)

@mcp.tool()
def dispatch_to_aiaura(telemetry_payload: str, audit_scope: str) -> str:
    """Sends scan telemetry to aiaura.me for AI risk triage and remediation generation."""
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {AIAURA_API_KEY}"
    }

    body = {
        "source": "AuraScope-Agent",
        "scope": audit_scope,
        "telemetry": json.loads(telemetry_payload),
        "task": "Evaluate real-world risk, eliminate false positives, and output a hardening script."
    }

    try:
        with httpx.Client(timeout=30.0) as client:
            response = client.post(AIAURA_API_ENDPOINT, json=body, headers=headers)
            if response.status_code == 200:
                return response.text
            return json.dumps({
                "error": f"AIAura returned status {response.status_code}",
                "body": response.text
            })
    except Exception as exc:
        return json.dumps({"error": f"Failed to dispatch to aiaura.me: {str(exc)}"})

if __name__ == "__main__":
    mcp.run()
