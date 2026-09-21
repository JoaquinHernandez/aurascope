import argparse
import json
from core.sys_scanner import SysOpsScanner
from core.web_scanner import WebScanner
from mcp_server.server import dispatch_to_aiaura

def main():
    parser = argparse.ArgumentParser(description="AuraScope Unified Security Scanner")
    parser.add_argument("--sys", action="store_true", help="Audit local hardware and OS posture")
    parser.add_argument("--web", type=str, help="Target URL for web vulnerability checks")
    parser.add_argument("--ai", action="store_true", help="Pipe results to https://aiaura.me for triage")
    args = parser.parse_args()

    results = {}

    if args.sys:
        print("[*] Initiating Hardware & OS audit...")
        sys_engine = SysOpsScanner()
        results["sys_audit"] = sys_engine.scan_all()

    if args.web:
        print(f"[*] Initiating Web audit against: {args.web}...")
        web_engine = WebScanner()
        results["web_audit"] = web_engine.scan_target(args.web)

    if not args.sys and not args.web:
        parser.print_help()
        return

    payload = json.dumps(results, indent=2)

    if args.ai:
        print("[*] Transmitting audit payload to https://aiaura.me via MCP pipeline...")
        ai_response = dispatch_to_aiaura(payload, audit_scope="Unified-Assessment")
        print("\n=== AIAura Intelligent Triage & Remediation Plan ===")
        print(ai_response)
    else:
        print("\n=== Scan Results ===")
        print(payload)

if __name__ == "__main__":
    main()
