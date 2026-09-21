# aurascope
arkdown
# 🛡️ AuraScope

**AI-Native Unified Security Scanner bridging Web, Hardware, and OS telemetry.**

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org)
[![FastMCP](https://img.shields.io/badge/FastMCP-Enabled-brightgreen.svg)](https://github.com)
[![AIAura](https://img.shields.io/badge/AI_Integration-AIAura.me-purple.svg)](https://aiaura.me)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

AuraScope is a modular vulnerability assessment framework designed for modern security workflows. Instead of generating noisy, static reports, AuraScope routes raw OS, hardware, and web vulnerability telemetry through **[AIAura.me](https://aiaura.me)** via the Model Context Protocol (MCP) for intelligent triage, context-aware analysis, and automated remediation scripting.

## ✨ Features

*   **SysOps Engine:** Gathers hardware configurations and evaluates local OS security posture (Windows/Linux) for privilege escalation paths, missing patches, and weak access controls without invasive operations.
*   **Web Engine:** Performs non-intrusive DAST checks including TLS state analysis, security header audits, and sensitive endpoint exposure detection.
*   **AIAura Integration Node:** A built-in FastMCP server that bridges scan results directly into `aiaura.me`.
*   **Actionable AI Output:** Cross-references hardware/OS states against web vulnerabilities to determine actual exploitability, generating targeted PowerShell or Bash remediation scripts.

## 🏗️ Architecture

```text
aurascope/
├── core/
│   ├── sys_scanner.py     # OS and Hardware telemetry (Linux/Windows)
│   └── web_scanner.py     # DAST and endpoint exposure wrappers
├── mcp_server/
│   └── server.py          # FastMCP bridge connecting to aiaura.me
└── main.py                # Unified CLI Entry Point
🚀 Installation
Clone the repository:

Bash
git clone [https://github.com/JoaquinHernandez/AuraScope.git](https://github.com/JoaquinHernandez/AuraScope.git)
cd AuraScope
Install dependencies:

Bash
pip install -r requirements.txt
💻 Usage
AuraScope provides a unified CLI to run individual modules or execute comprehensive, AI-assisted audits.

Local Hardware & OS Audit
Analyze local configurations and kernel settings:

Bash
python main.py --sys
Web Target Audit
Scan a specific domain for security headers and endpoint hygiene:

Bash
python main.py --web example.com
🧠 The AIAura Pipeline (Full Assessment)
Run a combined scan and pipe the JSON payload directly to aiaura.me to generate contextual remediation playbooks:

Bash
export AIAURA_API_KEY="your-api-key"
python main.py --sys --web example.com --ai
Launch FastMCP Server
Run AuraScope continuously as a background Model Context Protocol tool provider:

Bash
python mcp_server/server.py
🤝 Contributing
Contributions, issues, and feature requests are welcome! Feel free to check the issues page.

📄 License
This project is licensed under the MIT License.
Running the System
Install requirements:

Bash
pip install -r requirements.txt
Execute a local unified audit:

Bash
python main.py --sys --web example.com
Execute with AI remediation generation:

Bash
export AIAURA_API_KEY="your-api-key"
python main.py --sys --web example.com --ai
Launch as a background FastMCP server:

Bash
python mcp_server/server.py
