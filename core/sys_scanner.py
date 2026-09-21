import os
import sys
import platform
import subprocess
import psutil
from typing import Dict, Any, List

class SysOpsScanner:
    def __init__(self):
        self.os_type = platform.system().lower()

    def scan_all(self) -> Dict[str, Any]:
        return {
            "platform": {
                "os": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "architecture": platform.machine()
            },
            "hardware": self._audit_hardware(),
            "os_posture": self._audit_os_posture()
        }

    def _audit_hardware(self) -> Dict[str, Any]:
        hw_data = {
            "cpu_count_physical": psutil.cpu_count(logical=False),
            "cpu_count_logical": psutil.cpu_count(logical=True),
            "total_ram_gb": round(psutil.virtual_memory().total / (1024 ** 3), 2),
            "storage_partitions": []
        }

        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                hw_data["storage_partitions"].append({
                    "device": part.device,
                    "mountpoint": part.mountpoint,
                    "fstype": part.fstype,
                    "total_gb": round(usage.total / (1024 ** 3), 2),
                    "used_percent": usage.percent
                })
            except (PermissionError, FileNotFoundError):
                continue

        # Hardware-specific firmware telemetry
        if self.os_type == "linux":
            hw_data["firmware"] = self._run_command(["cat", "/sys/class/dmi/id/bios_version"])
        elif self.os_type == "windows":
            hw_data["firmware"] = self._run_command([
                "powershell", "-NoProfile", "-Command", 
                "(Get-CimInstance -ClassName Win32_BIOS).SMBIOSBIOSVersion"
            ])

        return hw_data

    def _audit_os_posture(self) -> Dict[str, Any]:
        posture = {
            "elevated_privileges": self._is_admin(),
            "misconfigurations": [],
            "running_security_agents": self._detect_security_agents()
        }

        if self.os_type == "linux":
            posture["misconfigurations"].extend(self._check_linux_posture())
        elif self.os_type == "windows":
            posture["misconfigurations"].extend(self._check_windows_posture())

        return posture

    def _is_admin(self) -> bool:
        try:
            if self.os_type == "windows":
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            return os.geteuid() == 0
        except Exception:
            return False

    def _detect_security_agents(self) -> List[str]:
        known_agents = ["sentinelone", "wazuh", "clamav", "falco", "qualys", "carbonblack"]
        active_agents = []
        
        for proc in psutil.process_iter(attrs=['name']):
            try:
                proc_name = proc.info['name'].lower()
                for agent in known_agents:
                    if agent in proc_name and agent not in active_agents:
                        active_agents.append(agent)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return active_agents

    def _check_linux_posture(self) -> List[Dict[str, str]]:
        findings = []
        # Check world-writable files in sensitive directories
        cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly"]
        for cron_path in cron_dirs:
            if os.path.exists(cron_path):
                mode = os.stat(cron_path).st_mode
                if mode & 0o002:
                    findings.append({
                        "severity": "HIGH",
                        "check": "World-Writable Cron Directory",
                        "details": f"Directory {cron_path} has write permissions for other users."
                    })
        return findings

    def _check_windows_posture(self) -> List[Dict[str, str]]:
        findings = []
        # Check unquoted service paths
        ps_cmd = (
            "Get-CimInstance -ClassName Win32_Service | "
            "Where-Object { $_.PathName -notmatch '\"' -and $_.PathName -match ' ' } | "
            "Select-Object -ExpandProperty Name"
        )
        output = self._run_command(["powershell", "-NoProfile", "-Command", ps_cmd])
        if output:
            services = [s.strip() for s in output.splitlines() if s.strip()]
            for svc in services:
                findings.append({
                    "severity": "MEDIUM",
                    "check": "Unquoted Service Path",
                    "details": f"Service '{svc}' has spaces in its binary path without quotation marks."
                })
        return findings

    def _run_command(self, cmd: List[str]) -> str:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=5, check=False
            )
            return result.stdout.strip()
        except Exception:
            return ""
