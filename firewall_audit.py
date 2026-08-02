import subprocess
import platform
import json

def audit_windows_firewall():
    findings = []
    is_windows = platform.system().lower() == 'windows'

    if not is_windows:
        findings.append({
            "module": "Windows Firewall",
            "check_name": "Windows Firewall Profiles Audit",
            "status": "Unable to Scan",
            "severity": "CRITICAL",
            "description": "Scan Failed / Unable to Scan: Get-NetFirewallProfile PowerShell cmdlet requires Microsoft Windows OS. Current OS: " + platform.system() + ".",
            "recommendation": "Execute BlueShield Auditor on Microsoft Windows with Administrator privileges.",
            "fix_script": ""
        })
        return findings

    try:
        cmd = "Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction | ConvertTo-Json"
        out = subprocess.check_output(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd], stderr=subprocess.STDOUT, text=True, timeout=10)
        
        profiles_data = json.loads(out.strip())
        if isinstance(profiles_data, dict):
            profiles_data = [profiles_data]

        for prof in profiles_data:
            p_name = prof.get("Name", "Unknown")
            p_enabled = prof.get("Enabled", False)
            if p_enabled is True or p_enabled == 1 or str(p_enabled).lower() == "true":
                findings.append({
                    "module": "Windows Firewall",
                    "check_name": f"{p_name} Profile Firewall Status",
                    "status": "PASS",
                    "severity": "CRITICAL",
                    "description": f"{p_name} Firewall Profile is ACTIVE.",
                    "recommendation": f"Maintain {p_name} Firewall Profile enabled.",
                    "fix_script": f"Set-NetFirewallProfile -Profile {p_name} -Enabled True"
                })
            else:
                findings.append({
                    "module": "Windows Firewall",
                    "check_name": f"{p_name} Profile Firewall Status",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "description": f"{p_name} Firewall Profile is DISABLED! Exposure to network attack vectors.",
                    "recommendation": f"Enable {p_name} Firewall Profile immediately.",
                    "fix_script": f"Set-NetFirewallProfile -Profile {p_name} -Enabled True"
                })

    except Exception as e:
        err_msg = str(e).strip()
        findings.append({
            "module": "Windows Firewall",
            "check_name": "Windows Firewall Profiles Audit",
            "status": "Scan Failed",
            "severity": "CRITICAL",
            "description": f"Scan Failed: Unable to query NetFirewall profiles. Reason: {err_msg}",
            "recommendation": "Ensure mpssvc (Windows Defender Firewall) service is running and execute with Administrator privileges.",
            "fix_script": "Set-Service -Name mpssvc -StartupType Automatic; Start-Service mpssvc"
        })

    return findings

