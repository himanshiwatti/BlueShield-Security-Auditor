import platform
import subprocess

def audit_startup_programs():
    findings = []
    is_windows = platform.system().lower() == 'windows'

    if not is_windows:
        findings.append({
            "module": "Startup Programs",
            "check_name": "Autorun & Startup Persistence Audit",
            "status": "Unable to Scan",
            "severity": "HIGH",
            "description": "Scan Failed / Unable to Scan: Windows Startup Command WMI and registry inspection requires Microsoft Windows OS. Current OS: " + platform.system() + ".",
            "recommendation": "Execute BlueShield Auditor on Microsoft Windows with Administrator privileges.",
            "fix_script": ""
        })
        return findings

    try:
        ps_cmd = "Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location | ConvertTo-Json"
        out = subprocess.check_output(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd], stderr=subprocess.STDOUT, text=True, timeout=10)
        
        if out.strip():
            findings.append({
                "module": "Startup Programs",
                "check_name": "Autorun Persistence Registry Audit",
                "status": "PASS",
                "severity": "MEDIUM",
                "description": "Autorun startup commands queried successfully via WMI Win32_StartupCommand.",
                "recommendation": "Regularly monitor HKLM/HKCU Run keys and Task Manager Startup tab.",
                "fix_script": "Get-CimInstance Win32_StartupCommand"
            })
        else:
            findings.append({
                "module": "Startup Programs",
                "check_name": "Autorun Persistence Registry Audit",
                "status": "PASS",
                "severity": "MEDIUM",
                "description": "No unmanaged autorun entries detected in standard Win32_StartupCommand locations.",
                "recommendation": "Regularly monitor HKLM/HKCU Run keys.",
                "fix_script": ""
            })

    except Exception as e:
        err_msg = str(e).strip()
        findings.append({
            "module": "Startup Programs",
            "check_name": "Autorun & Startup Persistence Audit",
            "status": "Scan Failed",
            "severity": "HIGH",
            "description": f"Scan Failed: Unable to query Win32_StartupCommand. Reason: {err_msg}",
            "recommendation": "Run PowerShell as Administrator to query startup entries.",
            "fix_script": "Get-CimInstance Win32_StartupCommand"
        })

    return findings

