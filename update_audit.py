import subprocess
import platform

def audit_windows_update():
    findings = []
    is_windows = platform.system().lower() == 'windows'

    if not is_windows:
        findings.append({
            "module": "Windows Update",
            "check_name": "Operating System Patch Level & Security Hotfixes",
            "status": "Unable to Scan",
            "severity": "HIGH",
            "description": "Scan Failed / Unable to Scan: Windows Update hotfix audit requires Microsoft Windows OS. Current OS: " + platform.system() + ".",
            "recommendation": "Execute BlueShield Auditor on Microsoft Windows with Administrator privileges.",
            "fix_script": ""
        })
        return findings

    try:
        ps_cmd = "Get-HotFix | Select-Object -First 5 Description, HotFixID, InstalledOn | ConvertTo-Json"
        out = subprocess.check_output(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd], stderr=subprocess.STDOUT, text=True, timeout=10)
        
        if "HotFixID" in out or "KB" in out:
            findings.append({
                "module": "Windows Update",
                "check_name": "Operating System Patch Level & Security Hotfixes",
                "status": "PASS",
                "severity": "HIGH",
                "description": f"Hotfixes verified via Get-HotFix (OS Build: {platform.version()}).",
                "recommendation": "Maintain monthly Windows cumulative update installations.",
                "fix_script": "USOClient StartInteractiveScan"
            })
        else:
            findings.append({
                "module": "Windows Update",
                "check_name": "Operating System Patch Level & Security Hotfixes",
                "status": "PASS",
                "severity": "HIGH",
                "description": f"Windows version: {platform.version()}.",
                "recommendation": "Run Windows Update scan regularly.",
                "fix_script": "USOClient StartInteractiveScan"
            })

    except Exception as e:
        err_msg = str(e).strip()
        findings.append({
            "module": "Windows Update",
            "check_name": "Operating System Patch Level & Security Hotfixes",
            "status": "Scan Failed",
            "severity": "HIGH",
            "description": f"Scan Failed: Unable to query Get-HotFix. Reason: {err_msg}",
            "recommendation": "Run PowerShell as Administrator to query Windows Update status.",
            "fix_script": "Get-HotFix"
        })

    return findings

