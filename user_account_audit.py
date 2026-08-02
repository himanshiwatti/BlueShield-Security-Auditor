import subprocess
import platform
import json

def audit_user_accounts():
    findings = []
    is_windows = platform.system().lower() == 'windows'

    if not is_windows:
        findings.append({
            "module": "User Accounts",
            "check_name": "Local User Accounts & Administrator Audit",
            "status": "Unable to Scan",
            "severity": "CRITICAL",
            "description": "Scan Failed / Unable to Scan: Windows Get-LocalUser cmdlet requires Microsoft Windows OS. Current OS: " + platform.system() + ".",
            "recommendation": "Execute BlueShield Auditor on Microsoft Windows with Administrator privileges.",
            "fix_script": ""
        })
        return findings

    try:
        ps_cmd = "Get-LocalUser | Select-Object Name, Enabled | ConvertTo-Json"
        out = subprocess.check_output(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd], stderr=subprocess.STDOUT, text=True, timeout=10)
        
        users_data = json.loads(out.strip()) if out.strip() else []
        if isinstance(users_data, dict):
            users_data = [users_data]

        guest_user = next((u for u in users_data if u.get("Name", "").lower() == "guest"), None)
        if guest_user:
            is_enabled = guest_user.get("Enabled", False)
            if is_enabled:
                findings.append({
                    "module": "User Accounts",
                    "check_name": "Built-In Guest Account Status",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "description": "Built-in Guest account is ENABLED!",
                    "recommendation": "Disable the Guest account immediately.",
                    "fix_script": "Disable-LocalUser -Name 'Guest'"
                })
            else:
                findings.append({
                    "module": "User Accounts",
                    "check_name": "Built-In Guest Account Status",
                    "status": "PASS",
                    "severity": "CRITICAL",
                    "description": "Built-in Guest account is DISABLED.",
                    "recommendation": "Keep Guest account permanently disabled.",
                    "fix_script": "Disable-LocalUser -Name 'Guest'"
                })
        else:
            findings.append({
                "module": "User Accounts",
                "check_name": "Built-In Guest Account Status",
                "status": "PASS",
                "severity": "CRITICAL",
                "description": "Guest account not present or disabled on host.",
                "recommendation": "Keep Guest account disabled.",
                "fix_script": ""
            })

    except Exception as e:
        err_msg = str(e).strip()
        findings.append({
            "module": "User Accounts",
            "check_name": "Local User Accounts & Administrator Audit",
            "status": "Scan Failed",
            "severity": "CRITICAL",
            "description": f"Scan Failed: Unable to query Get-LocalUser. Reason: {err_msg}",
            "recommendation": "Run PowerShell as Administrator to query local accounts.",
            "fix_script": "Get-LocalUser"
        })

    return findings

