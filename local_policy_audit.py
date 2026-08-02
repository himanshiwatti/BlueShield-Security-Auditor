import platform
import subprocess
import json

def audit_local_security_policy():
    findings = []
    is_windows = platform.system().lower() == 'windows'

    if not is_windows:
        findings.append({
            "module": "Local Security Policy",
            "check_name": "User Account Control (UAC) & Audit Policy",
            "status": "Unable to Scan",
            "severity": "CRITICAL",
            "description": "Scan Failed / Unable to Scan: Windows Local Security Policy audit requires Microsoft Windows OS. Current OS: " + platform.system() + ".",
            "recommendation": "Execute BlueShield Auditor on Microsoft Windows with Administrator privileges.",
            "fix_script": ""
        })
        return findings

    try:
        ps_cmd = "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' | Select-Object EnableLUA, ConsentPromptBehaviorAdmin, PromptOnSecureDesktop | ConvertTo-Json"
        out = subprocess.check_output(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd], stderr=subprocess.STDOUT, text=True, timeout=10)
        
        uac_data = json.loads(out.strip())
        enable_lua = uac_data.get("EnableLUA", 0)
        consent_prompt = uac_data.get("ConsentPromptBehaviorAdmin", 0)

        if enable_lua == 1:
            findings.append({
                "module": "Local Security Policy",
                "check_name": "User Account Control (UAC) System Status",
                "status": "PASS",
                "severity": "CRITICAL",
                "description": f"User Account Control (UAC) is ENABLED (EnableLUA = 1, ConsentPrompt = {consent_prompt}).",
                "recommendation": "Maintain UAC enabled at all times.",
                "fix_script": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -Value 1"
            })
        else:
            findings.append({
                "module": "Local Security Policy",
                "check_name": "User Account Control (UAC) System Status",
                "status": "FAIL",
                "severity": "CRITICAL",
                "description": "User Account Control (UAC) is DISABLED! Applications can execute silently with administrator rights.",
                "recommendation": "Enable UAC in Windows Control Panel or Registry.",
                "fix_script": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -Value 1"
            })
    except Exception as e:
        err_msg = str(e).strip()
        findings.append({
            "module": "Local Security Policy",
            "check_name": "User Account Control (UAC) & Audit Policy",
            "status": "Scan Failed",
            "severity": "CRITICAL",
            "description": f"Scan Failed: Unable to read Windows Local Security Policy registry settings. Reason: {err_msg}",
            "recommendation": "Run PowerShell as Administrator to query Local Security Policy keys.",
            "fix_script": ""
        })

    return findings

