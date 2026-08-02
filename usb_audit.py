import platform
import subprocess

def audit_usb_security():
    findings = []
    is_windows = platform.system().lower() == 'windows'

    if not is_windows:
        findings.append({
            "module": "USB Security",
            "check_name": "USB Storage & AutoRun Policy Audit",
            "status": "Unable to Scan",
            "severity": "CRITICAL",
            "description": "Scan Failed / Unable to Scan: USB AutoRun and PnP Device inspection requires Microsoft Windows OS. Current OS: " + platform.system() + ".",
            "recommendation": "Execute BlueShield Auditor on Microsoft Windows with Administrator privileges.",
            "fix_script": ""
        })
        return findings

    try:
        ps_cmd = "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -ErrorAction SilentlyContinue).NoDriveTypeAutoRun"
        out = subprocess.check_output(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd], stderr=subprocess.STDOUT, text=True, timeout=10)
        
        val_str = out.strip()
        if val_str and (val_str == "255" or val_str == "0xFF"):
            findings.append({
                "module": "USB Security",
                "check_name": "AutoRun / AutoPlay Executable Execution Policy",
                "status": "PASS",
                "severity": "CRITICAL",
                "description": f"AutoRun / AutoPlay for removable media is DISABLED (NoDriveTypeAutoRun = {val_str}).",
                "recommendation": "Maintain AutoRun restriction policy.",
                "fix_script": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255"
            })
        else:
            findings.append({
                "module": "USB Security",
                "check_name": "AutoRun / AutoPlay Executable Execution Policy",
                "status": "WARN",
                "severity": "CRITICAL",
                "description": f"AutoRun / AutoPlay policy is set to '{val_str or 'Not Configured'}'. May allow autorun executables on USB insertion.",
                "recommendation": "Enforce NoDriveTypeAutoRun = 255 via Registry or Group Policy.",
                "fix_script": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255"
            })

    except Exception as e:
        err_msg = str(e).strip()
        findings.append({
            "module": "USB Security",
            "check_name": "USB Storage & AutoRun Policy Audit",
            "status": "Scan Failed",
            "severity": "CRITICAL",
            "description": f"Scan Failed: Unable to query USB policies or PnP devices. Reason: {err_msg}",
            "recommendation": "Run PowerShell as Administrator to query registry settings.",
            "fix_script": ""
        })

    return findings

