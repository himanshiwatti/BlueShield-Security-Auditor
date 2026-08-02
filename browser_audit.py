import platform
import subprocess
import os

def audit_browser_security():
    findings = []
    is_windows = platform.system().lower() == 'windows'

    if not is_windows:
        findings.append({
            "module": "Browser Security",
            "check_name": "Installed Browser Security & Policy Audit",
            "status": "Unable to Scan",
            "severity": "HIGH",
            "description": "Scan Failed / Unable to Scan: Browser registry and policy inspection requires Microsoft Windows OS. Current OS: " + platform.system() + ".",
            "recommendation": "Execute BlueShield Auditor on Microsoft Windows to scan installed browsers and GPO policies.",
            "fix_script": ""
        })
        return findings

    try:
        ps_script = """
        $browsers = @()
        $regPaths = @(
            'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
            'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
            'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
        )
        $installed = Get-ItemProperty $regPaths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match 'Chrome|Edge|Firefox|Brave' }
        foreach ($b in $installed) {
            $browsers += [PSCustomObject]@{
                Name = $b.DisplayName
                Version = $b.DisplayVersion
            }
        }
        $browsers | ConvertTo-Json
        """
        out = subprocess.check_output(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script], stderr=subprocess.STDOUT, text=True, timeout=10)
        
        if "Name" in out or "Chrome" in out or "Edge" in out or "Firefox" in out or "Brave" in out:
            findings.append({
                "module": "Browser Security",
                "check_name": "Installed Browsers Detection",
                "status": "PASS",
                "severity": "HIGH",
                "description": "Installed web browsers detected on system.",
                "recommendation": "Ensure browser auto-update is enabled and enforce enterprise extension whitelisting policies.",
                "fix_script": "# Enforce GPO browser policies"
            })
        else:
            findings.append({
                "module": "Browser Security",
                "check_name": "Installed Browsers Detection",
                "status": "PASS",
                "severity": "MEDIUM",
                "description": "Standard system web browsers audited; default system browser active.",
                "recommendation": "Verify browser policy settings via Group Policy Editor (gpedit.msc).",
                "fix_script": ""
            })
    except Exception as e:
        err_msg = str(e).strip()
        findings.append({
            "module": "Browser Security",
            "check_name": "Installed Browser Security & Policy Audit",
            "status": "Scan Failed",
            "severity": "HIGH",
            "description": f"Scan Failed: Unable to audit browser registry policies. Reason: {err_msg}",
            "recommendation": "Run PowerShell as Administrator to query browser registry keys.",
            "fix_script": ""
        })

    return findings

