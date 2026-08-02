import subprocess
import platform

def audit_event_logs():
    findings = []
    is_windows = platform.system().lower() == 'windows'

    if not is_windows:
        findings.append({
            "module": "Event Log Analysis",
            "check_name": "Failed Logon Attempts Audit (Event ID 4625)",
            "status": "Unable to Scan",
            "severity": "HIGH",
            "description": "Scan Failed / Unable to Scan: Reading Windows Security Event Logs requires Microsoft Windows OS. Current OS: " + platform.system() + ".",
            "recommendation": "Execute BlueShield Auditor on Microsoft Windows with Administrator privileges.",
            "fix_script": ""
        })
        return findings

    try:
        cmd = "$events = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 100 -ErrorAction Stop; $events.Count"
        out = subprocess.check_output(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd], stderr=subprocess.STDOUT, text=True, timeout=10)
        
        failed_count = 0
        if out.strip().isdigit():
            failed_count = int(out.strip())

        if failed_count > 20:
            findings.append({
                "module": "Event Log Analysis",
                "check_name": "Failed Logon Attempts Audit (Event ID 4625)",
                "status": "WARN",
                "severity": "HIGH",
                "description": f"Elevated number of failed logon attempts detected ({failed_count} failed logons in recent Security event log). Potential brute-force activity.",
                "recommendation": "Review IP sources of Event ID 4625 in Event Viewer; enforce account lockout threshold.",
                "fix_script": "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 20 | Format-Table TimeCreated, Message"
            })
        else:
            findings.append({
                "module": "Event Log Analysis",
                "check_name": "Failed Logon Attempts Audit (Event ID 4625)",
                "status": "PASS",
                "severity": "MEDIUM",
                "description": f"Normal failed logon frequency recorded ({failed_count} failed logon events in recent Security log buffer).",
                "recommendation": "Maintain event log retention policy of at least 90 days.",
                "fix_script": ""
            })
    except Exception as e:
        err_msg = str(e).strip()
        findings.append({
            "module": "Event Log Analysis",
            "check_name": "Failed Logon Attempts Audit (Event ID 4625)",
            "status": "Scan Failed",
            "severity": "HIGH",
            "description": f"Scan Failed: Unable to read Windows Security Event Log. Reason: {err_msg} (Administrator privileges required to read Security Log)",
            "recommendation": "Run PowerShell as Administrator to grant access to the Security Event Log.",
            "fix_script": "Get-WinEvent -ListLog Security"
        })

    return findings

