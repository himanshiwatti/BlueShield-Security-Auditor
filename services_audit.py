import subprocess
import platform
import json

def audit_windows_services():
    findings = []
    is_windows = platform.system().lower() == 'windows'
    run_in = "PowerShell (Run as Administrator)"

    if not is_windows:
        findings.append({
            "module": "Windows Services",
            "check_name": "Insecure Windows Services Audit",
            "status": "Unable to Scan",
            "severity": "CRITICAL",
            "description": f"[Run in: {run_in}] Scan Failed / Unable to Scan: This check requires Microsoft Windows OS. Current OS: {platform.system()}.",
            "recommendation": "Execute BlueShield Auditor on Microsoft Windows with Administrator privileges.",
            "fix_script": ""
        })
        return findings

    try:
        cmd = "Get-Service RemoteRegistry, Spooler, TlntSvr -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, Status, StartType | ConvertTo-Json"
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd], 
            stderr=subprocess.STDOUT, text=True, timeout=15
        )
        
        services_data = json.loads(out.strip()) if out.strip() else []
        if isinstance(services_data, dict):
            services_data = [services_data]

        svc_map = {s.get("Name"): s for s in services_data if s}

        # 1. Remote Registry Check
        rem_reg = svc_map.get("RemoteRegistry")
        if rem_reg and (rem_reg.get("Status") == "Running"):
            findings.append({
                "module": "Windows Services",
                "check_name": "Remote Registry Service (RemoteRegistry)",
                "status": "FAIL",
                "severity": "CRITICAL",
                "description": f"[Run in: {run_in}] Remote Registry service is RUNNING! Remote users can query or modify registry keys. This is a major security risk.",
                "recommendation": "Disable Remote Registry service immediately.",
                "fix_script": "Set-Service -Name 'RemoteRegistry' -StartupType Disabled; Stop-Service -Name 'RemoteRegistry' -Force"
            })
        else:
            findings.append({
                "module": "Windows Services",
                "check_name": "Remote Registry Service (RemoteRegistry)",
                "status": "PASS",
                "severity": "CRITICAL",
                "description": f"[Run in: {run_in}] Remote Registry service is STOPPED/DISABLED or Not Installed. Good.",
                "recommendation": "Keep Remote Registry disabled.",
                "fix_script": ""  # PASS hai to fix script nahi chahiye
            })

        # 2. Spooler Check
        spooler = svc_map.get("Spooler")
        if spooler and (spooler.get("Status") == "Running"):
            findings.append({
                "module": "Windows Services",
                "check_name": "Print Spooler Service (Spooler)",
                "status": "WARN",
                "severity": "HIGH",
                "description": f"[Run in: {run_in}] Print Spooler service is RUNNING. On servers without printers, this increases attack surface (PrintNightmare vulnerability).",
                "recommendation": "Disable Print Spooler if you don't use printers.",
                "fix_script": "Stop-Service -Name 'Spooler' -Force; Set-Service -Name 'Spooler' -StartupType Disabled"
            })
        else:
            findings.append({
                "module": "Windows Services",
                "check_name": "Print Spooler Service (Spooler)",
                "status": "PASS",
                "severity": "HIGH",
                "description": f"[Run in: {run_in}] Print Spooler service is STOPPED/DISABLED. Good.",
                "recommendation": "Maintain Spooler service disabled on non-print servers.",
                "fix_script": ""
            })
            
        # 3. Telnet Check
        telnet = svc_map.get("TlntSvr")
        if telnet and (telnet.get("Status") == "Running"):
            findings.append({
                "module": "Windows Services",
                "check_name": "Telnet Service (TlntSvr)",
                "status": "FAIL",
                "severity": "CRITICAL",
                "description": f"[Run in: {run_in}] Telnet service is RUNNING. Telnet sends passwords in plain text. Highly insecure.",
                "recommendation": "Disable Telnet service immediately.",
                "fix_script": "Stop-Service -Name 'TlntSvr' -Force; Set-Service -Name 'TlntSvr' -StartupType Disabled"
            })
        else:
            findings.append({
                "module": "Windows Services",
                "check_name": "Telnet Service (TlntSvr)",
                "status": "PASS",
                "severity": "CRITICAL",
                "description": f"[Run in: {run_in}] Telnet service is STOPPED/DISABLED or Not Installed. Good.",
                "recommendation": "Ensure Telnet remains disabled.",
                "fix_script": ""
            })

    except subprocess.CalledProcessError as e:
        findings.append({
            "module": "Windows Services",
            "check_name": "Insecure Windows Services Audit",
            "status": "Scan Failed",
            "severity": "CRITICAL",
            "description": f"[Run in: {run_in}] Scan Failed: PowerShell could not query services. Reason: {e.output.strip()}. Please run the app as Administrator.",
            "recommendation": "Right-click on CMD/PowerShell and select 'Run as Administrator', then run BlueShield.",
            "fix_script": ""
        })
    except Exception as e:
        findings.append({
            "module": "Windows Services",
            "check_name": "Insecure Windows Services Audit",
            "status": "Scan Failed",
            "severity": "CRITICAL",
            "description": f"[Run in: {run_in}] Scan Failed: Unexpected error. Reason: {str(e)}",
            "recommendation": "Check if PowerShell is installed and run as Administrator.",
            "fix_script": ""
        })

    return findings