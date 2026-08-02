import subprocess
import platform

def audit_antivirus():
    findings = []
    is_windows = platform.system().lower() == 'windows'

    if not is_windows:
        findings.append({
            "module": "Antivirus Audit",
            "check_name": "Active Registered Endpoint Protection Engine",
            "status": "Unable to Scan",
            "severity": "CRITICAL",
            "description": "Scan Failed / Unable to Scan: Windows SecurityCenter2 WMI namespace is only available on Microsoft Windows OS. Current OS: " + platform.system() + ".",
            "recommendation": "Execute BlueShield Auditor on Microsoft Windows with Administrator privileges for live scanning.",
            "fix_script": ""
        })
        return findings

    try:
        cmd = "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object displayName, productState"
        out = subprocess.check_output(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd], stderr=subprocess.STDOUT, text=True, timeout=10)
        
        products = []
        for line in out.splitlines():
            line_str = line.strip()
            if line_str and not line_str.startswith("displayName") and not line_str.startswith("-----------"):
                parts = [p.strip() for p in line_str.split() if p.strip()]
                if len(parts) >= 1:
                    products.append(line_str)

        if products:
            findings.append({
                "module": "Antivirus Audit",
                "check_name": "Active Registered Endpoint Protection Engine",
                "status": "PASS",
                "severity": "CRITICAL",
                "description": f"Active Endpoint Protection detected via SecurityCenter2: {', '.join(products)}.",
                "recommendation": "Maintain daily signature update schedules and keep endpoint protection active.",
                "fix_script": "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct"
            })
        else:
            findings.append({
                "module": "Antivirus Audit",
                "check_name": "Active Registered Endpoint Protection Engine",
                "status": "FAIL",
                "severity": "CRITICAL",
                "description": "No registered antivirus or endpoint protection software detected in SecurityCenter2 WMI.",
                "recommendation": "Install and register an approved enterprise antivirus or enable Windows Defender.",
                "fix_script": "Start-Service WinDefend"
            })
    except Exception as e:
        err_msg = str(e).strip()
        findings.append({
            "module": "Antivirus Audit",
            "check_name": "Active Registered Endpoint Protection Engine",
            "status": "Scan Failed",
            "severity": "CRITICAL",
            "description": f"Scan Failed: Unable to query Windows SecurityCenter2 WMI namespace. Reason: {err_msg}",
            "recommendation": "Ensure the Windows Security Center service (wscsvc) is running and execute with Administrator rights.",
            "fix_script": "Get-Service wscsvc | Start-Service"
        })

    return findings

