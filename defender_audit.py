import subprocess
import platform
import json

def audit_windows_defender():
    findings = []
    is_windows = platform.system().lower() == 'windows'

    if not is_windows:
        findings.append({
            "module": "Windows Defender",
            "check_name": "Windows Defender Real-Time Protection & Status",
            "status": "Unable to Scan",
            "severity": "CRITICAL",
            "description": "Scan Failed / Unable to Scan: Get-MpComputerStatus PowerShell cmdlet requires Microsoft Windows OS. Current OS: " + platform.system() + ".",
            "recommendation": "Execute BlueShield Auditor on Microsoft Windows with Administrator privileges for live Defender inspection.",
            "fix_script": ""
        })
        return findings

    try:
        ps_cmd = "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, TamperProtectionEnabled, AntivirusSignatureAge, AntivirusSignatureVersion, QuickScanAge, FullScanAge | ConvertTo-Json"
        out = subprocess.check_output(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd], stderr=subprocess.STDOUT, text=True, timeout=10)
        
        status_data = json.loads(out.strip())
        
        realtime = status_data.get("RealTimeProtectionEnabled", False)
        tamper = status_data.get("TamperProtectionEnabled", False)
        sig_age = status_data.get("AntivirusSignatureAge", 999)
        sig_ver = status_data.get("AntivirusSignatureVersion", "Unknown")

        # Realtime Protection
        if realtime:
            findings.append({
                "module": "Windows Defender",
                "check_name": "Real-Time Antivirus Protection",
                "status": "PASS",
                "severity": "CRITICAL",
                "description": "Windows Defender Real-Time Protection is ACTIVE.",
                "recommendation": "Keep Real-Time Protection enabled at all times.",
                "fix_script": "Set-MpPreference -DisableRealtimeMonitoring $false"
            })
        else:
            findings.append({
                "module": "Windows Defender",
                "check_name": "Real-Time Antivirus Protection",
                "status": "FAIL",
                "severity": "CRITICAL",
                "description": "Windows Defender Real-Time Protection is DISABLED! The system is exposed to malware.",
                "recommendation": "Immediately enable Real-Time Protection in Windows Security.",
                "fix_script": "Set-MpPreference -DisableRealtimeMonitoring $false; Start-Service WinDefend"
            })

        # Tamper Protection
        if tamper:
            findings.append({
                "module": "Windows Defender",
                "check_name": "Tamper Protection Status",
                "status": "PASS",
                "severity": "HIGH",
                "description": "Tamper Protection is ENABLED.",
                "recommendation": "Maintain Tamper Protection via Windows Security.",
                "fix_script": "Set-MpPreference -DisableTamperProtection $false"
            })
        else:
            findings.append({
                "module": "Windows Defender",
                "check_name": "Tamper Protection Status",
                "status": "FAIL",
                "severity": "HIGH",
                "description": "Tamper Protection is DISABLED! Malware can modify Defender registry settings.",
                "recommendation": "Enable Tamper Protection via Windows Security.",
                "fix_script": "Set-MpPreference -DisableTamperProtection $false"
            })

        # Signature Freshness
        if isinstance(sig_age, (int, float)) and sig_age <= 7:
            findings.append({
                "module": "Windows Defender",
                "check_name": "Virus & Threat Definition Version",
                "status": "PASS",
                "severity": "HIGH",
                "description": f"Antivirus signatures are current (Version: {sig_ver}, Age: {sig_age} days).",
                "recommendation": "Maintain automatic definition updates.",
                "fix_script": "Update-MpSignature"
            })
        else:
            findings.append({
                "module": "Windows Defender",
                "check_name": "Virus & Threat Definition Version",
                "status": "WARN",
                "severity": "HIGH",
                "description": f"Antivirus signatures are outdated (Version: {sig_ver}, Age: {sig_age} days).",
                "recommendation": "Run Update-MpSignature immediately.",
                "fix_script": "Update-MpSignature"
            })

    except Exception as e:
        err_msg = str(e).strip()
        findings.append({
            "module": "Windows Defender",
            "check_name": "Windows Defender Real-Time Protection & Status",
            "status": "Scan Failed",
            "severity": "CRITICAL",
            "description": f"Scan Failed: Unable to query Windows Defender status. Reason: {err_msg}",
            "recommendation": "Ensure Windows Defender service (WinDefend) is active and execute with Administrator privileges.",
            "fix_script": "Start-Service WinDefend"
        })

    return findings

