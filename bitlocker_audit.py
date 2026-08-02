import subprocess
import platform

def audit_bitlocker():
    findings = []
    is_windows = platform.system().lower() == 'windows'

    if not is_windows:
        findings.append({
            "module": "BitLocker",
            "check_name": "System Drive Encryption (C: Volume)",
            "status": "Unable to Scan",
            "severity": "CRITICAL",
            "description": "Scan Failed / Unable to Scan: BitLocker PowerShell commands (Get-BitLockerVolume) are only supported on Microsoft Windows OS. Current OS: " + platform.system() + ".",
            "recommendation": "Run BlueShield Auditor on Windows with Administrator privileges for live BitLocker volume inspection.",
            "fix_script": ""
        })
        return findings

    try:
        cmd = "Get-BitLockerVolume -MountPoint 'C:' | Select-Object ProtectionStatus, VolumeStatus, EncryptionPercentage | ConvertTo-Json"
        out = subprocess.check_output(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd], stderr=subprocess.STDOUT, text=True, timeout=10)
        
        if "ProtectionStatus" in out:
            if '"ProtectionStatus": 1' in out or '"ProtectionStatus": "On"' in out or 'On' in out:
                findings.append({
                    "module": "BitLocker",
                    "check_name": "System Drive Encryption (C: Volume)",
                    "status": "PASS",
                    "severity": "CRITICAL",
                    "description": "BitLocker Drive Encryption is ACTIVE on Volume C:.",
                    "recommendation": "Ensure TPM protector is enforced.",
                    "fix_script": "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector"
                })
            else:
                findings.append({
                    "module": "BitLocker",
                    "check_name": "System Drive Encryption (C: Volume)",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "description": "BitLocker Drive Encryption is DISABLED or OFF on Volume C:! Physical access allows offline data extraction.",
                    "recommendation": "Enable BitLocker encryption on primary drive C: immediately.",
                    "fix_script": "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector"
                })
        else:
            findings.append({
                "module": "BitLocker",
                "check_name": "System Drive Encryption (C: Volume)",
                "status": "Scan Failed",
                "severity": "CRITICAL",
                "description": f"Scan Failed: Unexpected BitLocker output format. Output: {out.strip()[:200]}",
                "recommendation": "Verify BitLocker feature is installed on Windows.",
                "fix_script": "Install-WindowsFeature BitLocker"
            })
    except Exception as e:
        err_msg = str(e).strip()
        findings.append({
            "module": "BitLocker",
            "check_name": "System Drive Encryption (C: Volume)",
            "status": "Scan Failed",
            "severity": "CRITICAL",
            "description": f"Scan Failed: Unable to query BitLocker status on C:. Reason: {err_msg} (Administrator privileges required)",
            "recommendation": "Run PowerShell as Administrator to grant BitLocker management rights.",
            "fix_script": "Get-BitLockerVolume -MountPoint 'C:'"
        })

    return findings

