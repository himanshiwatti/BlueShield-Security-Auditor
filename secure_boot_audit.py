import subprocess
import platform

def audit_secure_boot():
    findings = []
    is_windows = platform.system().lower() == 'windows'

    if not is_windows:
        findings.append({
            "module": "Secure Boot & Hardware Security",
            "check_name": "UEFI Secure Boot & TPM Hardware Security",
            "status": "Unable to Scan",
            "severity": "CRITICAL",
            "description": "Scan Failed / Unable to Scan: UEFI SecureBoot and TPM hardware cmdlets require Microsoft Windows OS. Current OS: " + platform.system() + ".",
            "recommendation": "Execute BlueShield Auditor on Microsoft Windows with Administrator privileges.",
            "fix_script": ""
        })
        return findings

    # Check Secure Boot
    try:
        out_sb = subprocess.check_output(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "Confirm-SecureBootUEFI"], stderr=subprocess.STDOUT, text=True, timeout=10)
        if "True" in out_sb:
            findings.append({
                "module": "Secure Boot & Hardware Security",
                "check_name": "UEFI Secure Boot Enforcement",
                "status": "PASS",
                "severity": "CRITICAL",
                "description": "UEFI Secure Boot state is ENABLED.",
                "recommendation": "Maintain UEFI password protection to prevent Secure Boot tampering.",
                "fix_script": "Confirm-SecureBootUEFI"
            })
        elif "False" in out_sb:
            findings.append({
                "module": "Secure Boot & Hardware Security",
                "check_name": "UEFI Secure Boot Enforcement",
                "status": "FAIL",
                "severity": "CRITICAL",
                "description": "UEFI Secure Boot state is DISABLED! System is vulnerable to bootkit infections.",
                "recommendation": "Enable Secure Boot in system UEFI/BIOS settings.",
                "fix_script": ""
            })
        else:
            findings.append({
                "module": "Secure Boot & Hardware Security",
                "check_name": "UEFI Secure Boot Enforcement",
                "status": "Scan Failed",
                "severity": "CRITICAL",
                "description": f"Scan Failed: Secure Boot check returned unexpected output. Output: {out_sb.strip()[:150]}",
                "recommendation": "Verify system is running in UEFI mode rather than Legacy BIOS.",
                "fix_script": ""
            })
    except Exception as e:
        err_msg = str(e).strip()
        findings.append({
            "module": "Secure Boot & Hardware Security",
            "check_name": "UEFI Secure Boot Enforcement",
            "status": "Scan Failed",
            "severity": "CRITICAL",
            "description": f"Scan Failed: Unable to verify UEFI Secure Boot state. Reason: {err_msg} (Requires UEFI mode and Administrator rights)",
            "recommendation": "Run PowerShell as Administrator on UEFI-supported hardware.",
            "fix_script": ""
        })

    # Check TPM
    try:
        out_tpm = subprocess.check_output(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "(Get-Tpm).TpmPresent"], stderr=subprocess.STDOUT, text=True, timeout=10)
        if "True" in out_tpm:
            findings.append({
                "module": "Secure Boot & Hardware Security",
                "check_name": "Trusted Platform Module (TPM 2.0)",
                "status": "PASS",
                "severity": "HIGH",
                "description": "TPM hardware security chip is PRESENT and recognized.",
                "recommendation": "Ensure TPM auto-provisioning is active.",
                "fix_script": "Get-Tpm"
            })
        elif "False" in out_tpm:
            findings.append({
                "module": "Secure Boot & Hardware Security",
                "check_name": "Trusted Platform Module (TPM 2.0)",
                "status": "FAIL",
                "severity": "HIGH",
                "description": "TPM hardware chip is NOT present or disabled in BIOS.",
                "recommendation": "Enable TPM 2.0 security chip in motherboard BIOS settings.",
                "fix_script": ""
            })
    except Exception as e:
        err_msg = str(e).strip()
        findings.append({
            "module": "Secure Boot & Hardware Security",
            "check_name": "Trusted Platform Module (TPM 2.0)",
            "status": "Scan Failed",
            "severity": "HIGH",
            "description": f"Scan Failed: Unable to query TPM state. Reason: {err_msg}",
            "recommendation": "Run PowerShell as Administrator to query TPM status.",
            "fix_script": "Get-Tpm"
        })

    return findings

