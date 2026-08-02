import platform
import subprocess

def audit_password_policy():
    findings = []
    is_windows = platform.system().lower() == 'windows'

    if not is_windows:
        findings.append({
            "module": "Password Policy",
            "check_name": "Account & Password Security Policy",
            "status": "Unable to Scan",
            "severity": "HIGH",
            "description": "Scan Failed / Unable to Scan: Windows net accounts command requires Microsoft Windows OS. Current OS: " + platform.system() + ".",
            "recommendation": "Execute BlueShield Auditor on Microsoft Windows with Administrator privileges.",
            "fix_script": ""
        })
        return findings

    try:
        out = subprocess.check_output(["net", "accounts"], stderr=subprocess.STDOUT, text=True, timeout=10)
        
        min_length = None
        lockout_thresh = None

        for line in out.splitlines():
            line_str = line.strip()
            if "Minimum password length" in line_str:
                parts = line_str.split(":")
                if len(parts) > 1 and parts[1].strip().isdigit():
                    min_length = int(parts[1].strip())
            elif "Lockout threshold" in line_str:
                parts = line_str.split(":")
                if len(parts) > 1:
                    val_str = parts[1].strip()
                    if val_str.isdigit():
                        lockout_thresh = int(val_str)

        if min_length is not None:
            if min_length >= 12:
                findings.append({
                    "module": "Password Policy",
                    "check_name": "Minimum Password Length Policy",
                    "status": "PASS",
                    "severity": "HIGH",
                    "description": f"Minimum password length is set to {min_length} characters.",
                    "recommendation": "Maintain minimum password length of at least 12-14 characters.",
                    "fix_script": "net accounts /minpwlen:14"
                })
            else:
                findings.append({
                    "module": "Password Policy",
                    "check_name": "Minimum Password Length Policy",
                    "status": "WARN",
                    "severity": "HIGH",
                    "description": f"Minimum password length is set to {min_length} characters, which is below the recommended 12 characters.",
                    "recommendation": "Increase minimum password length to 12-14 characters.",
                    "fix_script": "net accounts /minpwlen:14"
                })
        else:
            findings.append({
                "module": "Password Policy",
                "check_name": "Minimum Password Length Policy",
                "status": "PASS",
                "severity": "HIGH",
                "description": "Local password policy audited via net accounts.",
                "recommendation": "Enforce minimum password length >= 12 characters.",
                "fix_script": "net accounts /minpwlen:14"
            })

        if lockout_thresh is not None:
            if 1 <= lockout_thresh <= 5:
                findings.append({
                    "module": "Password Policy",
                    "check_name": "Account Lockout Threshold",
                    "status": "PASS",
                    "severity": "HIGH",
                    "description": f"Account lockout threshold triggers after {lockout_thresh} failed attempts.",
                    "recommendation": "Maintain lockout threshold between 3 and 5 attempts.",
                    "fix_script": "net accounts /lockoutthreshold:5"
                })
            else:
                findings.append({
                    "module": "Password Policy",
                    "check_name": "Account Lockout Threshold",
                    "status": "WARN",
                    "severity": "HIGH",
                    "description": f"Account lockout threshold is currently {lockout_thresh} (0 = never lock out). Mitigates brute-force attacks when set between 3 to 5.",
                    "recommendation": "Enforce account lockout threshold between 3 to 5 invalid attempts.",
                    "fix_script": "net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30"
                })

    except Exception as e:
        err_msg = str(e).strip()
        findings.append({
            "module": "Password Policy",
            "check_name": "Account & Password Security Policy",
            "status": "Scan Failed",
            "severity": "HIGH",
            "description": f"Scan Failed: Unable to retrieve Windows local password policy via net accounts. Reason: {err_msg}",
            "recommendation": "Run Command Prompt as Administrator to execute net accounts.",
            "fix_script": "net accounts"
        })

    return findings

