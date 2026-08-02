import subprocess
import platform
import json

def audit_rdp():
    findings = []
    is_windows = platform.system().lower() == 'windows'

    if not is_windows:
        findings.append({
            "module": "Remote Desktop",
            "check_name": "Remote Desktop & NLA Audit",
            "status": "Unable to Scan",
            "severity": "CRITICAL",
            "description": "Scan Failed / Unable to Scan: Windows Remote Desktop Registry inspection requires Microsoft Windows OS. Current OS: " + platform.system() + ".",
            "recommendation": "Execute BlueShield Auditor on Microsoft Windows with Administrator privileges.",
            "fix_script": ""
        })
        return findings

    try:
        ps_cmd = """
        $fDeny = (Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -ErrorAction SilentlyContinue).fDenyTSConnections
        $nla = (Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -ErrorAction SilentlyContinue).UserAuthentication
        [PSCustomObject]@{
            fDenyTSConnections = $fDeny
            UserAuthentication = $nla
        } | ConvertTo-Json
        """
        out = subprocess.check_output(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd], stderr=subprocess.STDOUT, text=True, timeout=10)
        
        rdp_data = json.loads(out.strip())
        f_deny = rdp_data.get("fDenyTSConnections", 1)
        u_auth = rdp_data.get("UserAuthentication", 0)

        # RDP status
        if f_deny == 1:
            findings.append({
                "module": "Remote Desktop",
                "check_name": "Remote Desktop Service (RDP) Listener",
                "status": "PASS",
                "severity": "HIGH",
                "description": "Remote Desktop connections are DISABLED (fDenyTSConnections = 1). RDP attack vector closed.",
                "recommendation": "Keep RDP disabled if remote management is not required.",
                "fix_script": "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 1"
            })
        else:
            findings.append({
                "module": "Remote Desktop",
                "check_name": "Remote Desktop Service (RDP) Listener",
                "status": "WARN",
                "severity": "HIGH",
                "description": "Remote Desktop connections are ENABLED (fDenyTSConnections = 0).",
                "recommendation": "Ensure Network Level Authentication (NLA) is required and restrict allowed firewall IPs.",
                "fix_script": "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 1"
            })

            # NLA Status
            if u_auth == 1:
                findings.append({
                    "module": "Remote Desktop",
                    "check_name": "Network Level Authentication (NLA) Enforcement",
                    "status": "PASS",
                    "severity": "CRITICAL",
                    "description": "Network Level Authentication (NLA) is ENFORCED (UserAuthentication = 1).",
                    "recommendation": "Maintain NLA requirement.",
                    "fix_script": "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 1"
                })
            else:
                findings.append({
                    "module": "Remote Desktop",
                    "check_name": "Network Level Authentication (NLA) Enforcement",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "description": "Network Level Authentication (NLA) is DISABLED! System is vulnerable to unauthenticated remote access attempts.",
                    "recommendation": "Enable NLA immediately.",
                    "fix_script": "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 1"
                })

    except Exception as e:
        err_msg = str(e).strip()
        findings.append({
            "module": "Remote Desktop",
            "check_name": "Remote Desktop & NLA Audit",
            "status": "Scan Failed",
            "severity": "CRITICAL",
            "description": f"Scan Failed: Unable to read RDP registry keys. Reason: {err_msg}",
            "recommendation": "Run PowerShell as Administrator to query Terminal Server registry settings.",
            "fix_script": ""
        })

    return findings

