import subprocess
import platform
import winreg 

def audit_installed_software():
    findings = []
    run_in_reg = "Registry Editor / CMD"

    try:
        software_list = []
        reg_paths = [r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"]
        
        for reg_path in reg_paths:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_READ)
                for i in range(0, winreg.QueryInfoKey(key)[0]):
                    subkey_name = winreg.EnumKey(key, i)
                    subkey = winreg.OpenKey(key, subkey_name)
                    try:
                        name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                        version = winreg.QueryValueEx(subkey, "DisplayVersion")[0] if "DisplayVersion" in [winreg.EnumValue(subkey, j)[0] for j in range(winreg.QueryInfoKey(subkey)[1])] else "Unknown"
                        software_list.append({"Name": name, "Version": version})
                    except: pass
            except: pass

        # 1. Risky Software Check
        risky_software = ['TeamViewer', 'AnyDesk', 'WinRAR', 'uTorrent', 'VNC']
        found_risky = [s for s in software_list if any(risk.lower() in s['Name'].lower() for risk in risky_software)]

        if found_risky:
            findings.append({
                "module": "Installed Software",
                "check_name": "Risky/Remote Access Software Found",
                "status": "WARN", "severity": "HIGH",
                "description": f"[Run in: {run_in_reg}] Found: {found_risky[0]['Name']}. Remote tools can be abused.",
                "recommendation": "Uninstall unused remote access tools.",
                "fix_script": "appwiz.cpl"
            })
        else:
            findings.append({
                "module": "Installed Software",
                "check_name": "Risky/Remote Access Software Found",
                "status": "PASS", "severity": "HIGH",
                "description": f"[Run in: {run_in_reg}] No risky remote software found.",
                "recommendation": "Continue to audit software regularly.", "fix_script": ""
            })
        
        # 2. Inventory
        findings.append({
            "module": "Installed Software",
            "check_name": "Software Inventory",
            "status": "PASS", "severity": "INFO",
            "description": f"[Run in: {run_in_reg}] Total {len(software_list)} software packages installed.",
            "recommendation": "Review and remove unused software.", "fix_script": "appwiz.cpl"
        })

    except Exception as e:
        findings.append({
            "module": "Installed Software", "check_name": "Software Audit",
            "status": "Scan Failed", "severity": "MEDIUM",
            "description": f"[Run in: {run_in_reg}] Scan Failed: {str(e)}",
            "recommendation": "Run as Administrator.", "fix_script": ""
        })
    return findings