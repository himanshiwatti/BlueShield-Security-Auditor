import platform
import socket
import psutil
import os
import uuid

def audit_system_info():
    findings = []
    sys_details = {}

    try:
        hostname = socket.gethostname()
        username = os.getlogin() if hasattr(os, 'getlogin') else os.environ.get('USER', os.environ.get('USERNAME', 'LocalUser'))
        ip_address = socket.gethostbyname(hostname)
    except Exception:
        hostname = platform.node() or "Unknown-Host"
        username = os.environ.get('USER', os.environ.get('USERNAME', 'Unknown-User'))
        ip_address = "127.0.0.1"

    # MAC Address
    try:
        mac_num = uuid.getnode()
        mac_address = ':'.join(("%012X" % mac_num)[i:i+2] for i in range(0, 12, 2))
    except Exception:
        mac_address = "00:00:00:00:00:00"

    # CPU & Memory & Disk
    try:
        cpu_usage = psutil.cpu_percent(interval=0.1)
        cpu_count = psutil.cpu_count(logical=True) or 1
        cpu_model = platform.processor() or f"CPU ({cpu_count} Logical Cores)"

        mem = psutil.virtual_memory()
        mem_total_gb = round(mem.total / (1024**3), 2)
        mem_used_pct = mem.percent

        disk = psutil.disk_usage('/')
        disk_total_gb = round(disk.total / (1024**3), 2)
        disk_used_pct = disk.percent
    except Exception as e:
        cpu_usage = 0.0
        cpu_count = 1
        cpu_model = "Unknown Processor"
        mem_total_gb = 0.0
        mem_used_pct = 0.0
        disk_total_gb = 0.0
        disk_used_pct = 0.0

    os_info = f"{platform.system()} {platform.release()} (Version {platform.version()})"
    
    # Check OS Release & Support
    is_win = platform.system().lower() == 'windows'
    if is_win:
        is_win10_or_11 = "10" in os_info or "11" in os_info
        findings.append({
            "module": "System Information",
            "check_name": "Operating System Release & Support Status",
            "status": "PASS" if is_win10_or_11 else "WARN",
            "severity": "INFO" if is_win10_or_11 else "HIGH",
            "description": f"Host OS detected as {os_info}. System architecture: {platform.machine()}.",
            "recommendation": "Ensure Windows OS is running a supported release (Windows 10/11 Build 22H2 or newer) with active security patch support.",
            "fix_script": "Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsBuildNumber"
        })
    else:
        findings.append({
            "module": "System Information",
            "check_name": "Operating System Release & Support Status",
            "status": "Unable to Scan",
            "severity": "INFO",
            "description": f"Host environment detected as {os_info}. Note: Full security feature scanning requires Microsoft Windows OS.",
            "recommendation": "Execute BlueShield Auditor on Microsoft Windows with Administrator privileges for live scanning.",
            "fix_script": ""
        })

    # Memory Utilization Check
    if mem_used_pct > 90:
        findings.append({
            "module": "System Information",
            "check_name": "System Memory Usage Threshold",
            "status": "WARN",
            "severity": "MEDIUM",
            "description": f"High memory consumption detected at {mem_used_pct}% ({mem_total_gb} GB total).",
            "recommendation": "Investigate memory-intensive background processes.",
            "fix_script": "Get-Process | Sort-Object WS -Descending | Select-Object -First 10"
        })
    else:
        findings.append({
            "module": "System Information",
            "check_name": "System Memory Usage Threshold",
            "status": "PASS",
            "severity": "INFO",
            "description": f"RAM utilization is at {mem_used_pct}% of {mem_total_gb} GB Total RAM.",
            "recommendation": "Maintain regular resource monitoring.",
            "fix_script": ""
        })

    # Disk Space Check
    if disk_used_pct > 88:
        findings.append({
            "module": "System Information",
            "check_name": "Storage Volume Capacity",
            "status": "WARN",
            "severity": "MEDIUM",
            "description": f"Primary system drive is {disk_used_pct}% full ({disk_total_gb} GB capacity).",
            "recommendation": "Perform disk cleanup.",
            "fix_script": "cleanmgr.exe /sagerun:1"
        })
    else:
        findings.append({
            "module": "System Information",
            "check_name": "Storage Volume Capacity",
            "status": "PASS",
            "severity": "INFO",
            "description": f"Primary disk usage is at {disk_used_pct}% utilized of {disk_total_gb} GB.",
            "recommendation": "No action required.",
            "fix_script": ""
        })

    sys_details = {
        "hostname": hostname,
        "username": username,
        "ip_address": ip_address,
        "mac_address": mac_address,
        "os_info": os_info,
        "cpu_model": cpu_model,
        "cpu_usage": f"{cpu_usage}%",
        "memory": f"{mem_used_pct}% used of {mem_total_gb} GB",
        "disk": f"{disk_used_pct}% used of {disk_total_gb} GB"
    }

    return findings, sys_details

