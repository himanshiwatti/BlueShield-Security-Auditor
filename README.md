# BlueShield Auditor – AI Powered Windows Security Hardening & Compliance Checker

BlueShield Auditor is a Python Flask web application designed for Windows local security auditing, vulnerability assessment, and CIS / Microsoft Baseline compliance reporting.

## Features
- **17 Dedicated Security Audit Modules**:
  1. Windows Defender Audit
  2. Windows Firewall Audit
  3. Windows Update Audit
  4. BitLocker Drive Encryption Audit
  5. Secure Boot, TPM 2.0 & HVCI Core Isolation Audit
  6. Password Policy Audit
  7. User Account & Admin Audit
  8. Installed Software & Unsigned Binary Audit
  9. Startup Programs & Autoruns Audit
  10. Windows Services Audit (Remote Registry, Print Spooler, SMBv1)
  11. USB Security & AutoRun Policy Audit
  12. Browser Security & Extension Audit
  13. Remote Desktop (RDP) & NLA Audit
  14. Antivirus Engine Audit
  15. Event Log Analysis (Failed Logon Event 4625 Audit)
  16. Local Security Policy Audit
  17. System Information Probe

- **AI Security Analysis**: Powered by Google Gemini API (`gemini-3.1-pro-preview` with High reasoning) to generate executive summaries, risk analysis, priority fixes, and long-term hardening roadmaps.
- **Reports Exporter**: PDF (ReportLab), CSV, and JSON report generation.
- **Compliance Benchmarks**: Evaluated against Microsoft Windows 11 Security Baseline and CIS Benchmark Level 1.
- **Scan History & Side-by-Side Comparison**: SQLite database storage with security trend tracking over time.
- **Enterprise Dark Theme UI**: Built with HTML5, CSS3, Bootstrap 5, and Chart.js.

## Local Running Instructions

1. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Set Gemini API Key (Optional):
   ```bash
   export GEMINI_API_KEY="your-gemini-api-key"
   ```

3. Run the Flask Web Application:
   ```bash
   python app.py
   ```

4. Open your browser at:
   ```
   http://localhost:5000 (or http://localhost:3000)
   ```

5. Default Login Credentials:
   - **Username**: `admin`
   - **Password**: `admin123`
