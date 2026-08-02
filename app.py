import os
import time
import json
import logging
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file, Response
from flask_login import LoginManager, login_required, current_user

from config import Config
from database.db import init_db, get_db_connection
from database.models import User, save_scan_result, get_latest_scan, get_scan_by_id, get_all_scans
from auth.routes import auth_bp
from utils.helpers import calculate_security_score, format_datetime, get_compliance_benchmarks
from ai.gemini_engine import generate_ai_security_analysis, ask_ai_assistant
from reports.generator import generate_pdf_report, generate_csv_report, generate_json_report

# Import all 17 security audit modules
from modules.system_info_audit import audit_system_info
from modules.defender_audit import audit_windows_defender
from modules.firewall_audit import audit_windows_firewall
from modules.update_audit import audit_windows_update
from modules.bitlocker_audit import audit_bitlocker
from modules.secure_boot_audit import audit_secure_boot
from modules.password_policy_audit import audit_password_policy
from modules.user_account_audit import audit_user_accounts
from modules.software_audit import audit_installed_software
from modules.startup_audit import audit_startup_programs
from modules.services_audit import audit_windows_services
from modules.usb_audit import audit_usb_security
from modules.browser_audit import audit_browser_security
from modules.rdp_audit import audit_rdp
from modules.antivirus_audit import audit_antivirus
from modules.event_log_audit import audit_event_logs
from modules.local_policy_audit import audit_local_security_policy

app = Flask(__name__)
app.config.from_object(Config)

# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access BlueShield Auditor.'
login_manager.login_message_category = 'warning'

@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id)

# Register Blueprints
app.register_blueprint(auth_bp)

# Context Processors & Filters
@app.context_processor
def inject_user_settings():
    theme = 'dark'
    accent = '#0078FF'
    if current_user.is_authenticated:
        conn = get_db_connection()
        setting = conn.execute('SELECT theme, accent_color FROM settings WHERE user_id = ?', (current_user.id,)).fetchone()
        conn.close()
        if setting:
            theme = setting['theme']
            accent = setting['accent_color']
    return dict(user_theme=theme, user_accent=accent)

@app.template_filter('format_datetime')
def format_datetime_filter(s):
    return format_datetime(s)

# Helper Function to Run Full System Audit
def execute_full_audit(scan_type='full'):
    start_time = time.time()
    findings = []

    # 1. System Info
    sys_findings, sys_info = audit_system_info()
    findings.extend(sys_findings)

    # 2. Windows Defender
    findings.extend(audit_windows_defender())

    # 3. Windows Firewall
    findings.extend(audit_windows_firewall())

    # 4. Windows Update
    findings.extend(audit_windows_update())

    # 5. BitLocker
    findings.extend(audit_bitlocker())

    # 6. Secure Boot & TPM
    findings.extend(audit_secure_boot())

    # 7. Password Policy
    findings.extend(audit_password_policy())

    # 8. User Accounts
    findings.extend(audit_user_accounts())

    # 9. Installed Software
    findings.extend(audit_installed_software())

    # 10. Startup Programs
    findings.extend(audit_startup_programs())

    # 11. Windows Services
    findings.extend(audit_windows_services())

    # 12. USB Security
    findings.extend(audit_usb_security())

    # 13. Browser Security
    findings.extend(audit_browser_security())

    # 14. Remote Desktop (RDP)
    findings.extend(audit_rdp())

    # 15. Antivirus Audit
    findings.extend(audit_antivirus())

    # 16. Event Log Analysis
    findings.extend(audit_event_logs())

    # 17. Local Security Policy
    findings.extend(audit_local_security_policy())

    duration = round(time.time() - start_time, 2)

    # Calculate Security & Compliance Scores
    score, compliance_score, risk_level, total_passed, total_failed, total_warnings = calculate_security_score(findings)

    scan_payload = {
        'score': score,
        'compliance_score': compliance_score,
        'risk_level': risk_level,
        'total_passed': total_passed,
        'total_failed': total_failed,
        'total_warnings': total_warnings,
        'findings': findings,
        'system_info': sys_info
    }

    # Generate Gemini AI Analysis
    ai_summary = generate_ai_security_analysis(scan_payload)

    return {
        'scan_type': scan_type,
        'score': score,
        'compliance_score': compliance_score,
        'risk_level': risk_level,
        'total_passed': total_passed,
        'total_failed': total_failed,
        'total_warnings': total_warnings,
        'duration_seconds': duration,
        'ai_summary': ai_summary,
        'raw_data': sys_info,
        'findings': findings
    }

# ROUTES
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('auth.login'))

@app.route('/dashboard')
@login_required
def dashboard():
    latest_scan = get_latest_scan(current_user.id)
    all_scans = get_all_scans(limit=10)
    return render_template('dashboard.html', scan=latest_scan, recent_scans=all_scans)

@app.route('/scan')
@login_required
def scan_page():
    return render_template('scan.html')

@app.route('/api/run-scan', methods=['POST'])
@login_required
def api_run_scan():
    req_json = request.get_json() or {}
    scan_type = req_json.get('scan_type', 'full')

    audit_res = execute_full_audit(scan_type)
    scan_id = save_scan_result(
        current_user.id, audit_res['scan_type'], audit_res['score'],
        audit_res['compliance_score'], audit_res['risk_level'],
        audit_res['total_passed'], audit_res['total_failed'],
        audit_res['total_warnings'], audit_res['duration_seconds'],
        audit_res['ai_summary'], audit_res['raw_data'], audit_res['findings']
    )

    return jsonify({'status': 'success', 'scan_id': scan_id, 'data': audit_res})

@app.route('/modules/<module_name>')
@login_required
def module_detail(module_name):
    latest_scan = get_latest_scan(current_user.id)
    if not latest_scan:
        return redirect(url_for('dashboard'))

    # Normalized module matching
    module_title = module_name.replace('-', ' ').title()
    filtered_findings = [f for f in latest_scan['findings'] if module_name.lower() in f['module'].lower() or f['module'].lower() in module_name.lower()]

    return render_template('module_detail.html', module_title=module_title, module_name=module_name, findings=filtered_findings, scan=latest_scan)

@app.route('/compliance')
@login_required
def compliance_page():
    latest_scan = get_latest_scan(current_user.id)
    benchmarks = get_compliance_benchmarks()
    return render_template('compliance.html', scan=latest_scan, benchmarks=benchmarks)

@app.route('/reports')
@login_required
def reports_page():
    scans = get_all_scans(limit=20)
    latest_scan = get_latest_scan(current_user.id)
    return render_template('reports.html', scans=scans, latest_scan=latest_scan)

@app.route('/api/export-report/<format_type>/<int:scan_id>')
@login_required
def export_report(format_type, scan_id):
    scan_data = get_scan_by_id(scan_id)
    if not scan_data:
        flash('Scan report not found.', 'danger')
        return redirect(url_for('reports_page'))

    if format_type == 'pdf':
        pdf_bytes = generate_pdf_report(scan_data)
        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment;filename=BlueShield_Security_Report_{scan_id}.pdf'}
        )
    elif format_type == 'csv':
        csv_str = generate_csv_report(scan_data)
        return Response(
            csv_str,
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment;filename=BlueShield_Audit_Report_{scan_id}.csv'}
        )
    elif format_type == 'json':
        json_str = generate_json_report(scan_data)
        return Response(
            json_str,
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment;filename=BlueShield_Audit_Data_{scan_id}.json'}
        )
    else:
        return jsonify({'error': 'Invalid format'}), 400

@app.route('/history')
@login_required
def history_page():
    scans = get_all_scans(limit=50)
    return render_template('history.html', scans=scans)

@app.route('/compare')
@login_required
def compare_page():
    scans = get_all_scans(limit=20)
    scan_id_1 = request.args.get('scan1')
    scan_id_2 = request.args.get('scan2')

    scan1 = get_scan_by_id(scan_id_1) if scan_id_1 else (scans[0] if len(scans) > 0 else None)
    scan2 = get_scan_by_id(scan_id_2) if scan_id_2 else (scans[1] if len(scans) > 1 else scan1)

    return render_template('compare.html', scans=scans, scan1=scan1, scan2=scan2)

@app.route('/ai-assistant')
@login_required
def ai_assistant_page():
    latest_scan = get_latest_scan(current_user.id)
    return render_template('ai_assistant.html', scan=latest_scan)

@app.route('/api/ai-chat', methods=['POST'])
@login_required
def api_ai_chat():
    data = request.get_json() or {}
    query = data.get('query', '')
    if not query:
        return jsonify({'response': 'Please enter a valid cybersecurity query.'})

    latest_scan = get_latest_scan(current_user.id)
    reply = ask_ai_assistant(query, latest_scan)
    return jsonify({'response': reply})

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings_page():
    conn = get_db_connection()
    if request.method == 'POST':
        theme = request.form.get('theme', 'dark')
        accent_color = request.form.get('accent_color', '#0078FF')
        language = request.form.get('language', 'en')
        auto_scan = request.form.get('auto_scan', 'disabled')
        notifications = 1 if request.form.get('notifications') else 0

        conn.execute('''
            INSERT INTO settings (user_id, theme, accent_color, language, auto_scan, notifications_enabled)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
            theme=excluded.theme,
            accent_color=excluded.accent_color,
            language=excluded.language,
            auto_scan=excluded.auto_scan,
            notifications_enabled=excluded.notifications_enabled
        ''', (current_user.id, theme, accent_color, language, auto_scan, notifications))

        conn.commit()
        conn.close()
        flash('Settings updated successfully.', 'success')
        return redirect(url_for('settings_page'))

    setting = conn.execute('SELECT * FROM settings WHERE user_id = ?', (current_user.id,)).fetchone()
    conn.close()
    return render_template('settings.html', settings=setting)

# Initialize Database on Startup
init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=port, debug=False)
