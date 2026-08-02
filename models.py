from flask_login import UserMixin
from database.db import get_db_connection
import json

class User(UserMixin):
    def __init__(self, id, username, email, role):
        self.id = id
        self.username = username
        self.email = email
        self.role = role

    def get_id(self):
        return str(self.id)

    @staticmethod
    def get_by_id(user_id):
        if user_id is None:
            return None
        try:
            user_id_int = int(user_id)
        except (TypeError, ValueError):
            return None
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id_int,)).fetchone()
        conn.close()
        if user:
            return User(user['id'], user['username'], user['email'], user['role'])
        return None

    @staticmethod
    def get_by_username(username):
        if not username:
            return None
        identifier = username.strip()
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)', (identifier, identifier)).fetchone()
        conn.close()
        if user:
            return user
        return None

def save_scan_result(user_id, scan_type, score, compliance_score, risk_level, passed, failed, warnings, duration, ai_summary, raw_data, findings):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO scans (user_id, scan_type, score, compliance_score, risk_level, total_passed, total_failed, total_warnings, duration_seconds, ai_summary_json, raw_data_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        user_id, scan_type, score, compliance_score, risk_level,
        passed, failed, warnings, duration,
        json.dumps(ai_summary) if isinstance(ai_summary, (dict, list)) else ai_summary,
        json.dumps(raw_data) if isinstance(raw_data, (dict, list)) else raw_data
    ))

    scan_id = cursor.lastrowid

    for f in findings:
        cursor.execute('''
            INSERT INTO findings (scan_id, module, check_name, status, severity, description, recommendation, fix_script)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_id,
            f.get('module', 'General'),
            f.get('check_name', 'Unknown Check'),
            f.get('status', 'WARN'),
            f.get('severity', 'MEDIUM'),
            f.get('description', ''),
            f.get('recommendation', ''),
            f.get('fix_script', '')
        ))

    conn.commit()
    conn.close()
    return scan_id

def get_latest_scan(user_id=None):
    conn = get_db_connection()
    if user_id:
        scan = conn.execute('SELECT * FROM scans WHERE user_id = ? ORDER BY timestamp DESC LIMIT 1', (user_id,)).fetchone()
    else:
        scan = conn.execute('SELECT * FROM scans ORDER BY timestamp DESC LIMIT 1').fetchone()

    if not scan:
        conn.close()
        return None

    scan_dict = dict(scan)
    findings = conn.execute('SELECT * FROM findings WHERE scan_id = ?', (scan_dict['id'],)).fetchall()
    scan_dict['findings'] = [dict(f) for f in findings]
    try:
        scan_dict['ai_summary'] = json.loads(scan_dict['ai_summary_json']) if scan_dict['ai_summary_json'] else {}
    except Exception:
        scan_dict['ai_summary'] = {"executive_summary": scan_dict['ai_summary_json'] or "No AI summary."}
    
    conn.close()
    return scan_dict

def get_scan_by_id(scan_id):
    conn = get_db_connection()
    scan = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    if not scan:
        conn.close()
        return None

    scan_dict = dict(scan)
    findings = conn.execute('SELECT * FROM findings WHERE scan_id = ?', (scan_id,)).fetchall()
    scan_dict['findings'] = [dict(f) for f in findings]
    try:
        scan_dict['ai_summary'] = json.loads(scan_dict['ai_summary_json']) if scan_dict['ai_summary_json'] else {}
    except Exception:
        scan_dict['ai_summary'] = {"executive_summary": scan_dict['ai_summary_json'] or "No AI summary."}

    conn.close()
    return scan_dict

def get_all_scans(limit=50):
    conn = get_db_connection()
    scans = conn.execute('SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?', (limit,)).fetchall()
    conn.close()
    return [dict(s) for s in scans]
