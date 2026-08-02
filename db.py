import sqlite3
import os
from config import Config

def get_db_connection():
    db_path = Config.DATABASE
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA schema_version")
        return conn
    except sqlite3.DatabaseError:
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except Exception:
                pass
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn

def init_db():
    try:
        _run_init_db()
    except sqlite3.DatabaseError:
        db_path = Config.DATABASE
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except Exception:
                pass
        _run_init_db()

def _run_init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'Admin',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Scans Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            scan_type TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            score INTEGER NOT NULL,
            compliance_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            total_passed INTEGER NOT NULL,
            total_failed INTEGER NOT NULL,
            total_warnings INTEGER NOT NULL,
            duration_seconds REAL DEFAULT 0,
            ai_summary_json TEXT,
            raw_data_json TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    # Findings Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            module TEXT NOT NULL,
            check_name TEXT NOT NULL,
            status TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT,
            recommendation TEXT,
            fix_script TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        )
    ''')

    # Settings Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            theme TEXT DEFAULT 'dark',
            accent_color TEXT DEFAULT '#0078FF',
            language TEXT DEFAULT 'en',
            auto_scan TEXT DEFAULT 'disabled',
            notifications_enabled INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    conn.commit()

    # Create default admin user if none exists
    from utils.security import hash_password
    cursor.execute("SELECT id FROM users WHERE username = ?", ('admin',))
    if not cursor.fetchone():
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, role)
            VALUES (?, ?, ?, ?)
        ''', ('admin', 'admin@blueshield.local', hash_password('admin123'), 'Administrator'))
        admin_id = cursor.lastrowid
        
        cursor.execute('''
            INSERT OR IGNORE INTO settings (user_id, theme, accent_color, language, auto_scan, notifications_enabled)
            VALUES (?, 'dark', '#0078FF', 'en', 'disabled', 1)
        ''', (admin_id,))
        conn.commit()

    conn.close()
