import sqlite3
import os
from datetime import datetime

DB_PATH = 'security.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('DROP TABLE IF EXISTS assets')
    c.execute('DROP TABLE IF EXISTS scan_results')
    c.execute('DROP TABLE IF EXISTS vulnerabilities')
    c.execute('DROP TABLE IF EXISTS notifications')
    c.execute('DROP TABLE IF EXISTS reports')
    c.execute('DROP TABLE IF EXISTS email_settings')

    c.execute('''
    CREATE TABLE assets (
        id INTEGER PRIMARY KEY,
        name TEXT,
        type TEXT,
        os TEXT,
        ip TEXT,
        software TEXT,
        version TEXT,
        manager TEXT,
        manager_email TEXT
    )
    ''')

    c.execute('''
    CREATE TABLE scan_results (
        id INTEGER PRIMARY KEY,
        asset_id INTEGER,
        ip TEXT,
        port INTEGER,
        service TEXT,
        version TEXT,
        vulnerabilities TEXT,
        scan_time TEXT,
        FOREIGN KEY (asset_id) REFERENCES assets(id)
    )
    ''')

    c.execute('''
    CREATE TABLE vulnerabilities (
        id INTEGER PRIMARY KEY,
        name TEXT,
        description TEXT,
        severity TEXT,
        affected_systems TEXT,
        solution TEXT,
        publish_date TEXT,
        source TEXT
    )
    ''')

    c.execute('''
    CREATE TABLE notifications (
        id INTEGER PRIMARY KEY,
        asset_id INTEGER,
        vuln_id INTEGER,
        recipient TEXT,
        send_time TEXT,
        status TEXT,
        message TEXT, -- 新增 message 字段作为可选字段
        FOREIGN KEY (asset_id) REFERENCES assets(id),
        FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
    )
    ''')

    c.execute('''
    CREATE TABLE reports (
        id INTEGER PRIMARY KEY,
        vuln_id INTEGER,
        asset_id INTEGER,
        status TEXT,
        treatment_method TEXT,
        treatment_date TEXT,
        reporter TEXT,
        report_date TEXT,
        FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id),
        FOREIGN KEY (asset_id) REFERENCES assets(id)
    )
    ''')

    c.execute('''
    CREATE TABLE email_settings (
        id INTEGER PRIMARY KEY DEFAULT 1,
        host TEXT,
        port INTEGER,
        user TEXT,
        password TEXT,
        sender_from TEXT
    )
    ''')

    c.execute('''
    INSERT INTO assets (name, type, os, ip, software, version, manager, manager_email)
    VALUES ('九析工作站', '工作站', 'Ubuntu', '172.21.94.108', 'redis', '3.8', '张三', 'test@example.com')
    ''')

    c.execute('''
    INSERT OR REPLACE INTO email_settings (id, host, port, user, password, sender_from)
    VALUES (1, 'smtp.163.com', 25, 'your_email@163.com', 'your_authorization_code', 'your_email@163.com')
    ''')

    conn.commit()
    conn.close()

if not os.path.exists(DB_PATH):
    init_db()
else:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("PRAGMA table_info(email_settings)")
    if not c.fetchone():
        c.execute('''
        CREATE TABLE email_settings (
            id INTEGER PRIMARY KEY DEFAULT 1,
            host TEXT,
            port INTEGER,
            user TEXT,
            password TEXT,
            sender_from TEXT
        )
        ''')
        c.execute('''
        INSERT OR REPLACE INTO email_settings (id, host, port, user, password, sender_from)
        VALUES (1, 'smtp.163.com', 25, 'your_email@163.com', 'your_authorization_code', 'your_email@163.com')
        ''')
        conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def record_notification(asset_id, vuln_id, recipient, status, message=None):
    # 修改 record_notification 函数，增加 message 参数并设为可选
    conn = get_db_connection()
    conn.execute('''
    INSERT INTO notifications (asset_id, vuln_id, recipient, send_time, status, message)
    VALUES (?, ?, ?, ?, ?, ?)
    ''', (asset_id, vuln_id, recipient, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), status, message))
    conn.commit()
    conn.close()

def get_email_config_from_db():
    conn = get_db_connection()
    config = conn.execute('SELECT host, port, user, password, sender_from FROM email_settings WHERE id = 1').fetchone()
    conn.close()
    return dict(config) if config else None

def save_email_config_to_db(config_data):
    conn = get_db_connection()
    conn.execute('''
    INSERT OR REPLACE INTO email_settings (id, host, port, user, password, sender_from)
    VALUES (1, ?, ?, ?, ?, ?)
    ''', (config_data['host'], config_data['port'], config_data['user'], config_data['password'], config_data['from']))
    conn.commit()
    conn.close()
