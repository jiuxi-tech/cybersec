import sqlite3
import os
from datetime import datetime

# 数据库路径
DB_PATH = 'security.db'

# 初始化数据库
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # 删除旧表（如果存在）
    c.execute('DROP TABLE IF EXISTS assets')
    c.execute('DROP TABLE IF EXISTS scan_results')
    c.execute('DROP TABLE IF EXISTS vulnerabilities')
    c.execute('DROP TABLE IF EXISTS notifications')
    c.execute('DROP TABLE IF EXISTS reports')
    # 新增：删除旧的 email_settings 表
    c.execute('DROP TABLE IF EXISTS email_settings')

    # 创建 assets 表
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

    # 创建 scan_results 表
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

    # 创建 vulnerabilities 表
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

    # 创建 notifications 表
    c.execute('''
    CREATE TABLE notifications (
        id INTEGER PRIMARY KEY,
        asset_id INTEGER,
        vuln_id INTEGER,
        recipient TEXT,
        send_time TEXT,
        status TEXT,
        FOREIGN KEY (asset_id) REFERENCES assets(id),
        FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
    )
    ''')

    # 创建 reports 表
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

    # 新增：创建 email_settings 表
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

    # 插入测试数据
    c.execute('''
    INSERT INTO assets (name, type, os, ip, software, version, manager, manager_email)
    VALUES ('九析工作站', '工作站', 'Ubuntu', '172.21.94.108', 'redis', '3.8', '张三', 'test@example.com')
    ''')

    # 插入测试漏洞数据
    c.execute('''
    INSERT INTO vulnerabilities (name, description, severity, affected_systems, solution, publish_date, source)
    VALUES ('Redis 未授权访问', 'Redis 未设置密码，可能导致未授权访问', '高危', 'Redis 3.x, 4.x', '设置强密码并限制访问', '2023-01-15', 'CVE-2023-12345')
    ''')

    # 新增：插入默认邮件配置
    c.execute('''
    INSERT OR REPLACE INTO email_settings (id, host, port, user, password, sender_from)
    VALUES (1, 'smtp.163.com', 25, 'your_email@163.com', 'your_authorization_code', 'your_email@163.com')
    ''')

    conn.commit()
    conn.close()

# 自动初始化数据库（启动时运行一次）
# 如果数据库文件不存在，则创建并初始化
if not os.path.exists(DB_PATH):
    init_db()
# 如果数据库文件存在，确保 email_settings 表存在并有默认值
else:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("PRAGMA table_info(email_settings)")
    if not c.fetchone(): # 如果 email_settings 表不存在
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


# 数据库连接函数
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# 记录通知历史
def record_notification(asset_id, vuln_id, recipient, status):
    conn = get_db_connection()
    conn.execute('''
    INSERT INTO notifications (asset_id, vuln_id, recipient, send_time, status)
    VALUES (?, ?, ?, ?, ?)
    ''', (asset_id, vuln_id, recipient, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), status))
    conn.commit()
    conn.close()

# 新增：获取邮件配置
def get_email_config_from_db():
    conn = get_db_connection()
    config = conn.execute('SELECT host, port, user, password, sender_from FROM email_settings WHERE id = 1').fetchone()
    conn.close()
    return dict(config) if config else None

# 新增：保存邮件配置
def save_email_config_to_db(config_data):
    conn = get_db_connection()
    conn.execute('''
    INSERT OR REPLACE INTO email_settings (id, host, port, user, password, sender_from)
    VALUES (1, ?, ?, ?, ?, ?)
    ''', (config_data['host'], config_data['port'], config_data['user'], config_data['password'], config_data['from']))
    conn.commit()
    conn.close()
