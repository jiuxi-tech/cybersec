from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import datetime

from db import get_db_connection, get_email_config_from_db, save_email_config_to_db
from util import simulate_scan_core, collect_vulnerabilities_from_nvd_core, test_send_email

app = Flask(__name__)
CORS(app)

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

@app.route('/api/assets', methods=['GET', 'POST'])
def manage_assets():
    conn = get_db_connection()

    if request.method == 'POST':
        data = request.json
        conn.execute('''
        INSERT INTO assets (name, type, os, ip, software, version, manager, manager_email)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (data['name'], data['type'], data['os'], data['ip'], data['software'], data['version'], data['manager'], data['manager_email']))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success'})

    assets = conn.execute('SELECT * FROM assets').fetchall()
    conn.close()
    return jsonify([dict(asset) for asset in assets])

@app.route('/api/assets/<int:id>', methods=['PUT', 'DELETE'])
def update_asset(id):
    conn = get_db_connection()

    if request.method == 'PUT':
        data = request.json
        conn.execute('''
        UPDATE assets
        SET name = ?, type = ?, os = ?, ip = ?, software = ?, version = ?, manager = ?, manager_email = ?
        WHERE id = ?
        ''', (data['name'], data['type'], data['os'], data['ip'], data['software'], data['version'], data['manager'], data['manager_email'], id))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success'})

    if request.method == 'DELETE':
        conn.execute('DELETE FROM assets WHERE id = ?', (id,))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success'})

@app.route('/api/simulate_scan', methods=['POST'])
def run_simulation():
    data = request.json or {}
    ports = data.get('ports', '80,443,8080,8443,22,3389,6379')
    asset_id = data.get('asset_id')
    if not asset_id:
        return jsonify({'status': 'error', 'message': '必须指定资产ID'})
    result = simulate_scan_core(ports, asset_id)
    return jsonify(result)

@app.route('/api/scan_results', methods=['GET'])
def get_scan_results():
    conn = get_db_connection()
    results = conn.execute('''
    SELECT sr.*, a.name as asset_name
    FROM scan_results sr
    JOIN assets a ON sr.asset_id = a.id
    ORDER BY sr.scan_time DESC
    ''').fetchall()
    conn.close()
    return jsonify([dict(result) for result in results])

@app.route('/api/compare_versions', methods=['GET'])
def compare_versions():
    conn = get_db_connection()
    assets = conn.execute('SELECT * FROM assets').fetchall()
    scan_results = conn.execute('SELECT sr.*, a.name as asset_name FROM scan_results sr JOIN assets a ON sr.asset_id = a.id').fetchall()

    version_mismatches = []

    for asset in assets:
        for result in scan_results:
            if result['asset_id'] == asset['id']:
                reported_software = asset['software'].lower()
                reported_version = asset['version']
                scanned_service = result['service'].lower()
                scanned_version = result['version']

                if reported_software in scanned_service and reported_version != scanned_version:
                    version_mismatches.append({
                        'asset_id': asset['id'],
                        'asset_name': asset['name'],
                        'service': result['service'],
                        'reported_version': reported_version,
                        'scanned_version': scanned_version,
                        'scan_time': result['scan_time']
                    })

    conn.close()
    return jsonify(version_mismatches)

@app.route('/api/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    conn = get_db_connection()
    vulnerabilities = conn.execute('SELECT * FROM vulnerabilities').fetchall()
    conn.close()
    return jsonify([dict(vuln) for vuln in vulnerabilities])

@app.route('/api/collect_vulnerabilities', methods=['POST'])
def collect_vulnerabilities():
    print(f"Request headers: {request.headers}")
    print(f"Request data: {request.get_data()}")
    data = request.json or {}
    cve_id = data.get('cve_id')
    if not request.is_json:
        return jsonify({'status': 'error', 'message': '请求内容类型必须为 application/json'}), 415
    result = collect_vulnerabilities_from_nvd_core(cve_id=cve_id)
    return jsonify(result)

@app.route('/api/email_config', methods=['GET', 'POST'])
def email_config_api():
    if request.method == 'GET':
        config = get_email_config_from_db()
        if config:
            return jsonify({
                'host': config['host'],
                'port': config['port'],
                'user': config['user'],
                'from': config['sender_from']
            })
        else:
            return jsonify({
                'host': 'smtp.163.com',
                'port': 25,
                'user': '',
                'from': ''
            })
    elif request.method == 'POST':
        data = request.json or {}
        print(f"Received POST data for email config: {data}")

        required_fields = ['host', 'port', 'user', 'password', 'from']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return jsonify({'status': 'error', 'message': f'缺少必要字段: {", ".join(missing_fields)}'}), 400

        config_to_save = {
            'host': data.get('host'),
            'port': int(data.get('port')),
            'user': data.get('user'),
            'password': data.get('password'),
            'from': data.get('from')
        }
        save_email_config_to_db(config_to_save)
        return jsonify({'status': 'success', 'message': '邮件配置已更新'})

@app.route('/api/test_email', methods=['POST'])
def test_email_api():
    data = request.json or {}
    print(f"Received test email data: {data}")

    required_fields = ['host', 'port', 'user', 'password']
    missing_fields = [field for field in required_fields if not data.get(field) is not None]
    if missing_fields:
        return jsonify({'status': 'error', 'message': f'缺少必要字段: {", ".join(missing_fields)}'}), 400

    config_for_test = {
        'host': data.get('host'),
        'port': int(data.get('port')),
        'user': data.get('user'),
        'password': data.get('password'),
        'sender_from': data.get('user')
    }

    success = test_send_email(config_for_test)
    if success:
        return jsonify({'status': 'success', 'message': '测试邮件发送成功'})
    else:
        return jsonify({'status': 'error', 'message': '测试邮件发送失败，请检查网络连接或邮件配置（可能是授权码错误、防火墙阻止了端口，或SMTP服务器限制）'}), 400

@app.route('/api/reports', methods=['GET', 'POST'])
def manage_reports():
    conn = get_db_connection()

    if request.method == 'GET':
        try:
            reports = conn.execute('''
            SELECT r.*, a.name as asset_name, v.name as vuln_name
            FROM reports r
            JOIN assets a ON r.asset_id = a.id
            JOIN vulnerabilities v ON r.vuln_id = v.id
            ORDER BY r.report_date DESC
            ''').fetchall()
            conn.close()
            return jsonify([dict(report) for report in reports])
        except Exception as e:
            print(f"获取报告失败: {str(e)}")
            conn.close()
            return jsonify({'error': str(e)}), 500

    if request.method == 'POST':
        try:
            data = request.json
            conn.execute('''
            INSERT INTO reports (asset_id, vuln_id, status, treatment_method, treatment_date, reporter, report_date)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                data['asset_id'],
                data['vuln_id'],
                data['status'],
                data['treatment_method'],
                data['treatment_date'],
                data['reporter'],
                data['report_date']
            ))
            conn.commit()
            conn.close()
            return jsonify({'status': 'success'})
        except Exception as e:
            print(f"提交报告失败: {str(e)}")
            conn.close()
            return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
