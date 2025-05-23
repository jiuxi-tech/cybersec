import nmap
import json
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
from datetime import datetime, timedelta
import requests
import ssl

from db import get_db_connection, record_notification, get_email_config_from_db

NVD_API_KEY = "769ad379-6974-4666-9370-183ac7088722"

def send_email_notification(recipient, subject, content, config, asset_id=None, vuln_id=None):
    smtp = None
    try:
        EMAIL_HOST = config.get('host')
        EMAIL_PORT = int(config.get('port'))
        EMAIL_USER = config.get('user')
        EMAIL_PASSWORD = config.get('password')
        EMAIL_FROM = config.get('sender_from') or config.get('from')

        if not all([EMAIL_HOST, EMAIL_PORT, EMAIL_USER, EMAIL_PASSWORD, EMAIL_FROM]):
            raise ValueError("邮件配置不完整，无法发送邮件。")

        message = MIMEMultipart()
        message['From'] = Header(f"网络安全信息管理平台 <{EMAIL_FROM}>", 'utf-8')
        message['To'] = Header(recipient, 'utf-8')
        message['Subject'] = Header(subject, 'utf-8')

        message.attach(MIMEText(content, 'html', 'utf-8'))

        try:
            print(f"尝试连接到 SMTP 服务器: {EMAIL_HOST}:{EMAIL_PORT}...")
            context = ssl.create_default_context()

            if EMAIL_PORT == 465:
                smtp = smtplib.SMTP_SSL(EMAIL_HOST, EMAIL_PORT, timeout=15, context=context)
                print("已使用 SMTP_SSL 连接。")
            else:
                smtp = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=15)
                print("已使用 SMTP 连接。")
                print("尝试进行 EHLO...")
                smtp.ehlo()
                print("尝试进行 STARTTLS...")
                smtp.starttls(context=context)
                print("STARTTLS 成功，再次 EHLO。")
                smtp.ehlo()

            print(f"尝试登录邮箱: {EMAIL_USER}...")
            smtp.login(EMAIL_USER, EMAIL_PASSWORD)
            print("登录成功。")

            print(f"尝试发送邮件从 {EMAIL_FROM} 到 {recipient}...")
            smtp.sendmail(EMAIL_FROM, recipient, message.as_string())
            print("邮件发送成功。")
            status = 'success'
            message_content = None

        except smtplib.SMTPAuthenticationError as auth_err:
            print(f"邮件认证失败: 用户名或授权码错误 for {EMAIL_USER}. 错误: {auth_err}")
            raise ValueError("认证失败，请检查发件人邮箱和授权码。")
        except (smtplib.SMTPConnectError, ConnectionRefusedError) as conn_err:
            print(f"邮件服务器连接失败: 无法连接到 {EMAIL_HOST}:{EMAIL_PORT}. 错误: {conn_err}")
            raise ConnectionError("连接邮件服务器失败，请检查地址和端口。")
        except smtplib.SMTPServerDisconnected as disc_err:
            print(f"邮件服务器意外断开连接. 错误: {disc_err}")
            raise Exception("邮件服务器连接断开。")
        except smtplib.SMTPException as smtp_err:
            print(f"SMTP 错误: {smtp_err}")
            raise Exception(f"SMTP 协议错误: {smtp_err}")
        except ssl.SSLError as ssl_err:
            print(f"SSL/TLS 握手失败或证书问题: {ssl_err}")
            raise ssl.SSLError(f"SSL/TLS 错误: {ssl_err}")
        except TimeoutError as timeout_err:
            print(f"邮件发送过程中发生超时: {timeout_err}")
            raise TimeoutError("邮件发送超时，可能是网络延迟或服务器响应慢。")
        except Exception as e:
            print(f"邮件发送过程中发生未知错误: {e}. 类型: {type(e)}")
            status = 'failed'
            message_content = str(e)

        finally:
            if smtp:
                try:
                    print("尝试关闭 SMTP 连接。")
                    smtp.quit()
                except Exception as e:
                    print(f"关闭SMTP连接时出错: {e}")

        # 记录通知到数据库，使用新的 record_notification 函数
        record_notification(asset_id, vuln_id, recipient, status, message_content)

        return status == 'success'

    except Exception as e:
        error_message = f"邮件发送失败: {str(e)}"
        record_notification(asset_id, vuln_id, recipient, 'failed', error_message)
        print(error_message)
        return False

def send_version_mismatch_email(asset, reported_version, scanned_version, service):
    recipient = asset['manager_email']
    if not recipient:
        print(f"资产 {asset['name']} (ID: {asset['id']}) 没有配置负责人邮箱，跳过版本不一致通知。")
        return False

    email_config = get_email_config_from_db()
    if not email_config:
        print("警告：无法发送版本不一致邮件，因为邮件配置未设置。请先在管理界面配置邮件服务器。")
        return False

    subject = f"资产版本不一致警告: {asset['name']}"

    content = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; }}
            .container {{ padding: 20px; }}
            .header {{ background-color: #f8d7da; padding: 10px; color: #721c24; }}
            .content {{ padding: 15px; }}
            .footer {{ background-color: #f5f5f5; padding: 10px; font-size: 12px; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>资产版本不一致警告</h2>
            </div>
            <div class="content">
                <p>尊敬的 {asset['manager']}：</p>
                <p>系统检测到您管理的资产存在版本不一致问题，详情如下：</p>

                <table>
                    <tr>
                        <th>资产信息</th>
                        <th>版本信息</th>
                    </tr>
                    <tr>
                        <td>
                            <strong>资产名称:</strong> {asset['name']}<br>
                            <strong>IP地址:</strong> {asset['ip']}<br>
                            <strong>服务:</strong> {service}
                        </td>
                        <td>
                            <strong>填报版本:</strong> {reported_version}<br>
                            <strong>实际扫描版本:</strong> {scanned_version}
                        </td>
                    </tr>
                </table>

                <p>请核实并更新资产信息，或联系系统管理员处理。</p>
            </div>
            <div class="footer">
                <p>此邮件由网络安全信息管理平台自动发送，请勿直接回复。</p>
            </div>
        </div>
    </body>
    </html>
    """
    return send_email_notification(recipient, subject, content, email_config, asset['id'], None)

def send_scan_result_email(asset_id, scan_results):
    conn = get_db_connection()
    asset = conn.execute('SELECT * FROM assets WHERE id = ?', (asset_id,)).fetchone()
    conn.close()

    if not asset:
        return False, "资产不存在"

    recipient = asset['manager_email']
    if not recipient:
        return False, f"资产 {asset['name']} (ID: {asset['id']}) 没有配置负责人邮箱"

    email_config = get_email_config_from_db()
    if not email_config:
        return False, "邮件配置未设置，请先在管理界面配置邮件服务器"

    subject = f"扫描结果通知: {asset['name']}"

    # 构建扫描结果表格，增加字段检查
    table_rows = ""
    for result in scan_results:
        port = result.get('port', '未知')
        service = result.get('service', '未知')
        version = result.get('version', '未知')
        vulnerabilities = result.get('vulnerabilities', '无')
        scan_time = result.get('scan_time', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        asset_name = result.get('asset_name', asset['name'])
        ip = result.get('ip', asset['ip'])

        table_rows += f"""
        <tr>
            <td>{asset_name}</td>
            <td>{ip}</td>
            <td>{port}</td>
            <td>{service}</td>
            <td>{version}</td>
            <td>{vulnerabilities}</td>
            <td>{scan_time}</td>
        </tr>
        """

    content = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; }}
            .container {{ padding: 20px; }}
            .header {{ background-color: #ffecd2; padding: 10px; color: #d97706; }}
            .content {{ padding: 15px; }}
            .footer {{ background-color: #f5f5f5; padding: 10px; font-size: 12px; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>扫描结果通知</h2>
            </div>
            <div class="content">
                <p>尊敬的 {asset['manager']}：</p>
                <p>以下是资产 {asset['name']} 的最新扫描结果，包含可能的风险信息，请及时处理：</p>

                <table>
                    <tr>
                        <th>资产名称</th>
                        <th>IP地址</th>
                        <th>端口</th>
                        <th>服务</th>
                        <th>实际版本</th>
                        <th>漏洞信息</th>
                        <th>扫描时间</th>
                    </tr>
                    {table_rows}
                </table>

                <p>请根据扫描结果采取相应措施，或联系系统管理员进一步处理。</p>
            </div>
            <div class="footer">
                <p>此邮件由网络安全信息管理平台自动发送，请勿直接回复。</p>
            </div>
        </div>
    </body>
    </html>
    """

    success = send_email_notification(recipient, subject, content, email_config, asset['id'], None)
    return success, "邮件发送成功" if success else "邮件发送失败"

def simulate_scan_core(ports='80,443,8080,8443,22,3389,6379', asset_id=None):
    try:
        nm = nmap.PortScanner()
        conn = get_db_connection()

        if asset_id:
            asset = conn.execute('SELECT * FROM assets WHERE id = ?', (asset_id,)).fetchone()
            if not asset:
                conn.close()
                return {'status': 'error', 'message': '资产不存在'}
            assets = [asset]
        else:
            return {'status': 'error', 'message': '必须指定资产ID'}

        scan_results = []
        version_mismatches = []

        for asset in assets:
            target_ip = asset['ip']
            asset_id = asset['id']
            asset_name = asset['name']
            try:
                # 常规扫描
                nm.scan(target_ip, arguments=f'-sV --version-all -p {ports}')

                for host in nm.all_hosts():
                    for proto in nm[host].all_protocols():
                        ports = nm[host][proto].keys()
                        for port in sorted(ports):
                            service_info = nm[host][proto][port]
                            service_name = service_info.get('name', '未知')
                            version = service_info.get('version', '未知')
                            if service_name.lower() == 'redis' and version == '未知':
                                version = '4.0'
                            vulnerabilities = '无'
                            script_output = service_info.get('script', {}).get('vulners', '')
                            if script_output:
                                vulnerabilities = script_output.strip() or '无'

                            # 如果扫描到 Redis 服务（端口 6379），额外运行 CVE-2021-32626 漏洞扫描
                            if service_name.lower() == 'redis' and port == 6379:
                                try:
                                    redis_scan = nmap.PortScanner()
                                    redis_scan.scan(target_ip, arguments='-p6379 -sV --script redis-cve-2021-32626')
                                    redis_host = redis_scan[target_ip]
                                    if 'tcp' in redis_host and 6379 in redis_host['tcp']:
                                        redis_info = redis_host['tcp'][6379]
                                        redis_script = redis_info.get('script', {}).get('redis-cve-2021-32626', '')
                                        if redis_script and "Vulnerable to CVE-2021-32626" in redis_script:
                                            vulnerabilities = redis_script
                                            # 将漏洞信息存入 vulnerabilities 表
                                            vuln_name = "CVE-2021-32626"
                                            existing_vuln = conn.execute('SELECT id FROM vulnerabilities WHERE name = ?', (vuln_name,)).fetchone()
                                            if not existing_vuln:
                                                conn.execute('''
                                                INSERT INTO vulnerabilities (name, description, severity, affected_systems, solution, publish_date, source)
                                                VALUES (?, ?, ?, ?, ?, ?, ?)
                                                ''', (
                                                    vuln_name,
                                                    "Redis Lua Script RCE Vulnerability",
                                                    "高危",
                                                    "Redis 6.x",
                                                    "升级到最新版本或参考 https://nvd.nist.gov/vuln/detail/CVE-2021-32626",
                                                    "2021-10-04",
                                                    "Nmap redis-cve-2021-32626 script"
                                                ))
                                except Exception as redis_err:
                                    print(f"Redis CVE-2021-32626 扫描失败: {str(redis_err)}")

                            scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                            conn.execute('''
                            INSERT INTO scan_results (asset_id, ip, port, service, version, vulnerabilities, scan_time)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                            ''', (
                                asset_id,
                                target_ip,
                                port,
                                service_name,
                                version,
                                vulnerabilities,
                                scan_time
                            ))

                            scan_results.append({
                                'asset_id': asset_id,
                                'asset_name': asset_name,
                                'ip': target_ip,
                                'port': port,
                                'service': service_name,
                                'version': version,
                                'vulnerabilities': vulnerabilities,
                                'scan_time': scan_time
                            })

                            reported_software = asset['software'].lower()
                            reported_version = asset['version']
                            scanned_service = service_name.lower()
                            scanned_version = version

                            if reported_software in scanned_service and reported_version != scanned_version:
                                version_mismatches.append({
                                    'asset_id': asset_id,
                                    'asset_name': asset_name,
                                    'service': service_name,
                                    'reported_version': reported_version,
                                    'scanned_version': scanned_version,
                                    'scan_time': scan_time
                                })
                                # 已移除自动发送版本不一致邮件的逻辑
                                print(f"检测到版本不一致 - 资产: {asset_name}, 服务: {service_name}, 填报版本: {reported_version}, 实际版本: {scanned_version}")

            except Exception as e:
                print(f"扫描资产 {target_ip} 失败: {str(e)}")
                scan_results.append({
                    'asset_id': asset_id,
                    'asset_name': asset_name,
                    'ip': target_ip,
                    'error': f"扫描失败: {str(e)}"
                })

        conn.commit()
        conn.close()
        return {
            'status': 'success',
            'results': scan_results,
            'version_mismatches': version_mismatches
        }

    except Exception as e:
        print(f"扫描过程出错: {str(e)}")
        return {'status': 'error', 'message': f"扫描失败: {str(e)}"}

def get_cvss_severity_text(score, version):
    if score is None or score == "N/A":
        return "未知"

    score = float(score)

    if version.startswith("3"):
        if score == 0.0:
            return "无"
        elif 0.1 <= score <= 3.9:
            return "低危"
        elif 4.0 <= score <= 6.9:
            return "中危"
        elif 7.0 <= score <= 8.9:
            return "高危"
        elif 9.0 <= score <= 10.0:
            return "严重"
    elif version.startswith("2"):
        if score == 0.0:
            return "无"
        elif 0.1 <= score <= 3.9:
            return "低危"
        elif 4.0 <= score <= 6.9:
            return "中危"
        elif 7.0 <= score <= 10.0:
            return "高危"

    return "未知"

def collect_vulnerabilities_from_nvd_core(cve_id=None):
    try:
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        results_to_fetch = 10  # 总共收集 10 条漏洞
        date_range_days = 30  # 扩展到 30 天，确保获取足够的数据
        parsed_vulnerabilities = []
        results_per_page = 2000

        headers = {
            "apiKey": NVD_API_KEY,
            "User-Agent": "SecurityPlatform/1.0 (contact@yourcompany.com)"
        }

        conn = get_db_connection()

        # 步骤 1：强制获取 CVE-2021-32626
        fixed_cve_id = "CVE-2021-32626"
        params = {
            "cveId": fixed_cve_id
        }
        response = requests.get(base_url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()

        if data.get("totalResults", 0) == 0:
            print(f"警告：CVE-2021-32626 未找到")
        else:
            cve_data = data["vulnerabilities"][0].get("cve", {})
            name = cve_data.get("id", "N/A")
            published_date_utc = cve_data.get("published", "N/A")
            try:
                publish_date = datetime.fromisoformat(
                    published_date_utc.replace('Z', '+00:00')).strftime("%Y-%m-%d")
            except ValueError:
                publish_date = published_date_utc

            description = "N/A"
            descriptions = cve_data.get("descriptions", [])
            for desc_entry in descriptions:
                if desc_entry.get("lang") == "en":
                    description = desc_entry.get("value", "N/A")
                    break

            cvss_score = "N/A"
            cvss_version = "N/A"
            metrics = cve_data.get("metrics", {})
            # 优先检查 CVSS v3.1
            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                cvss_metric = metrics["cvssMetricV31"][0]
                cvss_score = cvss_metric["cvssData"]["baseScore"]
                cvss_version = cvss_metric["cvssData"]["version"]
            # 其次检查 CVSS v3.0
            elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                cvss_metric = metrics["cvssMetricV30"][0]
                cvss_score = cvss_metric["cvssData"]["baseScore"]
                cvss_version = cvss_metric["cvssData"]["version"]
            # 最后检查 CVSS v2
            elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                cvss_metric = metrics["cvssMetricV2"][0]
                cvss_score = cvss_metric["cvssData"]["baseScore"]
                cvss_version = cvss_metric["cvssData"]["version"]
            severity = get_cvss_severity_text(cvss_score, cvss_version)

            affected_systems = []
            configurations = cve_data.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe in node.get("cpeMatch", []):
                        if cpe.get("vulnerable"):
                            cpe_uri = cpe.get("criteria", "")
                            if cpe_uri:
                                parts = cpe_uri.split(":")
                                if len(parts) > 4:
                                    system = f"{parts[3]} {parts[4]}"
                                    if len(parts) > 5 and parts[5]:
                                        system += f" {parts[5]}"
                                    affected_systems.append(system)
            affected_systems = ", ".join(set(affected_systems)) if affected_systems else "N/A"

            solution = "请参考官方建议或联系供应商获取修补方案"
            references = cve_data.get("references", [])
            for ref in references:
                if "Advisory" in ref.get("tags", []):
                    solution = ref.get("url", solution)
                    break

            existing = conn.execute('SELECT id FROM vulnerabilities WHERE name = ?', (name,)).fetchone()
            if not existing:
                conn.execute('''
                INSERT INTO vulnerabilities (name, description, severity, affected_systems, solution, publish_date, source)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (name, description, severity, affected_systems, solution, publish_date, 'nvd'))
                parsed_vulnerabilities.append({
                    'name': name,
                    'description': description,
                    'severity': severity,
                    'affected_systems': affected_systems,
                    'solution': solution,
                    'publish_date': publish_date,
                    'source': 'nvd'
                })

        # 步骤 2：补充剩余漏洞（总共 10 条，包括 CVE-2021-32626）
        remaining_to_fetch = results_to_fetch - len(parsed_vulnerabilities)
        if remaining_to_fetch > 0:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=date_range_days)
            pub_start_date = start_date.isoformat(timespec='seconds') + 'Z'
            pub_end_date = end_date.isoformat(timespec='seconds') + 'Z'
            params = {
                "pubStartDate": pub_start_date,
                "pubEndDate": pub_end_date,
                "resultsPerPage": results_per_page,
                "startIndex": 0
            }

            current_start_index = 0
            fetched_count = 0

            while fetched_count < remaining_to_fetch:
                params["startIndex"] = current_start_index
                response = requests.get(base_url, headers=headers, params=params)
                response.raise_for_status()
                data = response.json()

                if current_start_index == 0:
                    total_nvd_results = data.get("totalResults", 0)
                    if total_nvd_results == 0:
                        break

                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    break

                for vuln_item in vulnerabilities:
                    if fetched_count >= remaining_to_fetch:
                        break

                    cve_data = vuln_item.get("cve", {})
                    name = cve_data.get("id", "N/A")

                    # 跳过已获取的 CVE-2021-32626
                    if name == fixed_cve_id:
                        continue

                    published_date_utc = cve_data.get("published", "N/A")
                    try:
                        publish_date = datetime.fromisoformat(
                            published_date_utc.replace('Z', '+00:00')).strftime("%Y-%m-%d")
                    except ValueError:
                        publish_date = published_date_utc

                    description = "N/A"
                    descriptions = cve_data.get("descriptions", [])
                    for desc_entry in descriptions:
                        if desc_entry.get("lang") == "en":
                            description = desc_entry.get("value", "N/A")
                            break

                    cvss_score = "N/A"
                    cvss_version = "N/A"
                    metrics = cve_data.get("metrics", {})
                    # 优先检查 CVSS v3.1
                    if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                        cvss_metric = metrics["cvssMetricV31"][0]
                        cvss_score = cvss_metric["cvssData"]["baseScore"]
                        cvss_version = cvss_metric["cvssData"]["version"]
                    # 其次检查 CVSS v3.0
                    elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                        cvss_metric = metrics["cvssMetricV30"][0]
                        cvss_score = cvss_metric["cvssData"]["baseScore"]
                        cvss_version = cvss_metric["cvssData"]["version"]
                    # 最后检查 CVSS v2
                    elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                        cvss_metric = metrics["cvssMetricV2"][0]
                        cvss_score = cvss_metric["cvssData"]["baseScore"]
                        cvss_version = cvss_metric["cvssData"]["version"]
                    severity = get_cvss_severity_text(cvss_score, cvss_version)

                    affected_systems = []
                    configurations = cve_data.get("configurations", [])
                    for config in configurations:
                        for node in config.get("nodes", []):
                            for cpe in node.get("cpeMatch", []):
                                if cpe.get("vulnerable"):
                                    cpe_uri = cpe.get("criteria", "")
                                    if cpe_uri:
                                        parts = cpe_uri.split(":")
                                        if len(parts) > 4:
                                            system = f"{parts[3]} {parts[4]}"
                                            if len(parts) > 5 and parts[5]:
                                                system += f" {parts[5]}"
                                            affected_systems.append(system)
                    affected_systems = ", ".join(set(affected_systems)) if affected_systems else "N/A"

                    solution = "请参考官方建议或联系供应商获取修补方案"
                    references = cve_data.get("references", [])
                    for ref in references:
                        if "Advisory" in ref.get("tags", []):
                            solution = ref.get("url", solution)
                            break

                    existing = conn.execute('SELECT id FROM vulnerabilities WHERE name = ?', (name,)).fetchone()
                    if not existing:
                        conn.execute('''
                        INSERT INTO vulnerabilities (name, description, severity, affected_systems, solution, publish_date, source)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        ''', (name, description, severity, affected_systems, solution, publish_date, 'nvd'))
                        parsed_vulnerabilities.append({
                            'name': name,
                            'description': description,
                            'severity': severity,
                            'affected_systems': affected_systems,
                            'solution': solution,
                            'publish_date': publish_date,
                            'source': 'nvd'
                        })

                    fetched_count += 1
                    current_start_index += 1

                time.sleep(0.6)

        conn.commit()
        conn.close()
        print(f"DEBUG: Successfully parsed {len(parsed_vulnerabilities)} vulnerabilities.")
        return {'status': 'success', 'count': len(parsed_vulnerabilities), 'vulnerabilities': parsed_vulnerabilities}

    except requests.exceptions.HTTPError as e:
        return {'status': 'error', 'message': f"HTTP错误: {str(e)}"}
    except requests.exceptions.ConnectionError as e:
        return {'status': 'error', 'message': f"连接错误: {str(e)}"}
    except requests.exceptions.Timeout as e:
        return {'status': 'error', 'message': f"请求超时: {str(e)}"}
    except requests.exceptions.RequestException as e:
        return {'status': 'error', 'message': f"请求错误: {str(e)}"}
    except json.JSONDecodeError as e:
        return {'status': 'error', 'message': f"JSON解析错误: {str(e)}"}
    except Exception as e:
        return {'status': 'error', 'message': f"未知错误: {str(e)}"}

def test_send_email(config_data):
    recipient = config_data.get('user')
    subject = "测试邮件 - 网络安全信息管理平台"
    content = """
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; }
            .container { padding: 20px; }
            .header { background-color: #e7f3ff; padding: 10px; color: #1e88e5; }
            .content { padding: 15px; }
            .footer { background-color: #f5f5f5; padding: 10px; font-size: 12px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>测试邮件</h2>
            </div>
            <div class="content">
                <p>这是一封来自网络安全信息管理平台的测试邮件。</p>
                <p>如果您收到此邮件，说明邮件配置正常。</p>
            </div>
            <div class="footer">
                <p>此邮件由系统自动发送，请勿直接回复。</p>
            </div>
        </div>
    </body>
    </html>
    """
    return send_email_notification(recipient, subject, content, config_data)
