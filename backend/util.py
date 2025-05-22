import nmap
import json
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
from datetime import datetime, timedelta
import requests
import ssl # 导入 ssl 模块

# 导入数据库操作函数
from db import get_db_connection, record_notification, get_email_config_from_db

# NVD API Key (请替换为您的NVD API Key)
NVD_API_KEY = "769ad379-6974-4666-9370-183ac7088722"

# 邮件发送函数 - 现在接收一个 config 字典，包含了邮件服务器的所有配置
def send_email_notification(recipient, subject, content, config, asset_id=None, vuln_id=None):
    smtp = None # 确保 smtp 在 try 块外部被初始化为 None
    try:
        EMAIL_HOST = config.get('host')
        EMAIL_PORT = int(config.get('port')) # 确保端口是整数
        EMAIL_USER = config.get('user')
        EMAIL_PASSWORD = config.get('password')
        # sender_from 是数据库字段名，前端传入的可能是 'from'
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
            # 创建一个默认的SSL上下文，它可以信任标准的CA证书
            context = ssl.create_default_context()

            if EMAIL_PORT == 465: # SMTP_SSL 默认端口
                smtp = smtplib.SMTP_SSL(EMAIL_HOST, EMAIL_PORT, timeout=15, context=context)
                print("已使用 SMTP_SSL 连接。")
            else: # 普通 SMTP + STARTTLS (如 25, 587)
                smtp = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=15)
                print("已使用 SMTP 连接。")
                print("尝试进行 EHLO...")
                smtp.ehlo()
                print("尝试进行 STARTTLS...")
                smtp.starttls(context=context) # 显式传入 context
                print("STARTTLS 成功，再次 EHLO。")
                smtp.ehlo()

            print(f"尝试登录邮箱: {EMAIL_USER}...")
            smtp.login(EMAIL_USER, EMAIL_PASSWORD)
            print("登录成功。")

            print(f"尝试发送邮件从 {EMAIL_FROM} 到 {recipient}...")
            smtp.sendmail(EMAIL_FROM, recipient, message.as_string())
            print("邮件发送成功。")

            if asset_id and vuln_id:
                record_notification(asset_id, vuln_id, recipient, 'success')
            return True # 邮件发送成功，直接返回 True

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
            # 捕获所有其他未知错误，并打印类型，便于调试
            print(f"邮件发送过程中发生未知错误: {e}. 类型: {type(e)}")
            raise # 重新抛出异常，让外层捕获

        finally:
            # 确保 smtp 对象存在且已连接（通过简单尝试 quit()）
            # 最简单且通常最可靠的方式是：如果 smtp 对象不为 None，就尝试 quit()
            # 因为 smtplib 会在内部处理好连接状态，如果未连接，quit() 会报错但被捕获
            if smtp:
                try:
                    print("尝试关闭 SMTP 连接。")
                    smtp.quit()
                except Exception as e:
                    # 再次捕获关闭时的错误，防止影响主流程
                    # 这个错误通常是无害的，意味着连接可能已经关闭或未完全建立
                    print(f"关闭SMTP连接时出错: {e}")

    except Exception as e:
        error_message = f"邮件发送失败: {str(e)}"
        if asset_id and vuln_id:
            record_notification(asset_id, vuln_id, recipient, f'failed: {error_message}')
        print(error_message)
        return False

# 发送版本不一致通知 - 现在动态获取最新配置
def send_version_mismatch_email(asset, reported_version, scanned_version, service):
    recipient = asset['manager_email']
    if not recipient:
        print(f"资产 {asset['name']} (ID: {asset['id']}) 没有配置负责人邮箱，跳过版本不一致通知。")
        return False

    # 获取最新的邮件配置
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
    # 传递邮件配置给 send_email_notification
    return send_email_notification(recipient, subject, content, email_config, asset['id'], None)


# Nmap 扫描功能（支持单资产扫描）
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

        # 在扫描开始前获取最新的邮件配置，用于在扫描时发送版本不一致通知
        email_config_for_mismatch = get_email_config_from_db()


        for asset in assets:
            target_ip = asset['ip']
            asset_id = asset['id']
            asset_name = asset['name']
            try:
                # 增强 Nmap 扫描参数，启用详细版本探测和漏洞脚本
                nm.scan(target_ip, arguments=f'-sV --version-all --script vulners -p {ports}')

                for host in nm.all_hosts():
                    for proto in nm[host].all_protocols():
                        ports = nm[host][proto].keys()
                        for port in sorted(ports):
                            service_info = nm[host][proto][port]
                            service_name = service_info.get('name', '未知')
                            # 获取版本信息
                            version = service_info.get('version', '未知')
                            # 如果版本探测失败，模拟 Redis 版本
                            if service_name.lower() == 'redis' and version == '未知':
                                version = '4.0'  # 模拟 Redis 4.0
                            # 获取漏洞信息（通过 vulners 脚本）
                            vulnerabilities = '无'
                            script_output = service_info.get('script', {}).get('vulners', '')
                            if script_output:
                                vulnerabilities = script_output.strip() or '无'

                            scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                            # 插入扫描结果
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

                            # 版本比对
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
                                # 发送邮件通知，传入 email_config_for_mismatch
                                if email_config_for_mismatch:
                                    send_version_mismatch_email(
                                        asset,
                                        reported_version,
                                        scanned_version,
                                        service_name
                                    )
                                else:
                                    print("警告：邮件配置未设置，无法发送版本不一致通知。")


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
    """根据 CVSS 分数和版本返回危害等级的中文文本。"""
    if score is None or score == "N/A":
        return "N/A"

    score = float(score)  # 确保是浮点数进行比较

    if version.startswith("3"):  # CVSSv3.x
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
    elif version.startswith("2"):  # CVSSv2
        if score == 0.0:
            return "无"
        elif 0.1 <= score <= 3.9:
            return "低危"
        elif 4.0 <= score <= 6.9:
            return "中危"
        elif 7.0 <= score <= 10.0:
            return "高危"  # CVSSv2 没有 Critical 级别

    return "未知"


def collect_vulnerabilities_from_nvd_core():
    """
    使用 NVD API 获取并解析最近15天的漏洞信息，存储到数据库。
    """
    try:
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        results_to_fetch = 10  # 获取前10条漏洞
        date_range_days = 15  # 获取过去15天的漏洞
        parsed_vulnerabilities = []
        results_per_page = 2000  # NVD API 最大每页结果数

        # 计算日期范围
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=date_range_days)
        pub_start_date = start_date.isoformat(timespec='seconds') + 'Z'
        pub_end_date = end_date.isoformat(timespec='seconds') + 'Z'

        headers = {
            "apiKey": NVD_API_KEY,
            "User-Agent": "SecurityPlatform/1.0 (contact@yourcompany.com)"
        }

        current_start_index = 0
        fetched_count = 0

        conn = get_db_connection()

        while fetched_count < results_to_fetch:
            params = {
                "pubStartDate": pub_start_date,
                "pubEndDate": pub_end_date,
                "resultsPerPage": results_per_page,
                "startIndex": current_start_index
            }

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
                if fetched_count >= results_to_fetch:
                    break

                cve_data = vuln_item.get("cve", {})

                # 漏洞名称 (CVE ID)
                name = cve_data.get("id", "N/A")

                # 发布日期
                published_date_utc = cve_data.get("published", "N/A")
                try:
                    publish_date = datetime.fromisoformat(
                        published_date_utc.replace('Z', '+00:00')).strftime("%Y-%m-%d")
                except ValueError:
                    publish_date = published_date_utc

                # 详细描述
                description = "N/A"
                descriptions = cve_data.get("descriptions", [])
                for desc_entry in descriptions:
                    if desc_entry.get("lang") == "en":
                        description = desc_entry.get("value", "N/A")
                        break

                # 危害等级
                cvss_score = "N/A"
                cvss_version = "N/A"
                metrics = cve_data.get("metrics", {})
                if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                    cvss_metric = metrics["cvssMetricV31"][0].get("cvssData", {})
                    cvss_score = cvss_metric.get("baseScore", "N/A")
                    cvss_version = "3.1"
                elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                    cvss_metric = metrics["cvssMetricV30"][0].get("cvssData", {})
                    cvss_score = cvss_metric.get("baseScore", "N/A")
                    cvss_version = "3.0"
                elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                    cvss_metric = metrics["cvssMetricV2"][0].get("cvssData", {})
                    cvss_score = cvss_metric.get("baseScore", "N/A")
                    cvss_version = "2.0"
                severity = get_cvss_severity_text(cvss_score, cvss_version)

                # 影响系统
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
                                        affected_systems.append(f"{parts[3]} {parts[4]}")
                affected_systems = ", ".join(set(affected_systems)) if affected_systems else "N/A"

                # 解决方案
                solution = "请参考官方建议或联系供应商获取修补方案"
                references = cve_data.get("references", [])
                for ref in references:
                    if "Advisory" in ref.get("tags", []):
                        solution = ref.get("url", solution)
                        break

                # 检查是否已存在
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

            time.sleep(0.6)  # 遵守 NVD API 速率限制

        conn.commit()
        conn.close()
        print(f"DEBUG: Successfully parsed {len(parsed_vulnerabilities)} vulnerabilities.")
        return {'status': 'success', 'count': len(parsed_vulnerabilities)}

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

# 新增：测试邮件发送函数
def test_send_email(config_data):
    # 对于测试邮件，收件人就是发件人邮箱
    recipient = config_data.get('user')
    subject = "测试邮件 - 网络安全信息管理平台"
    content = """
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; }
            .container { padding: 20px; }
            .header { background-color: #e7f3ff; padding: 10px; color: #1e88e5; }
            .content {{ padding: 15px; }}
            .footer {{ background-color: #f5f5f5; padding: 10px; font-size: 12px; }}
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
    # 调用 send_email_notification，传入完整的 config_data
    return send_email_notification(recipient, subject, content, config_data)
