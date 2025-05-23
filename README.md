# 1. 前端初始化 
npm create vite@latest frontend -- --template vue
cd frontend
npm install axios element-plus vue-router echarts

# 2. 后端初始化
mkdir backend
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install flask flask-cors requests beautifulsoup4 sqlite3

## 2.1 创建虚拟环境
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

## 2.2 安装依赖
上面提供的requirements.txt内容保存到文件
pip install -r requirements.txt

## 2.3 更新依赖
pip install --upgrade werkzeug Flask

# 3. NVD (National Vulnerability Database) - 美国国家漏洞数据库

网站： https://nvd.nist.gov/
API 文档/开发者页面： https://nvd.nist.gov/developers
特点： NVD 是 NIST (美国国家标准与技术研究院) 维护的官方数据库，它聚合了所有已公开的 CVE (Common Vulnerabilities and Exposures) 信息，并提供了丰富的补充数据，如 CVSS 评分 (Common Vulnerability Scoring System)、受影响产品 (CPE - Common Platform Enumeration) 等。它的数据结构化非常好，非常适合自动化处理。
API 访问： NVD 提供了 RESTful API，你可以通过 HTTP 请求来获取 CVE 和 CPE 数据。为了获得更高的请求速率，你可以免费申请一个 API Key。
API Key 申请页面： https://nvd.nist.gov/developers/request-an-api-key
Python 库： 社区也有一些 Python 封装库，如 nvdlib，可以进一步简化 API 调用。

P.S. 需要申请 API Key: 769ad379-6974-4666-9370-183ac7088722

# 4. 安装 nmap 和 nmap 依赖
wget https://files.pythonhosted.org/packages/f7/1b/8e6b3d1461331e4e8600faf099e7c62ba3c1603987dafdd558681fb8ba37/python-nmap-0.7.1.tar.gz

tar -xzf python-nmap-0.7.1.tar.gz
cd python-nmap-0.7.1

python setup.py install

sudo apt-get update
sudo apt-get install nmap


# 5. 安装 Vulscan
cd /usr/share/nmap/scripts/
git clone https://github.com/scipag/vulscan.git

nmap --script-updatedb

# 6. 修改 redis 配置
vim /etc/redis/redis.conf

protected_mode 改成 no
bind: 改成0.0.0.0

# 7. 设计漏洞
redis + nmap

## 7.1 安装和配置 redis
进入 software 目录，提供 redis-6.2.5 版本，编译源码：
wget https://download.redis.io/releases/redis-6.2.5.tar.gz
tar -xzf redis-6.2.5.tar.gz
cd redis-6.2.5

make
sudo make install

redis-server --port 6379 &
redis-cli ping


pkill redis-server
redis-server /path/to/redis.conf --port 6379 &



## 7.2 安装和配置 nmap
进入 software 目录，执行如下指令：
tar -xjf nmap-7.94.tar.bz2
cd nmap-7.94
sudo apt update
sudo apt install -y build-essential libssl-dev libpcap-dev
./configure
make
sudo make install
nmap --version
sudo nmap --script-updatedb


## 7.3 扫描漏洞
编写一个简单的检测脚本：
创建脚本文件 /usr/share/nmap/scripts/redis-cve-2021-32626.nse：
lua

复制
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Detects CVE-2021-32626 in Redis servers, a Lua script RCE vulnerability.
]]

author = "Custom Script"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(6379, "redis")

action = function(host, port)
    local version = port.version and port.version.version or ""
    if version == "" then
        return "Could not determine Redis version"
    end

    if string.match(version, "^6%.2%.[0-5]$") or string.match(version, "^[4-5]%.") then
        return "Vulnerable to CVE-2021-32626: Redis Lua Script RCE Vulnerability\n" ..
               "CVSS: 8.8 (HIGH)\n" ..
               "References: https://nvd.nist.gov/vuln/detail/CVE-2021-32626"
    end
    return "Not vulnerable to CVE-2021-32626"
end
更新脚本数据库：
bash

复制
sudo nmap --script-updatedb
运行脚本：
bash

复制
nmap -sV -p6379 --script redis-cve-2021-32626 172.21.94.108

