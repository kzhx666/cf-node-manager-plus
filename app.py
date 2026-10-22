# -*- coding: utf-8 -*-
import json, base64, urllib.parse, os, copy, datetime, re, random, threading, time, socket, shutil, glob, asyncio, logging, zipfile, io, binascii, ssl
from flask import Flask, request, render_template, render_template_string, Response, jsonify, send_file, redirect, make_response, abort
from werkzeug.middleware.proxy_fix import ProxyFix
from collections import deque

try: import requests; import aiohttp; import yaml; import geoip2.database
except: pass

app = Flask(__name__)
try: app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
except: pass

WEB_PASSWORD = os.environ.get("WEB_PASSWORD", "admin")
LOGIN_PATH = "admin_login"
DEFAULT_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DATA_DIR = os.environ.get("DATA_DIR", "/app/data" if os.path.exists("/app/data") else DEFAULT_DATA_DIR)
APP_VERSION = "v43.20-komari-nezha-automatch"
DATA_FILE = os.path.join(DATA_DIR, "data.json")
BACKUP_FILE = os.path.join(DATA_DIR, "data.json.bak")
CACHE_FILE = os.path.join(DATA_DIR, "domain_cache.json")
GEOIP_DB = os.path.join(DATA_DIR, "Country.mmdb")
LOG_FILE = os.path.join(DATA_DIR, "app.log")

MAX_NODES_OUTPUT = 5000
DATA_LOCK = threading.Lock()
IS_SYNCING = False 
SUB_TOKEN_CHECK = True
IP_SEPARATOR = "##### ⬇️ 自动获取 (请写在横线上面) ⬇️ #####"
DEFAULT_IPS = "104.16.1.1\n172.67.1.1"

DEFAULT_OPENCLASH_TPL = """port: 7890
socks-port: 7891
mixed-port: 7890
mode: rule
log-level: info
allow-lan: true
external-controller: 0.0.0.0:9090
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  nameserver:
    - 223.5.5.5
    - 119.29.29.29
  fallback:
    - 1.1.1.1
    - 8.8.8.8
proxies:
#PLACEHOLDER#
proxy-groups:
  - name: 🚀 节点选择
    type: select
    proxies:
      - ♻️ 自动优选
      - 🎯 全球直连
#PLACEHOLDER_NAMES#
  - name: ♻️ 自动优选
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
    proxies:
#PLACEHOLDER_NAMES#
  - name: 🎯 全球直连
    type: select
    proxies:
      - DIRECT
  - name: 🐟 漏网之鱼
    type: select
    proxies:
      - 🚀 节点选择
      - 🎯 全球直连
rules:
  - GEOIP,CN,🎯 全球直连
  - MATCH,🐟 漏网之鱼
"""

DEFAULT_SINGBOX_TPL = json.dumps({
    "log": {"level": "info", "timestamp": True},
    "dns": {
        "servers": [
            {"tag": "dns-remote", "address": "tls://1.1.1.1"},
            {"tag": "dns-direct", "address": "https://223.5.5.5/dns-query", "detour": "direct"},
            {"tag": "dns-block", "address": "rcode://success"}
        ],
        "rules": [
            {"outbound": "any", "server": "dns-direct"},
            {"clash_mode": "Global", "server": "dns-remote"},
            {"clash_mode": "Direct", "server": "dns-direct"},
            {"rule_set": "geosite-cn", "server": "dns-direct"}
        ],
        "strategy": "prefer_ipv4"
    },
    "inbounds": [
        {
            "type": "tun",
            "tag": "tun-in",
            "interface_name": "tun0",
            "inet4_address": "172.19.0.1/30",
            "auto_route": True,
            "strict_route": True,
            "stack": "system",
            "sniff": True
        },
        {
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": 2080,
            "sniff": True
        }
    ],
    "outbounds": "#PLACEHOLDER#",
    "route": {
        "auto_detect_interface": True,
        "final": "🚀 节点选择",
        "rules": [
            {"type": "logical", "mode": "or", "rules": [{"port": 53}, {"protocol": "dns"}], "outbound": "dns-out"},
            {"clash_mode": "Direct", "outbound": "🎯 全球直连"},
            {"clash_mode": "Global", "outbound": "🚀 节点选择"},
            {"rule_set": "geosite-geolocation-!cn", "outbound": "🚀 节点选择"},
            {"rule_set": ["geoip-cn", "geosite-cn"], "outbound": "🎯 全球直连"}
        ],
        "rule_set": [
            {
                "type": "remote",
                "tag": "geosite-geolocation-!cn",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-!cn.srs",
                "download_detour": "🎯 全球直连"
            },
            {
                "type": "remote",
                "tag": "geosite-cn",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
                "download_detour": "🎯 全球直连"
            },
            {
                "type": "remote",
                "tag": "geoip-cn",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
                "download_detour": "🎯 全球直连"
            }
        ]
    }
}, indent=2, ensure_ascii=False)

if not os.path.exists(DATA_DIR): os.makedirs(DATA_DIR, exist_ok=True)

def write_log(msg):
    t = datetime.datetime.now().strftime("%m-%d %H:%M:%S")
    print(f"[{t}] {msg}", flush=True)
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f: f.write(f"[{t}] {msg}\n")
    except: pass

def init_geoip():
    if not os.path.exists(GEOIP_DB) and requests:
        try:
            r = requests.get("https://github.com/Hackl0us/GeoIP2-CN/raw/release/Country.mmdb", stream=True, timeout=60)
            if r.status_code == 200:
                with open(GEOIP_DB, 'wb') as f: f.write(r.content)
        except: pass
threading.Thread(target=init_geoip).start()

DOMAIN_CACHE = {}
if os.path.exists(CACHE_FILE):
    try: 
        with open(CACHE_FILE, 'r') as f: DOMAIN_CACHE = json.load(f)
    except: pass
def save_cache():
    try: 
        with open(CACHE_FILE, 'w') as f: json.dump(DOMAIN_CACHE, f)
    except: pass

def load_data():
    default_conf = {
        "ips": DEFAULT_IPS,
        "remote_subs": [],
        "cached_nodes": [],
        "cached_probe_nodes": [],
        "cf_api_url": "",
        "custom_doh": "",
        "max_ips_per_node": 0,
        "clash_tpl": "proxies:\n#PLACEHOLDER#",
        "singbox_tpl": DEFAULT_SINGBOX_TPL,
        "last_sync": int(time.time()),
        "config": {
            "interval": 14400,
            "threads": 8,
            "timeout": 20,
            "ua": "v2rayNG/1.8.5",
            "sub_token": WEB_PASSWORD,
            "web_password": WEB_PASSWORD,
            "custom_groups": "snip, work",
            "probe_type": "komari",
            "probe_url": "",
            "probe_token": "",
            "nezha_url": "",
            "nezha_token": ""
        }
    }
    with DATA_LOCK:
        if not os.path.exists(DATA_FILE):
            if os.path.exists(BACKUP_FILE): shutil.copy2(BACKUP_FILE, DATA_FILE)
            else: return default_conf
        try:
            with open(DATA_FILE, 'r', encoding='utf-8') as f:
                d = json.load(f)
                if "config" not in d: d["config"] = default_conf["config"]
                if "ips" not in d: d["ips"] = default_conf["ips"]
                if "singbox_tpl" not in d: d["singbox_tpl"] = default_conf["singbox_tpl"]
                if "clash_tpl" not in d: d["clash_tpl"] = default_conf["clash_tpl"]
                if "cached_probe_nodes" not in d: d["cached_probe_nodes"] = []
                if "web_password" not in d["config"]: d["config"]["web_password"] = WEB_PASSWORD
                if "probe_type" not in d["config"]: d["config"]["probe_type"] = "komari"
                if "probe_url" not in d["config"]: d["config"]["probe_url"] = d["config"].get("nezha_url", "")
                if "probe_token" not in d["config"]: d["config"]["probe_token"] = d["config"].get("nezha_token", "")
                if "nezha_url" not in d["config"]: d["config"]["nezha_url"] = d["config"]["probe_url"]
                if "nezha_token" not in d["config"]: d["config"]["nezha_token"] = d["config"]["probe_token"]
                
                # 自动清理历史遗留的 24TB 虚假 subconverter 流量占位数据
                for sub in d.get('remote_subs', []):
                    inf = sub.get('info')
                    if isinstance(inf, dict):
                        tot = str(inf.get('total', ''))
                        exp = str(inf.get('expire', ''))
                        if '24576' in tot or '26388' in tot or '270' in exp or '267' in exp:
                            sub['info'] = None
                return d
        except Exception as e:
            write_log(f"Load Error: {e}")
            if os.path.exists(BACKUP_FILE):
                try: shutil.copy2(BACKUP_FILE, DATA_FILE); return json.load(open(DATA_FILE))
                except: pass
            return default_conf

def save_data(data):
    with DATA_LOCK:
        try:
            if os.path.exists(DATA_FILE): shutil.copy2(DATA_FILE, BACKUP_FILE)
            tmp = DATA_FILE + ".tmp"
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
                f.flush(); os.fsync(f.fileno())
            os.replace(tmp, DATA_FILE)
        except Exception as e: write_log(f"Save Error: {e}")

def get_current_password():
    d = load_data()
    return d.get('config', {}).get('web_password') or WEB_PASSWORD

def is_authenticated():
    expected_pwd = get_current_password()
    d = load_data()
    sub_token = d.get('config', {}).get('sub_token') or expected_pwd
    valid_keys = {k for k in [expected_pwd, sub_token, WEB_PASSWORD] if k}
    
    # 1. Cookie 鉴权
    cookie_auth = request.cookies.get('auth')
    if cookie_auth and cookie_auth in valid_keys:
        return True
        
    # 2. Authorization Header (Bearer <token> 或直接 <token>)
    auth_header = request.headers.get('Authorization', '').strip()
    if auth_header:
        token = auth_header[7:].strip() if auth_header.lower().startswith('bearer ') else auth_header
        if token and token in valid_keys:
            return True

    # 3. 自定义 Header
    custom_key = request.headers.get('X-API-Key', '').strip() or request.headers.get('X-Token', '').strip()
    if custom_key and custom_key in valid_keys:
        return True

    # 4. URL Query 参数 (?token=... 或 ?password=...)
    query_token = (request.args.get('token') or request.args.get('password') or '').strip()
    if query_token and query_token in valid_keys:
        return True

    # 5. POST JSON / Form 中的 token
    if request.is_json:
        try:
            req_data = request.get_json(silent=True) or {}
            body_token = str(req_data.get('token') or req_data.get('password') or '').strip()
            if body_token and body_token in valid_keys:
                return True
        except: pass
    elif request.form:
        form_token = (request.form.get('token') or request.form.get('password') or '').strip()
        if form_token and form_token in valid_keys:
            return True

    return False

def split_host_port(target_str, default_port=None):
    if not target_str:
        return "", default_port
    target_str = str(target_str).strip()
    if target_str.startswith('[') and ']' in target_str:
        host = target_str[1:target_str.find(']')]
        rest = target_str[target_str.find(']')+1:]
        port = rest[1:] if rest.startswith(':') else default_port
        try: return host, int(port) if port else default_port
        except: return host, default_port
    if target_str.count(':') == 1:
        h, p = target_str.split(':', 1)
        try: return h, int(p)
        except: return h, default_port
    return target_str, default_port

def extract_speedtest_ips(content, limit=0):
    content = (content or "").strip()
    if not content: return []
    lines = content.splitlines()
    candidates = []
    
    is_csv = any("," in l and ("ip" in l.lower() or "延迟" in l or "速度" in l or "loss" in l.lower()) for l in lines[:5])
    if is_csv:
        import csv
        reader = csv.reader(io.StringIO(content))
        rows = [r for r in reader if r]
        if rows:
            header = [h.strip().lower() for h in rows[0]]
            ip_idx = -1; port_idx = -1; loss_idx = -1; speed_idx = -1
            for idx, col in enumerate(header):
                if 'ip' in col and ip_idx == -1: ip_idx = idx
                elif ('端口' in col or 'port' in col) and port_idx == -1: port_idx = idx
                elif ('丢包' in col or 'loss' in col) and loss_idx == -1: loss_idx = idx
                elif ('速度' in col or 'speed' in col) and speed_idx == -1: speed_idx = idx
            
            if ip_idx != -1:
                data_rows = rows[1:]
                if speed_idx != -1:
                    def parse_speed(r):
                        try:
                            v = r[speed_idx].replace('mb/s', '').replace('mb', '').strip()
                            return float(v)
                        except: return 0.0
                    data_rows.sort(key=parse_speed, reverse=True)
                
                for row in data_rows:
                    if len(row) > ip_idx:
                        ip_val = row[ip_idx].strip()
                        if not ip_val: continue
                        if loss_idx != -1 and len(row) > loss_idx:
                            loss_str = row[loss_idx].replace('%', '').strip()
                            try:
                                if float(loss_str) >= 100: continue
                            except: pass
                        port_val = row[port_idx].strip() if (port_idx != -1 and len(row) > port_idx) else ""
                        item = f"{ip_val}:{port_val}" if port_val and port_val != "443" else ip_val
                        if item not in candidates: candidates.append(item)
    
    if not candidates:
        ipv4_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b', content)
        ipv6_bracket = re.findall(r'\[[a-fA-F0-9:]+\](?::\d+)?', content)
        for m in ipv4_matches + ipv6_bracket:
            if m not in candidates: candidates.append(m)
            
    if limit > 0 and len(candidates) > limit:
        candidates = candidates[:limit]
    return candidates

SMART_REGION_MAP = {
    r"(?i)(美国|美|States|America|\bUS\b|\bUSA\b|洛杉矶|硅谷|西雅图|芝加哥|纽约|达拉斯|圣何塞|凤凰城|波特兰|LAX|SJC|SEA|ORD|JFK|DFW|PHX)": "🇺🇸 美国",
    r"(?i)(香港|港|HongKong|Hong Kong|\bHK\b|\bHKG\b)": "🇭🇰 香港",
    r"(?i)(日本|日|Japan|\bJP\b|\bJPN\b|东京|大阪|TYO|OSA)": "🇯🇵 日本",
    r"(?i)(新加坡|新|Singapore|\bSG\b|\bSGP\b|狮城|SIN)": "🇸🇬 新加坡",
    r"(?i)(台湾|台|Taiwan|\bTW\b|\bTWN\b|台北|TPE)": "🇹🇼 台湾",
    r"(?i)(韩国|韩|Korea|\bKR\b|\bKOR\b|首尔|ICN|SEL)": "🇰🇷 韩国",
    r"(?i)(英国|英|United Kingdom|\bUK\b|\bGB\b|伦敦|LHR|LON)": "🇬🇧 英国",
    r"(?i)(德国|德|Germany|\bDE\b|\bDEU\b|法兰克福|FRA)": "🇩🇪 德国",
    r"(?i)(法国|法|France|\bFR\b|\bFRA\b|巴黎|CDG)": "🇫🇷 法国",
    r"(?i)(俄罗斯|俄|Russia|\bRU\b|\bRUS\b|莫斯科|SVO)": "🇷🇺 俄罗斯",
    r"(?i)(加拿大|加|Canada|\bCA\b|\bCAN\b|温哥华|多伦多|YVR|YYZ)": "🇨🇦 加拿大",
    r"(?i)(澳大利亚|澳洲|澳|Australia|\bAU\b|\bAUS\b|悉尼|墨尔本|SYD|MEL)": "🇦🇺 澳大利亚",
    r"(?i)(印度|印|India|\bIN\b|\bIND\b|孟买|BOM)": "🇮🇳 印度",
    r"(?i)(荷兰|荷|Netherlands|\bNL\b|\bNLD\b|阿姆斯特丹|AMS)": "🇳🇱 荷兰",
    r"(?i)(土耳其|土|Turkey|\bTR\b|\bTUR\b|伊斯坦布尔|IST)": "🇹🇷 土耳其",
    r"(?i)(巴西|巴|Brazil|\bBR\b|\bBRA\b|圣保罗|GRU)": "🇧🇷 巴西",
    r"(?i)(阿根廷|Argentina|\bAR\b|\bARG\b)": "🇦🇷 阿根廷",
    r"(?i)(越南|Vietnam|\bVN\b|\bVNM\b|河内|胡志明|SGN|HAN)": "🇻🇳 越南",
    r"(?i)(泰国|泰|Thailand|\bTH\b|\bTHA\b|曼谷|BKK)": "🇹🇭 泰国",
    r"(?i)(菲律宾|Philippines|\bPH\b|\bPHL\b|马尼拉|MNL)": "🇵🇭 菲律宾",
    r"(?i)(马来西亚|大马|Malaysia|\bMY\b|\bMYS\b|吉隆坡|KUL)": "🇲🇾 马来西亚",
    r"(?i)(芬兰|芬蘭|Finland|\bFI\b|\bFIN\b|赫尔辛基|HEL)": "🇫🇮 芬兰",
    r"(?i)(印度尼西亚|印尼|Indonesia|\bID\b|\bIDN\b|雅加达|CGK)": "🇮🇩 印尼",
}

# 匹配 Unicode 国旗 Emoji（区域指示符号对）
FLAG_EMOJI_REGEX = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')

def detect_country_info(text=""):
    """智能识别文本中的国家名与国旗 Emoji，如 ('美国', '🇺🇸')"""
    if not text: return "其他", "🌐"
    text = str(text)
    m = FLAG_EMOJI_REGEX.search(text)
    if m:
        flag = m.group(0)
        for _, val in SMART_REGION_MAP.items():
            parts = val.split(' ')
            if parts[0] == flag:
                return parts[1] if len(parts) > 1 else "其他", flag
    for p, val in SMART_REGION_MAP.items():
        if re.search(p, text):
            parts = val.split(' ')
            flag = parts[0]
            name = parts[1] if len(parts) > 1 else "其他"
            return name, flag
    return "其他", "🌐"

def get_node_flag(name="", tag="", server=""):
    """从节点名称、分组标签或服务器地址智能识别国旗 Emoji"""
    m = FLAG_EMOJI_REGEX.search(name or "")
    if m:
        return m.group(0)
    
    combined = f"{name or ''} {tag or ''} {server or ''}"
    for p, f in SMART_REGION_MAP.items():
        if re.search(p, combined):
            return f.split(' ')[0]
            
    if server:
        ip = DOMAIN_CACHE.get(server, server)
        flag = get_flag(ip)
        if flag and FLAG_EMOJI_REGEX.search(flag):
            return flag
            
    return ""

def ensure_node_flag(name_str, tag="", server=""):
    """保证节点名称最前面带有国旗 Emoji，若已有则不重复添加"""
    if not name_str:
        name_str = "Node"
    if FLAG_EMOJI_REGEX.search(name_str):
        return name_str
    flag = get_node_flag(name_str, tag, server)
    if flag:
        return f"{flag} {name_str}"
    return name_str

def safe_b64decode(s):
    if not s: return b""
    s = s.strip().replace('-', '+').replace('_', '/')
    return base64.b64decode(s + '=' * (-len(s) % 4))

def parse_ports_spec(spec: str):
    """Parse port range list like '443', '5000-6000', '443,5000-6000', '443/5000-6000' into ['443','5000-6000']"""
    if not spec:
        return []
    spec = str(spec).strip()
    if not spec:
        return []
    # mihomo uses '/' as separator for multi ranges; also accept ',' and ';'
    spec = spec.replace("/", ",").replace(";", ",")
    parts = [p.strip() for p in spec.split(",") if p.strip()]
    return parts

def join_ports_spec(parts):
    parts = [str(p).strip() for p in (parts or []) if str(p).strip()]
    return ",".join(parts)

async def resolve_domain_to_ip(domain):
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain): return domain
    if domain in DOMAIN_CACHE: return DOMAIN_CACHE[domain]
    if not aiohttp: return None
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(f"https://dns.google/resolve?name={domain}&type=A", timeout=3) as r:
                js = await r.json(); ip = js['Answer'][0]['data']; DOMAIN_CACHE[domain] = ip; return ip
    except: pass
    return None

def get_flag(ip):
    if not geoip2 or not os.path.exists(GEOIP_DB): return ""
    try:
        iso = geoip2.database.Reader(GEOIP_DB).country(ip).country.iso_code
        flags = {"US":"🇺🇸","HK":"🇭🇰","JP":"🇯🇵","SG":"🇸🇬","TW":"🇹🇼","KR":"🇰🇷","CN":"🇨🇳","GB":"🇬🇧","DE":"🇩🇪","FR":"🇫🇷","RU":"🇷🇺","CA":"🇨🇦","AU":"🇦🇺"}
        return flags.get(iso, iso)
    except: return ""

async def smart_identify_region(node, tag):
    name = node.get('name', '')
    server = node.get('server', '')
    flag = get_node_flag(name, tag, server)
    if not flag:
        try:
            ip = await resolve_domain_to_ip(server)
            if ip:
                geo_flag = get_flag(ip)
                if geo_flag and FLAG_EMOJI_REGEX.search(geo_flag):
                    flag = geo_flag
        except:
            pass
            
    base_name = name or tag or "Node"
    if FLAG_EMOJI_REGEX.search(base_name):
        return base_name
    if flag:
        return f"{flag} {base_name}"
    return base_name

def format_bytes_smart(bytes_val):
    if bytes_val is None or bytes_val < 0: return ""
    gb = bytes_val / 1073741824.0
    if gb >= 1024:
        tb = gb / 1024.0
        return f"{tb:.1f}TB".replace('.0TB', 'TB')
    elif gb >= 1:
        return f"{gb:.1f}GB".replace('.0GB', 'GB')
    else:
        mb = bytes_val / 1048576.0
        return f"{mb:.1f}MB".replace('.0MB', 'MB')

app.jinja_env.globals.update(detect_country_info=detect_country_info, format_bytes_smart=format_bytes_smart)

def is_fake_traffic(u, d, t, e):
    # 24TB dummy total (26388279066624 or 24576 * 1024^3) from subconverter
    if t == 26388279066624 or t == 24576 * 1073741824:
        return True
    now_ts = time.time()
    # Expire date is year 2100 (4102444800) or > 3000 days into the future with >= 10TB total
    if e >= 4102444800 or (e > now_ts and (e - now_ts) > 86400 * 3000):
        if t >= 10 * 1024 * 1073741824:
            return True
    return False

def parse_traffic_info(header_str, custom_total_gb=0):
    if not header_str: return None
    try:
        info = dict(re.findall(r'(\w+)=(\d+)', header_str))
        if not info: return None
        u = int(info.get('upload', 0))
        d = int(info.get('download', 0))
        t = int(info.get('total', 0))
        e = int(info.get('expire', 0))

        fake = is_fake_traffic(u, d, t, e)
        used_bytes = u + d

        if custom_total_gb > 0:
            real_t = int(custom_total_gb * 1073741824)
        elif fake:
            # 过滤 24TB 虚假占位数据，仅真实机场订阅显示总配额
            real_t = 0
        else:
            real_t = t

        # 如果为 subconverter 虚假占位数据，且用户未配置自定义 VPS 总配额，则不显示任何虚假流量胶囊
        if fake and custom_total_gb <= 0:
            return None

        exp_str = ""
        now = time.time()
        if e > 0 and not fake:
            diff_days = int((e - now) / 86400)
            if 0 < diff_days <= 1500:
                exp_str = f"剩{diff_days}天"
            elif diff_days > 1500 or e >= 4102444800:
                exp_str = "长期有效"
            elif diff_days <= 0:
                exp_str = "已过期"

        pct = 0
        if real_t > 0:
            pct = min(100, int((used_bytes / real_t) * 100))

        return {
            "used": format_bytes_smart(used_bytes),
            "used_bytes": used_bytes,
            "total": format_bytes_smart(real_t) if real_t > 0 else "",
            "total_bytes": real_t,
            "percent": pct,
            "has_total": real_t > 0,
            "expire": exp_str,
            "color": "#dc3545" if pct >= 90 else ("#f59e0b" if pct >= 75 else "#10b981")
        }
    except:
        return None

def bytes_to_gb_smart(b):
    """将字节数转换为人性化 GB 数（支持二进制 GiB 与十进制 GB 智能对齐，如 1000GB / 10000GB）"""
    if not b or b <= 0: return 0
    gib = b / (1024**3)
    gb = b / (1000**3)
    if abs(gib - round(gib)) < 0.05: return int(round(gib))
    if abs(gb - round(gb)) < 0.05: return int(round(gb))
    val = round(gib, 2)
    return int(val) if val.is_integer() else val

async def fetch_komari_stats(session, komari_url, api_key=""):
    """抓取 Komari 探针 (1.5+) 节点的实时进出网卡流量及总流量配额"""
    if not komari_url or not aiohttp: return {}
    komari_url = komari_url.strip().rstrip('/')
    if not komari_url.startswith('http'):
        komari_url = f"https://{komari_url}"
        
    headers = {'User-Agent': 'Mozilla/5.0'}
    if api_key:
        headers['Authorization'] = f"Bearer {api_key.strip()}"

    servers_map = {}
    
    # 方式 1：优先使用 Komari JSON-RPC (/api/rpc2) 单次批量拉取所有节点及最新状态
    try:
        rpc_url = f"{komari_url}/api/rpc2"
        node_info_map = {}
        # 1.1 获取节点列表（提取 UUID、节点名称 Name 与 traffic_limit 总流量限制）
        nodes_req = {"jsonrpc": "2.0", "method": "common:getNodes", "params": {}, "id": 1}
        async with session.post(rpc_url, json=nodes_req, headers=headers, timeout=aiohttp.ClientTimeout(total=15), ssl=False) as r:
            if r.status == 200:
                res = await r.json()
                data = res.get('result') or {}
                if isinstance(data, dict):
                    for uid, c in data.items():
                        if isinstance(c, dict):
                            lval = c.get('traffic_limit') or c.get('trafficLimit') or c.get('limit') or 0
                            try: lval = int(lval)
                            except: lval = 0
                            node_info_map[str(uid).lower()] = {
                                "name": str(c.get('name', '')).strip(),
                                "traffic_limit": lval
                            }
                elif isinstance(data, list):
                    for c in data:
                        if isinstance(c, dict) and c.get('uuid'):
                            lval = c.get('traffic_limit') or c.get('trafficLimit') or c.get('limit') or 0
                            try: lval = int(lval)
                            except: lval = 0
                            node_info_map[str(c['uuid']).lower()] = {
                                "name": str(c.get('name', '')).strip(),
                                "traffic_limit": lval
                            }

        # 1.2 获取节点最新流量状态（提取 net_total_up 与 net_total_down）
        status_req = {"jsonrpc": "2.0", "method": "common:getNodesLatestStatus", "params": {}, "id": 2}
        async with session.post(rpc_url, json=status_req, headers=headers, timeout=aiohttp.ClientTimeout(total=15), ssl=False) as r:
            if r.status == 200:
                res = await r.json()
                stat_data = res.get('result') or {}
                if isinstance(stat_data, dict):
                    for uid, s in stat_data.items():
                        if isinstance(s, dict):
                            up = int(s.get('net_total_up') or 0)
                            down = int(s.get('net_total_down') or 0)
                            used = up + down
                            uid_str = str(uid).lower()
                            n_info = node_info_map.get(uid_str, {})
                            name = n_info.get('name', '')
                            limit = n_info.get('traffic_limit', 0)
                            limit_gb = bytes_to_gb_smart(limit)
                            
                            entry = {
                                "uuid": uid_str,
                                "name": name,
                                "used": used,
                                "up": up,
                                "down": down,
                                "limit": limit,
                                "limit_gb": limit_gb
                            }
                            # 同时通过 UUID 和 节点名称 Name 建立双向索引，用户填哪一个都能匹配！
                            servers_map[uid_str] = entry
                            if name:
                                servers_map[name.lower()] = entry
    except Exception as e:
        write_log(f"Komari RPC fetch error: {e}")

    # 方式 2：REST API 兜底 (/api/nodes 与 /api/recent/:uuid)
    if not servers_map:
        try:
            nodes_url = f"{komari_url}/api/nodes"
            async with session.get(nodes_url, headers=headers, timeout=aiohttp.ClientTimeout(total=15), ssl=False) as r:
                if r.status == 200:
                    data = await r.json()
                    nodes_list = data.get('data') or []
                    if isinstance(nodes_list, list):
                        for c in nodes_list:
                            if not isinstance(c, dict): continue
                            uid = str(c.get('uuid') or '').strip()
                            name = str(c.get('name') or '').strip()
                            lval = c.get('traffic_limit') or c.get('trafficLimit') or c.get('limit') or 0
                            try: lval = int(lval)
                            except: lval = 0
                            limit_gb = bytes_to_gb_smart(lval)
                            if not uid: continue
                            
                            used = 0
                            try:
                                recent_url = f"{komari_url}/api/recent/{uid}"
                                async with session.get(recent_url, headers=headers, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as rr:
                                    if rr.status == 200:
                                        r_data = await rr.json()
                                        recs = r_data.get('data') or []
                                        if recs and isinstance(recs, list) and isinstance(recs[-1], dict):
                                            last_rec = recs[-1]
                                            used = int(last_rec.get('net_total_up') or 0) + int(last_rec.get('net_total_down') or 0)
                            except: pass
                            
                            entry = {"uuid": uid.lower(), "name": name, "used": used, "limit": lval, "limit_gb": limit_gb}
                            servers_map[uid.lower()] = entry
                            if name:
                                servers_map[name.lower()] = entry
        except Exception as e:
            write_log(f"Komari REST fetch error: {e}")

    return servers_map

async def fetch_nezha_stats(session, nezha_url, nezha_token=""):
    if not nezha_url or not aiohttp: return {}
    nezha_url = nezha_url.strip().rstrip('/')
    if not nezha_url.startswith('http'):
        nezha_url = f"https://{nezha_url}"
    headers = {'User-Agent': 'Mozilla/5.0'}
    if nezha_token:
        headers['Authorization'] = nezha_token.strip()

    endpoints = [
        f"{nezha_url}/api/v1/server/details",
        f"{nezha_url}/api/v1/server/list"
    ]
    
    servers_map = {}
    for ep in endpoints:
        try:
            async with session.get(ep, headers=headers, timeout=aiohttp.ClientTimeout(total=15), ssl=False) as r:
                if r.status == 200:
                    data = await r.json()
                    raw_list = []
                    if isinstance(data, dict):
                        raw_list = data.get('data') or data.get('result') or []
                    elif isinstance(data, list):
                        raw_list = data
                        
                    for s in raw_list:
                        if not isinstance(s, dict): continue
                        sid = str(s.get('id', ''))
                        name = str(s.get('name', ''))
                        status_obj = s.get('status') or {}
                        
                        net_in = int(status_obj.get('NetInTransfer') or s.get('net_in_transfer') or 0)
                        net_out = int(status_obj.get('NetOutTransfer') or s.get('net_out_transfer') or 0)
                        total_transfer = net_in + net_out
                        
                        entry = {
                            "id": sid,
                            "uuid": sid,
                            "name": name,
                            "in": net_in,
                            "out": net_out,
                            "used": total_transfer
                        }
                        servers_map[sid] = entry
                        if name:
                            servers_map[name.lower()] = entry
                    if servers_map:
                        break
        except Exception:
            pass
    return servers_map

# 中文数字与探针规整化字典
CN_NUMS_MAP = {
    '零': '0', '一': '1', '二': '2', '两': '2', '三': '3', '四': '4',
    '五': '5', '六': '6', '七': '7', '八': '8', '九': '9', '十': '10'
}

PROBE_STRIP_SUFFIXES = [
    '本机', '优选', '中转', '直连', '备用', '节点', '专线', '测试', '自建', '落地',
    '电信', '联通', '移动', 'bgp', 'gia', 'cmi', 'ipv4', 'ipv6', 'v4', 'v6',
    'argo', 'cf', 'tunnel', '隧道', 'tg', 'bot'
]

PROBE_SPEC_PATTERNS = [
    r'\d+c\d+g', r'\d+c', r'\d+g', '玩具', '家宽', '无限流量', '优化', '原生', '动态', '静态'
]

PROBE_COUNTRIES = ['美国', '香港', '日本', '新加坡', '德国', '英国', '韩国', '台湾', '荷兰', '法国', '加拿大', '澳大利亚', '俄罗斯', '芬兰']

def clean_probe_text(s):
    """规整化探针节点匹配文本：去除Emoji、特殊字符与空格并转小写"""
    if not s: return ""
    s = re.sub(r'[\U0001F1E6-\U0001F1FF]{2}', '', str(s))
    s = re.sub(r'[\U0001F300-\U0001FAFF]', '', s)
    s = re.sub(r'[\u2600-\u27BF]', '', s)
    s = s.lower().strip()
    for cn, num in CN_NUMS_MAP.items():
        s = s.replace(cn, num)
    s = re.sub(r'([a-z]+)o(\d+)', r'\g<1>0\2', s)
    s = re.sub(r'(\d+)o([a-z]+)', r'\g<1>0\2', s)
    return re.sub(r'[\s\-_\.:\/\[\]\(\)\{\}\*#@!+=~`|\^]+', '', s)

def extract_probe_core_features(s):
    """提取核心名称特征（去除本机/优选后缀、去除配置规格标识符）"""
    norm = clean_probe_text(s)
    if not norm: return "", ""
    
    # 剥离尾部节点功能词（如 本机、优选 等）
    changed = True
    while changed:
        changed = False
        for suf in PROBE_STRIP_SUFFIXES:
            if norm.endswith(suf) and len(norm) > len(suf) + 1:
                norm = norm[:-len(suf)]
                changed = True
                
    # 剥离 VPS 规格词（如 8c8g, 玩具, 家宽 等）
    core = norm
    for sp in PROBE_SPEC_PATTERNS:
        core = re.sub(sp, '', core)
    core = re.sub(r'[\s\-_\.:]+', '', core)
    
    return norm, core if len(core) >= 2 else norm

def check_probe_prefix_conflict(s1, s2):
    """防止跨商家误匹配：若包含相同国家词，但国家词前的商家品牌相似度极低，则判定冲突"""
    for c in PROBE_COUNTRIES:
        if c in s1 and c in s2:
            p1 = s1.split(c)[0]
            p2 = s2.split(c)[0]
            if p1 and p2 and p1 != p2:
                import difflib
                sim_p = difflib.SequenceMatcher(None, p1, p2).ratio()
                if sim_p < 0.6:
                    return True # 商家冲突
    return False

GENERIC_IGNORE_WORDS = {
    'vless', 'vmess', 'trojan', 'ss', 'shadowsocks', 'hy2', 'hysteria', 'tuic', 
    'argo', 'link', 'sub', 'node', '节点', 'proxy', '本机', '优选', '直连',
    'none', '__none__', 'off', 'disable', 'disabled'
}

def is_generic_or_spec_only(s):
    """过滤无辨识度的候选词（如纯数字ID、配置规格4c8g、通用协议词、不匹配标记等）"""
    if not s: return True
    s = str(s).strip().lower()
    if s in GENERIC_IGNORE_WORDS: return True
    if s.isdigit(): return True
    if re.match(r'^\d+c\d*g*$', s): return True
    return False

def score_probe_match(candidate, probe_entry, is_explicit_id=False):
    """
    计算候选字符串与探针节点的容错匹配度得分 (0.0 ~ 1.0)
    支持：
    1. 自动剥离 [本机]、[优选]、[直连] 等功能后缀
    2. 中文数字自动转换为阿拉伯数字（如 '三区' 匹配 '3区'）
    3. 忽略大小写、国旗Emoji、空格标点符号
    4. 字母O与数字0自动容错（如 'RNO2' 匹配 'RN02'）
    5. 核心品牌地域提取（如 '无聊云德国玩具' 匹配 '无聊云德国8C8G'）
    6. 智能品牌前缀防串防误匹配
    """
    if not candidate or not probe_entry: return 0.0
    cand_raw = str(candidate).strip()
    cand_lower = cand_raw.lower()
    
    if cand_lower in ('__none__', 'none', 'off', 'disable', 'disabled'): return 0.0
    if not is_explicit_id and is_generic_or_spec_only(cand_lower): return 0.0
    
    node_name = str(probe_entry.get('name', '')).strip()
    node_uuid = str(probe_entry.get('uuid', '')).strip().lower()
    node_id = str(probe_entry.get('id', '')).strip().lower()
    
    # 1. 绝对精确匹配 (UUID 或 ID)
    if node_uuid and cand_lower == node_uuid: return 1.0
    if node_id and cand_lower == node_id:
        if is_explicit_id or len(node_id) >= 8: return 1.0
    if node_name and cand_raw == node_name: return 1.0
    if node_name and cand_lower == node_name.lower(): return 0.98
        
    c_norm, c_core = extract_probe_core_features(cand_raw)
    n_norm, n_core = extract_probe_core_features(node_name)
    
    if not c_norm or not n_norm: return 0.0
    
    # 品牌商家冲突检查（避免因同为'美国'而将 'rn02美国' 误匹配至 'dr美国'）
    if check_probe_prefix_conflict(c_norm, n_norm):
        return 0.0
        
    # 2. 剥离本机/优选后缀与规整后完全相等
    if c_norm == n_norm:
        return 0.96
        
    # 3. 核心词完全相等（核心品牌+国家一致，如 无聊云德国玩具 vs 无聊云德国8C8G）
    if c_core and n_core and c_core == n_core and len(c_core) >= 3:
        return 0.93
        
    # 4. 子串包含关系 (例如 "无聊云新加坡玩具" in "无聊云新加坡玩具本机")
    if c_norm in n_norm or n_norm in c_norm:
        shorter = min(len(c_norm), len(n_norm))
        longer = max(len(c_norm), len(n_norm))
        if shorter >= 3:
            return 0.75 + 0.20 * (shorter / longer)
            
    # 5. 核心词包含关系
    if c_core and n_core and (c_core in n_core or n_core in c_core):
        shorter = min(len(c_core), len(n_core))
        longer = max(len(c_core), len(n_core))
        if shorter >= 3:
            return 0.70 + 0.20 * (shorter / longer)
            
    # 6. 字符序列相似度容错 (difflib SequenceMatcher)
    import difflib
    sim1 = difflib.SequenceMatcher(None, c_norm, n_norm).ratio()
    sim2 = difflib.SequenceMatcher(None, c_core, n_core).ratio() if c_core and n_core else 0
    sim = max(sim1, sim2)
    if sim >= 0.75:
        return 0.60 + 0.35 * sim
        
    return 0.0

def find_best_probe_node(candidates, probe_servers, min_threshold=0.78, is_explicit_id=False):
    """
    在一组候选文本（用户指定ID、订阅分组名、节点名等）中，
    对所有探针节点计算容错匹配度，返回最佳匹配的探针节点 entry, 得分, 以及命中的候选词
    """
    if not candidates or not probe_servers: return None, 0.0, ""
    
    unique_nodes = []
    seen_keys = set()
    for k, v in probe_servers.items():
        if isinstance(v, dict):
            ukey = v.get('uuid') or v.get('id') or v.get('name')
            if ukey and ukey not in seen_keys:
                seen_keys.add(ukey)
                unique_nodes.append(v)
                
    best_entry = None
    best_score = 0.0
    matched_cand = ""
    
    for cand in candidates:
        if not cand or not str(cand).strip(): continue
        cand_str = str(cand).strip()
        if not is_explicit_id and is_generic_or_spec_only(cand_str): continue
        for entry in unique_nodes:
            score = score_probe_match(cand_str, entry, is_explicit_id=is_explicit_id)
            if score > best_score:
                best_score = score
                best_entry = entry
                matched_cand = cand_str
                
    if best_score >= min_threshold:
        return best_entry, best_score, matched_cand
    return None, 0.0, ""

async def fetch_single_url(session, url, timeout):
    try:
        async with session.get(url, timeout=timeout, ssl=False) as r:
            if r.status == 200:
                text = await r.text()
                info = parse_traffic_info(r.headers.get('Subscription-Userinfo', ''))
                return text or "", info
    except: pass
    return "", None
def clash_to_internal(p):
    if not isinstance(p, dict):
        return None
    t = str(p.get('type', '')).lower()
    name = str(p.get('name', ''))
    server = str(p.get('server', ''))
    try: port = int(p.get('port', 443))
    except: port = 443
    node = {
        'type': t,
        'name': name,
        'server': server,
        'port': port
    }
    if p.get('tls'): node['tls'] = True
    if p.get('servername') or p.get('sni'):
        node['sni'] = p.get('servername') or p.get('sni')
    if p.get('skip-cert-verify'): node['skip-cert-verify'] = True
    if p.get('alpn'): node['alpn'] = p.get('alpn')
    if p.get('client-fingerprint') or p.get('fp'):
        node['fp'] = p.get('client-fingerprint') or p.get('fp')
        
    if t in ['vless', 'vmess']:
        node['uuid'] = p.get('uuid', '')
        if t == 'vmess':
            node['alterId'] = int(p.get('alterId', 0))
            node['cipher'] = p.get('cipher', 'auto')
        if t == 'vless' and p.get('flow'):
            node['flow'] = p.get('flow')
        ropts = p.get('reality-opts') or {}
        if ropts or p.get('reality'):
            node['reality'] = True
            node['pbk'] = ropts.get('public-key', '') or p.get('pbk', '')
            node['sid'] = ropts.get('short-id', '') or p.get('sid', '')
            
    elif t == 'trojan':
        node['password'] = p.get('password', '')
        
    elif t in ['hysteria2', 'hy2']:
        node['type'] = 'hysteria2'
        node['password'] = p.get('password', '') or p.get('auth', '')
        if p.get('obfs'):
            node['obfs'] = p.get('obfs')
            node['obfs_password'] = p.get('obfs-password') or p.get('obfs_password', '')
        if p.get('ports'):
            node['ports'] = str(p.get('ports'))
        if p.get('mport'):
            node['ports'] = str(p.get('mport'))
        if p.get('up'): node['up_mbps'] = p.get('up')
        if p.get('down'): node['down_mbps'] = p.get('down')
        
    elif t == 'tuic':
        node['uuid'] = p.get('uuid', '')
        node['password'] = p.get('password', '')
        node['congestion_control'] = p.get('congestion-controller') or p.get('congestion_control', 'bbr')
        node['udp_relay_mode'] = p.get('udp-relay-mode') or p.get('udp_relay_mode', 'native')
        
    elif t == 'ss':
        node['cipher'] = p.get('cipher', '')
        node['password'] = p.get('password', '')
        if p.get('plugin'):
            node['plugin'] = p.get('plugin')
            node['plugin_opts'] = p.get('plugin-opts', {})

    elif t in ['wireguard', 'awg']:
        node['type'] = 'wireguard'
        node['ip'] = p.get('ip', '10.8.0.2')
        node['public-key'] = (p.get('public-key', '') or '').strip().replace(' ', '+')
        node['private-key'] = (p.get('private-key', '') or '').strip().replace(' ', '+')
        if p.get('preshared-key'):
            node['psk'] = (p.get('preshared-key') or '').strip().replace(' ', '+')
        awg_opt = p.get('amnezia-wg-option') or {}
        for k in ['jc', 'jmin', 'jmax', 's1', 's2', 'h1', 'h2', 'h3', 'h4']:
            if k in awg_opt:
                node[k] = awg_opt[k]
            elif k in p:
                node[k] = p[k]
            
    net = p.get('network', 'tcp')
    node['network'] = net
    if net == 'ws' or p.get('ws-opts'):
        node['network'] = 'ws'
        ws_opts = p.get('ws-opts', {})
        node['ws-path'] = ws_opts.get('path', '/')
        headers = ws_opts.get('headers', {})
        if 'Host' in headers or 'host' in headers:
            node['ws-host'] = headers.get('Host') or headers.get('host')
    elif net == 'grpc' or p.get('grpc-opts'):
        node['network'] = 'grpc'
        grpc_opts = p.get('grpc-opts', {})
        node['grpc-name'] = grpc_opts.get('grpc-service-name', '')
    elif net in ['xhttp', 'splithttp'] or p.get('xhttp-opts') or p.get('splithttp-opts'):
        node['network'] = 'xhttp'
        x_opts = p.get('xhttp-opts') or p.get('splithttp-opts') or {}
        node['xhttp-path'] = x_opts.get('path', '/')
        node['xhttp-host'] = x_opts.get('host', '') or p.get('servername', '')
        node['xhttp-mode'] = x_opts.get('mode', 'packet-up')
        node['alpn'] = p.get('alpn') or ['h3']
        
    return node

def decode_sub_content(content):
    content = content.strip()
    if ('\n' not in content and '\r' not in content) and any(content.startswith(p) for p in ['vless://', 'vmess://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://', 'tuic://', 'anytls://', 'shadowtls://', 'stls://', 'naive+https://', 'naive+quic://', 'naive://', 'awg://', 'wireguard://']):
        return parse_uri_list([content])
    try:
        if yaml and ("proxies:" in content or "Proxy:" in content):
            try: return [n for n in (clash_to_internal(p) for p in (yaml.safe_load(content).get('proxies') or [])) if n]
            except: pass
        try: return parse_uri_list(base64.b64decode(content + '='*(-len(content)%4)).decode('utf-8', 'ignore').splitlines())
        except: return parse_uri_list(content.splitlines())
    except: return []

def parse_uri_list(lines): return [n for n in (parse_uri(l.strip()) for l in lines) if n]

def parse_uri(uri):
    if not uri:
        return None
    try:
        uri = uri.strip()
        if uri.startswith(('awg://', 'wireguard://')):
            try:
                raw = uri
                scheme, rest = raw.split('://', 1)
                fragment = ''
                if '#' in rest:
                    rest, fragment = rest.split('#', 1)
                    remark = urllib.parse.unquote(fragment)
                else:
                    remark = 'AmneziaWG'

                query_dict = {}
                if '?' in rest:
                    rest, qstr = rest.split('?', 1)
                    for part in qstr.split('&'):
                        if not part: continue
                        if '=' in part:
                            k, v = part.split('=', 1)
                            query_dict[k.lower()] = urllib.parse.unquote(v).strip().replace(' ', '+')
                        else:
                            query_dict[part.lower()] = ''

                client_pri = ''
                if '@' in rest:
                    client_pri, rest = rest.rsplit('@', 1)
                    client_pri = urllib.parse.unquote(client_pri).strip().replace(' ', '+')

                server_host, port_str = split_host_port(rest, 51820)
                try: port_val = int(port_str) if port_str else 51820
                except: port_val = 51820

                pub_key = (query_dict.get('publickey') or query_dict.get('public-key') or query_dict.get('pubkey') or '').strip().replace(' ', '+')
                psk_key = (query_dict.get('psk') or query_dict.get('preshared-key') or '').strip().replace(' ', '+')
                ip_val = (query_dict.get('address') or query_dict.get('ip') or '10.8.0.2').split('/')[0].strip()

                def safe_int(v, default):
                    try: return int(v)
                    except: return default

                return {
                    'type': 'wireguard',
                    'name': remark or 'AmneziaWG',
                    'server': server_host,
                    'port': port_val,
                    'uuid': None,
                    'password': None,
                    'private-key': client_pri,
                    'public-key': pub_key,
                    'ip': ip_val,
                    'psk': psk_key,
                    'jc': safe_int(query_dict.get('jc'), 4),
                    'jmin': safe_int(query_dict.get('jmin'), 50),
                    'jmax': safe_int(query_dict.get('jmax'), 1000),
                    's1': safe_int(query_dict.get('s1'), 15),
                    's2': safe_int(query_dict.get('s2'), 20),
                    'h1': safe_int(query_dict.get('h1'), 1),
                    'h2': safe_int(query_dict.get('h2'), 2),
                    'h3': safe_int(query_dict.get('h3'), 3),
                    'h4': safe_int(query_dict.get('h4'), 4),
                    'udp': True
                }
            except:
                pass

        p = urllib.parse.urlparse(uri)
        q = urllib.parse.parse_qs(p.query)

        # Base (do NOT eagerly access p.port for schemes that may carry multi-port)
        name = urllib.parse.unquote(p.fragment or "")
        server = p.hostname
        try:
            base_port = p.port
        except:
            base_port = None
        b = {
            "name": name,
            "server": server,
            "port": base_port,
            "uuid": p.username,
            "password": p.password
        }

        if p.scheme == "vless":
            b.update({
                'type': 'vless',
                'network': q.get('type', ['tcp'])[0],
                'tls': q.get('security', [''])[0] in ['tls', 'reality'],
                'reality': q.get('security', [''])[0] == 'reality',
                'flow': q.get('flow', [''])[0],
                'sni': q.get('sni', [''])[0] or q.get('host', [''])[0],
                'headerType': q.get('headerType', ['none'])[0],
            })
            if b['reality']:
                b.update({
                    'pbk': q.get('pbk', [''])[0],
                    'sid': q.get('sid', [''])[0],
                    'fp': q.get('fp', ['chrome'])[0],
                })
            is_insecure = (
                q.get('insecure', ['0'])[0] in ['1', 'true', 'True'] or
                q.get('allowInsecure', ['0'])[0] in ['1', 'true', 'True'] or
                q.get('allow_insecure', ['0'])[0] in ['1', 'true', 'True'] or
                q.get('skip-cert-verify', ['0'])[0] in ['1', 'true', 'True']
            )
            server_host = str(server or '')
            is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", server_host) or server_host.startswith('[') or ':' in server_host)
            if is_insecure or (is_ip and not b.get('reality') and b.get('sni')):
                b['skip-cert-verify'] = True
            if q.get('fp'):
                b['fp'] = q.get('fp')[0]
            if b['network'] == 'ws':
                b.update({'ws-path': q.get('path', ['/'])[0], 'ws-host': q.get('host', [''])[0]})
            elif b['network'] == 'grpc':
                b['grpc-name'] = q.get('serviceName', [''])[0]
            elif b['network'] in ['xhttp', 'splithttp']:
                b['network'] = 'xhttp'
                b.update({
                    'xhttp-path': q.get('path', ['/'])[0],
                    'xhttp-host': q.get('host', [''])[0] or q.get('sni', [''])[0],
                    'xhttp-mode': q.get('mode', ['auto'])[0],
                    'alpn': q.get('alpn', [''])[0].split(',') if q.get('alpn') else []
                })
            return b

        elif p.scheme == "vmess":
            j = json.loads(base64.b64decode(uri[8:] + '=' * (-len(uri[8:]) % 4)).decode('utf-8', 'ignore'))
            b.update({
                'type': 'vmess',
                'name': j.get('ps'),
                'server': j.get('add'),
                'port': int(j.get('port')),
                'uuid': j.get('id'),
                'alterId': int(j.get('aid', 0)),
                'network': j.get('net', 'tcp'),
                'tls': j.get('tls') == 'tls',
                'sni': j.get('sni') or j.get('host')
            })
            if b['network'] == 'ws':
                b.update({'ws-path': j.get('path', '/'), 'ws-host': j.get('host', '')})
            elif b['network'] == 'grpc':
                b['grpc-name'] = j.get('path', '')
            return b

        elif p.scheme in ["trojan", "trojan-go"]:
            b.update({
                'type': 'trojan',
                'password': p.username,
                'sni': q.get('sni', [''])[0],
                'skip-cert-verify': q.get('allowInsecure', ['0'])[0] == '1',
                'udp': True
            })
            b['network'] = q.get('type', ['tcp'])[0]
            if b['network'] == 'ws':
                b.update({'ws-path': q.get('path', ['/'])[0], 'ws-host': q.get('host', [''])[0]})
            elif b['network'] == 'grpc':
                b['grpc-name'] = q.get('serviceName', [''])[0]
            if q.get('alpn'):
                b['alpn'] = q.get('alpn', [''])[0].split(',')
            return b

        elif p.scheme == "ss":
            try:
                raw = uri.replace("ss://", "").split("#")[0]
                plugin_info = {}
                if "?" in raw:
                    raw, query = raw.split("?", 1)
                    q_params = urllib.parse.parse_qs(query)
                    if 'plugin' in q_params:
                        plugin_str = urllib.parse.unquote(q_params['plugin'][0])
                        parts = plugin_str.split(';')
                        plugin_info['name'] = parts[0]
                        plugin_info['opts'] = {}
                        for opt in parts[1:]:
                            if "=" in opt:
                                k, v = opt.split("=", 1)
                                plugin_info['opts'][k] = v
                            else:
                                plugin_info['opts'][opt] = True

                def _split_host_port(hp: str):
                    hp = (hp or "").strip()
                    # IPv6 bracket form: [::1]:443
                    if hp.startswith('[') and ']' in hp:
                        host = hp[1:hp.find(']')]
                        rest = hp[hp.find(']')+1:]
                        if rest.startswith(':'):
                            return host, rest[1:]
                        return host, ""
                    # If it looks like IPv6 without brackets, assume last ':' splits port
                    if hp.count(':') > 1:
                        host, port = hp.rsplit(':', 1)
                        return host, port
                    # IPv4 / domain
                    if ':' in hp:
                        host, port = hp.split(':', 1)
                        return host, port
                    return hp, ""

                if "@" in raw:
                    user_part, host_part = raw.rsplit("@", 1)
                    host, port = _split_host_port(host_part)
                    try:
                        userinfo = safe_b64decode(user_part).decode()
                        method, password = userinfo.split(":", 1)
                    except:
                        method, password = user_part.split(":", 1)
                else:
                    decoded = safe_b64decode(raw).decode()
                    userinfo, hostport = decoded.rsplit("@", 1)
                    method, password = userinfo.split(":", 1)
                    host, port = _split_host_port(hostport)
                b.update({'type': 'ss', 'server': host, 'port': int(port), 'cipher': method, 'password': password})
                if plugin_info:
                    # Normalize shadow-tls plugin naming
                    if plugin_info.get('name') in ['shadowtls', 'shadow-tls']:
                        plugin_info['name'] = 'shadow-tls'
                    b['plugin'] = plugin_info['name']
                    b['plugin_opts'] = plugin_info['opts']
                return b
            except:
                pass


        elif p.scheme == "anytls":
            try:
                password = q.get('password', [''])[0] or (p.password or p.username or '')
                b.update({'type': 'anytls', 'server': server, 'port': int(base_port or q.get('port', [443])[0] or 443), 'password': password, 'udp': True})
                if q.get('sni'): b['sni'] = q.get('sni', [''])[0]
                if q.get('alpn'): b['alpn'] = q.get('alpn', [''])[0]
                if q.get('idle-session-check-interval'): b['idle-session-check-interval'] = int(float(q.get('idle-session-check-interval', ['30'])[0]))
                if q.get('idle-session-timeout'): b['idle-session-timeout'] = int(float(q.get('idle-session-timeout', ['30'])[0]))
                if q.get('min-idle-session'): b['min-idle-session'] = int(float(q.get('min-idle-session', ['0'])[0]))
                if q.get('fp'): b['fp'] = q.get('fp', ['chrome'])[0]
                elif q.get('client-fingerprint'): b['fp'] = q.get('client-fingerprint', ['chrome'])[0]
                is_insecure = q.get('allow_insecure', ['0'])[0] == '1' or q.get('allowInsecure', ['0'])[0] == '1' or q.get('insecure', ['0'])[0] == '1'
                if is_insecure: b['skip-cert-verify'] = True
                return b
            except:
                pass

        elif p.scheme in ["shadowtls", "stls"]:
            try:
                password = q.get('password', [''])[0] or (p.password or p.username or '')
                version = int(float(q.get('version', [q.get('v', ['1'])[0] if q.get('v') else '1'])[0]))
                b.update({'type': 'shadowtls', 'server': server, 'port': int(base_port or q.get('port', [443])[0] or 443), 'password': password, 'version': version, 'udp': True})
                if q.get('sni'): b['sni'] = q.get('sni', [''])[0]
                if q.get('alpn'): b['alpn'] = q.get('alpn', [''])[0]
                if q.get('fp'): b['fp'] = q.get('fp', ['chrome'])[0]
                elif q.get('client-fingerprint'): b['fp'] = q.get('client-fingerprint', ['chrome'])[0]
                is_insecure = q.get('allow_insecure', ['0'])[0] == '1' or q.get('allowInsecure', ['0'])[0] == '1' or q.get('insecure', ['0'])[0] == '1'
                if is_insecure: b['skip-cert-verify'] = True
                return b
            except:
                pass

        elif p.scheme.startswith("naive"):
            try:
                username = p.username or q.get('username', [''])[0]
                password = p.password or q.get('password', [''])[0]
                scheme = p.scheme.lower()
                use_quic = ('quic' in scheme)
                b.update({'type': 'naive', 'server': server, 'port': int(base_port or q.get('port', [443])[0] or 443), 'username': username, 'password': password, 'quic': use_quic, 'udp': True})
                if q.get('sni'): b['sni'] = q.get('sni', [''])[0]
                if q.get('fp'): b['fp'] = q.get('fp', ['chrome'])[0]
                is_insecure = q.get('allow_insecure', ['0'])[0] == '1' or q.get('allowInsecure', ['0'])[0] == '1' or q.get('insecure', ['0'])[0] == '1'
                if is_insecure: b['skip-cert-verify'] = True
                return b
            except:
                pass
        elif p.scheme in ["hysteria2", "hy2"]:
            # Support both:
            # 1) Official multi-port style: hysteria2://auth@host:443,5000-6000?...#name
            # 2) Common extension: ?mport=5000-6000  (port hopping)
            netloc = p.netloc or ""
            userinfo = ""
            hostport = netloc
            if "@" in netloc:
                userinfo, hostport = netloc.rsplit("@", 1)

            # auth can be "password" or "user:password"
            userinfo = urllib.parse.unquote(userinfo)
            hy_pass = ""
            if ":" in userinfo:
                _u, _pw = userinfo.split(":", 1)
                hy_pass = urllib.parse.unquote(_pw or _u)
            else:
                hy_pass = userinfo

            host = ""
            port_part = ""

            if hostport.startswith('[') and ']' in hostport:
                # IPv6 form: [::1]:443,5000-6000
                host = hostport[1:hostport.find(']')]
                rest = hostport[hostport.find(']') + 1:]
                if rest.startswith(':'):
                    port_part = rest[1:]
            else:
                if ":" in hostport:
                    host, port_part = hostport.rsplit(":", 1)
                else:
                    host = hostport

            # port part (may contain comma/range)
            port_part = urllib.parse.unquote(port_part)
            port_parts = parse_ports_spec(port_part) if port_part else []
            # If port part is a single range "5000-6000", treat as ports too
            is_multi_in_port = (len(port_parts) > 1) or (len(port_parts) == 1 and "-" in port_parts[0])

            # mport extension (may contain ranges / list)
            mport_raw = (q.get('mport', [''])[0] or q.get('ports', [''])[0] or "").strip()
            mport_parts = parse_ports_spec(mport_raw)

            # Determine base port
            base_port = None
            if port_parts:
                m0 = re.match(r"^(\d+)", port_parts[0])
                if m0:
                    base_port = int(m0.group(1))
            if base_port is None:
                try:
                    base_port = p.port
                except:
                    pass

            if not base_port:
                return None

            # Build combined hopping ports spec (used for clash/sing-box)
            combined = []
            # If we already have multi-port in port-part, that usually already includes the base
            if port_parts:
                combined.extend(port_parts)
            else:
                combined.append(str(base_port))

            for pp in mport_parts:
                if pp and pp not in combined:
                    combined.append(pp)

            ports_spec = join_ports_spec(combined) if (len(combined) > 1 or (combined and "-" in combined[0])) else ""

            b = {
                "type": "hysteria2",
                "name": name,
                "server": host,
                "port": int(base_port),
                "password": hy_pass or (p.username or p.password or ""),
                "sni": q.get('sni', [''])[0],
                "alpn": q.get('alpn', ['h3'])[0],
            }

            if ports_spec:
                b["ports"] = ports_spec
                if mport_raw:
                    b["_mport"] = mport_raw
                    b["_ports_mode"] = "mport"
                else:
                    b["_ports_mode"] = "multi"

            is_insecure = (
                q.get('insecure', ['0'])[0] in ['1', 'true', 'True'] or
                q.get('allowInsecure', ['0'])[0] in ['1', 'true', 'True'] or
                q.get('allow_insecure', ['0'])[0] in ['1', 'true', 'True'] or
                q.get('skip-cert-verify', ['0'])[0] in ['1', 'true', 'True']
            )
            is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) or host.startswith('[') or ':' in host)
            if is_insecure or is_ip or (b.get('sni') and b.get('sni') != host):
                b['skip-cert-verify'] = True
            return b

        elif p.scheme == "tuic":
            # [v42.31 Fix] 强制 Unquote 用户信息，修复 %3A 导致的分割失败
            uuid = urllib.parse.unquote(p.username) if p.username else ""
            password = urllib.parse.unquote(p.password) if p.password else ""

            if not password and ":" in uuid:
                uuid, password = uuid.split(':', 1)

            b.update({
                'type': 'tuic',
                'uuid': uuid,
                'password': password,
                'sni': q.get('sni', [''])[0],
                'alpn': q.get('alpn', ['h3'])[0],
                'congestion_control': q.get('congestion_control', ['bbr'])[0]
            })

            # [v42.31 Fix] 兼容多种 insecure 写法与 IP 直连默认跳过证书校验
            is_insecure = (
                q.get('allow_insecure', ['0'])[0] in ['1', 'true', 'True'] or
                q.get('allowInsecure', ['0'])[0] in ['1', 'true', 'True'] or
                q.get('insecure', ['0'])[0] in ['1', 'true', 'True'] or
                q.get('skip-cert-verify', ['0'])[0] in ['1', 'true', 'True']
            )
            server_host = str(server or '')
            is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", server_host) or server_host.startswith('[') or ':' in server_host)
            if is_insecure or is_ip or (b.get('sni') and b.get('sni') != server_host):
                b['skip-cert-verify'] = True
            return b

        elif p.scheme in ["awg", "wireguard"]:
            try:
                netloc = p.netloc or ""
                client_pri = p.username or ""
                server_part = p.hostname or ""
                port_val = p.port or 51820
                if not client_pri and "@" in netloc:
                    client_pri, rest = netloc.rsplit("@", 1)
                    client_pri = urllib.parse.unquote(client_pri)
                    server_part, port_str = split_host_port(rest, 51820)
                    port_val = int(port_str) if port_str else 51820

                b.update({
                    'type': 'wireguard',
                    'name': name or 'AmneziaWG',
                    'server': server_part,
                    'port': int(port_val),
                    'private-key': client_pri,
                    'public-key': q.get('publickey', [''])[0] or q.get('public-key', [''])[0] or q.get('pubkey', [''])[0],
                    'ip': q.get('address', ['10.8.0.2'])[0].split('/')[0],
                    'psk': q.get('psk', [''])[0] or q.get('preshared-key', [''])[0],
                    'jc': int(q.get('jc', [4])[0]) if q.get('jc') else 4,
                    'jmin': int(q.get('jmin', [50])[0]) if q.get('jmin') else 50,
                    'jmax': int(q.get('jmax', [1000])[0]) if q.get('jmax') else 1000,
                    's1': int(q.get('s1', [15])[0]) if q.get('s1') else 15,
                    's2': int(q.get('s2', [20])[0]) if q.get('s2') else 20,
                    'h1': int(q.get('h1', [1])[0]) if q.get('h1') else 1,
                    'h2': int(q.get('h2', [2])[0]) if q.get('h2') else 2,
                    'h3': int(q.get('h3', [3])[0]) if q.get('h3') else 3,
                    'h4': int(q.get('h4', [4])[0]) if q.get('h4') else 4,
                    'udp': True
                })
                return b
            except:
                pass

    except:
        pass
    return None

def gen_clash(n, ip=None, port=None, name=None):
    try:
        if n['type'] == 'clash_import':
            c = copy.deepcopy(n['raw']); c['name'] = name; c['server'] = ip or c['server']; c['port'] = port or c['port']; return c
        c = {"name": name or n['name'], "type": n['type'], "server": ip or n['server'], "port": port or n['port'], "udp": True}
        if n['type'] == 'shadowtls': return None
        
        if n.get('skip-cert-verify'): c['skip-cert-verify'] = True
        
        server_str = str(c['server'])
        is_ip_server = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", server_str)
        sni = n.get('sni') or n.get('servername')
        
        if is_ip_server and sni: c['skip-cert-verify'] = True
        elif sni and server_str != sni: c['skip-cert-verify'] = True

        def get_alpn_list(obj):
            val = obj.get('alpn', 'h3')
            if isinstance(val, (list, tuple)):
                return [str(x).strip() for x in val if str(x).strip()]
            val = str(val).strip()
            if not val:
                return ['h3']
            return [x.strip() for x in val.split(',')] if ',' in val else [val]

        if n['type'] == 'vless':
            c.update({"uuid":n['uuid'], "network":n['network'], "tls":n['tls']})
            if n.get('sni'): c['servername'] = n['sni']
            if n.get('flow'): c['flow'] = n['flow']
            if n.get('reality'): c.update({'reality-opts': {'public-key':n['pbk'], 'short-id':n['sid']}, 'client-fingerprint':n.get('fp','chrome')})
            else: c['client-fingerprint'] = 'chrome'
            if n.get('fp'): c['client-fingerprint'] = n['fp']
            if n['network']=='ws': c['ws-opts'] = {'path':n.get('ws-path'), 'headers':{'Host':n.get('ws-host')}}
            elif n['network']=='grpc': c['grpc-opts'] = {'grpc-service-name':n.get('grpc-name')}
            elif n['network'] in ['xhttp', 'splithttp']:
                c['network'] = 'xhttp'
                c['xhttp-opts'] = {
                    'path': n.get('xhttp-path') or n.get('ws-path') or '/',
                    'host': n.get('xhttp-host') or n.get('ws-host') or n.get('sni') or '',
                    'mode': n.get('xhttp-mode') or 'auto'
                }
                eff_port = int(port or n.get('port') or 443)
                if eff_port == 443:
                    c['alpn'] = ['h3', 'h2', 'http/1.1']
                else:
                    c['alpn'] = ['h2', 'http/1.1']
        elif n['type'] == 'vmess':
            c.update({"uuid":n['uuid'], "alterId":n['alterId'], "cipher":"auto", "network":n['network']})
            if n.get('tls'): c['tls']=True; c['servername']=n.get('sni')
            else: c['tls']=False
            if n['network']=='ws': c['ws-opts'] = {'path':n.get('ws-path'), 'headers':{'Host':n.get('ws-host')}}
            elif n['network']=='grpc': c['grpc-opts'] = {'grpc-service-name':n.get('grpc-name')}
            elif n['network'] in ['xhttp', 'splithttp']:
                c['network'] = 'xhttp'
                c['xhttp-opts'] = {
                    'path': n.get('xhttp-path') or n.get('ws-path') or '/',
                    'host': n.get('xhttp-host') or n.get('ws-host') or n.get('sni') or '',
                    'mode': n.get('xhttp-mode') or 'auto'
                }
                eff_port = int(port or n.get('port') or 443)
                if eff_port == 443:
                    c['alpn'] = ['h3', 'h2', 'http/1.1']
                else:
                    c['alpn'] = ['h2', 'http/1.1']
        elif n['type'] == 'trojan':
            c.update({"password":n['password'], "network":n.get('network','tcp')})
            if n.get('sni'): c['sni'] = n['sni']
            if n.get('alpn'): c['alpn'] = n['alpn'] 
            if n.get('network')=='ws': c['ws-opts'] = {'path':n.get('ws-path'), 'headers':{'Host':n.get('ws-host')}}
            elif n.get('network')=='grpc': c['grpc-opts'] = {'grpc-service-name':n.get('grpc-name')}
        elif n['type'] == 'hysteria2':
            c.update({"password": n.get('password',''), "sni": n.get('sni',''), "alpn": get_alpn_list(n)})
            if n.get('obfs'):
                c['obfs'] = n['obfs']
                c['obfs-password'] = n.get('obfs_password') or n.get('obfs-password', '')
            if n.get('ports'):
                parts = parse_ports_spec(n.get('ports'))
                if port and str(port) != str(n.get('port')):
                    orig_base = str(n.get('port'))
                    parts = [pp for pp in parts if pp != orig_base]
                    parts = [str(port)] + parts
                c['ports'] = join_ports_spec(parts)
        elif n['type'] == 'tuic':
            c.update({"uuid":n['uuid'], "password":n['password'], "sni":n.get('sni',''), 
                      "alpn": get_alpn_list(n)})
            if n.get('udp_relay_mode'): c['udp-relay-mode'] = n['udp_relay_mode']
            if sni and server_str != sni: c['skip-cert-verify'] = True
        elif n['type'] == 'anytls':
            c.update({
                'type': 'anytls',
                'password': n.get('password', ''),
                'udp': True,
                'client-fingerprint': n.get('fp', 'chrome'),
                'idle-session-check-interval': int(n.get('idle-session-check-interval', 30)),
                'idle-session-timeout': int(n.get('idle-session-timeout', 30)),
                'min-idle-session': int(n.get('min-idle-session', 0)),
                'sni': n.get('sni', '')
            })
            if n.get('alpn'): c['alpn'] = get_alpn_list(n)
            if n.get('skip-cert-verify'): c['skip-cert-verify'] = True
        elif n['type'] == 'naive':
            c.update({
                'type': 'naive',
                'username': n.get('username', ''),
                'password': n.get('password', ''),
                'sni': n.get('sni', ''),
                'udp': True
            })
            if n.get('quic'): c['network'] = 'quic'
            if n.get('skip-cert-verify'): c['skip-cert-verify'] = True
        elif n['type'] == 'ss':
            c.update({"cipher":n['cipher'], "password":n['password']})
            c['client-fingerprint'] = 'chrome'
            if n.get('plugin'):
                c['plugin'] = n['plugin']
                popts = n.get('plugin_opts', {})
                if n.get('plugin') == 'shadow-tls':
                    c['client-fingerprint'] = n.get('fp', 'chrome')
                    if 'version' in popts:
                        try: popts['version'] = int(popts['version'])
                        except: pass
                if n['plugin'] == 'v2ray-plugin':
                    c['plugin-opts'] = {'mode': popts.get('mode', 'websocket'), 'host': popts.get('host', ''), 'path': popts.get('path', '/'), 'tls': True if 'tls' in popts else False, 'skip-cert-verify': True if 'skip-cert-verify' in popts else False, 'mux': False, 'headers': {'Host': popts.get('host', ''), 'User-Agent': 'Mozilla/5.0'}}
                else: c['plugin-opts'] = popts
        elif n['type'] in ['wireguard', 'awg']:
            pub_key = (n.get('public-key') or '').strip().replace(' ', '+')
            pri_key = (n.get('private-key') or '').strip().replace(' ', '+')
            psk_key = (n.get('psk') or '').strip().replace(' ', '+')
            c = {
                "name": name or n['name'],
                "type": "wireguard",
                "server": ip or n['server'],
                "port": int(port or n.get('port', 51820)),
                "ip": n.get('ip', '10.8.0.2'),
                "public-key": pub_key,
                "private-key": pri_key,
                "allowed-ips": ["0.0.0.0/0", "::/0"],
                "udp": True,
                "remote-dns-resolve": False,
                "dns": ["1.1.1.1", "8.8.8.8"]
            }
            if psk_key:
                c["pre-shared-key"] = psk_key
                c["preshared-key"] = psk_key
            if n.get('jc') is not None or n.get('s1') is not None:
                c["amnezia-wg-option"] = {
                    "jc": int(n.get('jc', 4)),
                    "jmin": int(n.get('jmin', 50)),
                    "jmax": int(n.get('jmax', 1000)),
                    "s1": int(n.get('s1', 15)),
                    "s2": int(n.get('s2', 20)),
                    "h1": int(n.get('h1', 1)),
                    "h2": int(n.get('h2', 2)),
                    "h3": int(n.get('h3', 3)),
                    "h4": int(n.get('h4', 4))
                }
            return c
        return c
    except: return None

def gen_uri(n, ip=None, port=None, name=None):
    if not isinstance(n, dict) or 'type' not in n: return None
    server = ip or n['server']; port = str(port or n['port']); remark = urllib.parse.quote(name or n['name'])
    if n['type'] == 'vless':
        sec = 'reality' if n.get('reality') else ('tls' if n.get('tls') else 'none')
        p = {'type': n.get('network', 'tcp'), 'security': sec, 'encryption': n.get('encryption', 'none')}
        if n.get('reality'):
            p.update({'pbk': n.get('pbk', ''), 'sid': n.get('sid', ''), 'fp': n.get('fp', 'chrome')})
        if n.get('sni'):
            p['sni'] = n['sni']
        if n.get('flow'):
            p['flow'] = n['flow']
        if n.get('fp'):
            p['fp'] = n['fp']
        if n.get('headerType'):
            p['headerType'] = n['headerType']
        elif n.get('network', 'tcp') == 'tcp':
            p['headerType'] = 'none'
        server_str = str(server)
        is_ip_server = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", server_str) or server_str.startswith('[') or ':' in server_str)
        sni = n.get('sni', '')
        should_skip_cert = n.get('skip-cert-verify') or (is_ip_server and sni and not n.get('reality'))

        if should_skip_cert:
            p['insecure'] = '1'; p['allowInsecure'] = '1'; p['allow_insecure'] = '1'; p['skip-cert-verify'] = '1'
        if n.get('network') == 'ws':
            p.update({'path': n.get('ws-path', '/'), 'host': n.get('ws-host', '')})
        elif n.get('network') == 'grpc':
            p['serviceName'] = n.get('grpc-name', '')
        elif n.get('network') in ['xhttp', 'splithttp']:
            p['type'] = 'xhttp'
            p['path'] = n.get('xhttp-path') or n.get('ws-path') or '/'
            p['host'] = n.get('xhttp-host') or n.get('ws-host') or n.get('sni') or ''
            p['mode'] = n.get('xhttp-mode') or 'auto'
            eff_port = int(port or n.get('port') or 443)
            if eff_port == 443 and n.get('alpn') and 'h3' in n.get('alpn'):
                p['alpn'] = 'h3,h2'
        return f"vless://{n['uuid']}@{server}:{port}?{urllib.parse.urlencode(p)}#{remark}"
    elif n['type'] == 'vmess':
        j = {"v":"2", "ps":name or n['name'], "add":server, "port":port, "id":n['uuid'], "aid":n.get('alterId',0), "scy":"auto", "net":n['network'], "type":"none"}
        if n.get('tls'): j['tls']="tls"; j['host']=n.get('sni'); j['sni']=n.get('sni')
        else: j['tls']=""; j['host']=n.get('ws-host')
        if n['network']=='ws': j['path']=n.get('ws-path','/'); j['host']=n.get('ws-host','')
        elif n['network']=='grpc': j['path']=n.get('grpc-name','')
        return "vmess://" + base64.b64encode(json.dumps(j).encode()).decode()
    elif n['type'] == 'trojan':
        p = {'type':n.get('network','tcp'), 'sni':n.get('sni',''), 'allowInsecure': '1' if n.get('skip-cert-verify') else '0'}
        if n.get('alpn'): p['alpn'] = n['alpn']
        if n.get('network')=='ws': p.update({'path':n.get('ws-path','/'), 'host':n.get('ws-host','')})
        elif n.get('network')=='grpc': p['serviceName'] = n.get('grpc-name','')
        return f"trojan://{n['password']}@{server}:{port}?{urllib.parse.urlencode(p)}#{remark}"
    elif n['type'] == 'hysteria2':
        server_str = str(server)
        is_ip_server = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", server_str) or server_str.startswith('[') or ':' in server_str)
        sni = n.get('sni', '')
        skip_cert = n.get('skip-cert-verify') or is_ip_server or (sni and server_str != sni)

        p = {'sni': sni, 'alpn': n.get('alpn', 'h3')}
        if skip_cert:
            p['insecure'] = '1'
            p['allowInsecure'] = '1'
            p['allow_insecure'] = '1'
            p['skip-cert-verify'] = '1'

        # Port hopping support:
        # - If original was ?mport=..., keep mport in query for compatibility.
        # - Otherwise, use official multi-port style in the port part: host:443,5000-6000
        ports_spec = n.get('ports', '')
        ports_mode = n.get('_ports_mode', '')

        if ports_spec:
            parts = parse_ports_spec(ports_spec)
            # If caller overrides base port, rebuild spec with new base as first element
            if port and str(port) != str(n.get('port')):
                orig_base = str(n.get('port'))
                parts = [pp for pp in parts if pp != orig_base]
                parts = [str(port)] + parts
            ports_spec = join_ports_spec(parts)

            if ports_mode == 'mport' and n.get('_mport'):
                p['mport'] = n.get('_mport')
                port_part = str(port)
            else:
                port_part = ports_spec
        else:
            port_part = str(port)

        return f"hysteria2://{n.get('password','')}@{server}:{port_part}?{urllib.parse.urlencode(p)}#{remark}"
    elif n['type'] == 'tuic':
        server_str = str(server)
        is_ip_server = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", server_str) or server_str.startswith('[') or ':' in server_str)
        sni = n.get('sni', '')
        skip_cert = n.get('skip-cert-verify') or is_ip_server or (sni and server_str != sni)

        p = {'sni': sni, 'congestion_control': n.get('congestion_control', 'bbr'), 'alpn': n.get('alpn', 'h3')}
        if skip_cert:
            p['allow_insecure'] = '1'
            p['allowInsecure'] = '1'
            p['insecure'] = '1'
            p['skip-cert-verify'] = '1'
        return f"tuic://{n['uuid']}:{n['password']}@{server}:{port}?{urllib.parse.urlencode(p)}#{remark}"
    elif n['type'] == 'anytls':
        p = {}
        if n.get('sni'): p['sni'] = n['sni']
        if n.get('alpn'): p['alpn'] = n['alpn']
        if n.get('fp'): p['fp'] = n['fp']
        if n.get('idle-session-check-interval') is not None: p['idle-session-check-interval'] = str(n.get('idle-session-check-interval'))
        if n.get('idle-session-timeout') is not None: p['idle-session-timeout'] = str(n.get('idle-session-timeout'))
        if n.get('min-idle-session') is not None: p['min-idle-session'] = str(n.get('min-idle-session'))
        if n.get('skip-cert-verify'): p['insecure'] = '1'; p['allowInsecure'] = '1'
        return f"anytls://{urllib.parse.quote(n.get('password',''))}@{server}:{port}?{urllib.parse.urlencode(p)}#{remark}"
    elif n['type'] == 'shadowtls':
        p = {'version': str(int(n.get('version', 1)))}
        if n.get('sni'): p['sni'] = n['sni']
        if n.get('alpn'): p['alpn'] = n['alpn']
        if n.get('fp'): p['fp'] = n['fp']
        if n.get('skip-cert-verify'): p['insecure'] = '1'
        return f"shadowtls://{urllib.parse.quote(n.get('password',''))}@{server}:{port}?{urllib.parse.urlencode(p)}#{remark}"
    elif n['type'] == 'naive':
        p = {}
        if n.get('sni'): p['sni'] = n['sni']
        if n.get('fp'): p['fp'] = n['fp']
        if n.get('skip-cert-verify'): p['insecure'] = '1'
        scheme = 'naive+quic' if n.get('quic') else 'naive+https'
        user = urllib.parse.quote(n.get('username',''))
        pwd = urllib.parse.quote(n.get('password',''))
        return f"{scheme}://{user}:{pwd}@{server}:{port}?{urllib.parse.urlencode(p)}#{remark}"
    elif n['type'] == 'ss':
        auth = base64.b64encode(f"{n['cipher']}:{n['password']}".encode()).decode()
        uri = f"ss://{auth}@{server}:{port}"
        if n.get('plugin'):
            popts = n.get('plugin_opts', {})
            opt_str = ";".join([f"{k}={v}" if v is not True else k for k,v in popts.items()])
            plugin_str = urllib.parse.quote(f"{n['plugin']};{opt_str}")
            uri += f"/?plugin={plugin_str}"
        return f"{uri}#{remark}"
    elif n['type'] in ['wireguard', 'awg']:
        pub_key = (n.get('public-key') or '').strip().replace(' ', '+')
        pri_key = (n.get('private-key') or '').strip().replace(' ', '+')
        psk_key = (n.get('psk') or '').strip().replace(' ', '+')
        p = {
            'publickey': pub_key,
            'address': n.get('ip', '10.8.0.2'),
            'jc': str(n.get('jc', 4)),
            'jmin': str(n.get('jmin', 50)),
            'jmax': str(n.get('jmax', 1000)),
            's1': str(n.get('s1', 15)),
            's2': str(n.get('s2', 20)),
            'h1': str(n.get('h1', 1)),
            'h2': str(n.get('h2', 2)),
            'h3': str(n.get('h3', 3)),
            'h4': str(n.get('h4', 4))
        }
        if psk_key:
            p['psk'] = psk_key
        quoted_pri = urllib.parse.quote(pri_key, safe='')
        return f"awg://{quoted_pri}@{server}:{port}?{urllib.parse.urlencode(p)}#{remark}"
    return None

def gen_singbox(n, ip=None, port=None, name=None):
    try:
        server = ip or n['server']
        port = int(port or n.get('port') or 443)
        tag = name or n['name']
        ntype = n.get('type')
        
        def get_alpn_list(obj):
            val = obj.get('alpn', ['h3'] if ntype in ['hysteria2', 'tuic'] else [])
            if isinstance(val, (list, tuple)):
                return [str(x).strip() for x in val if str(x).strip()]
            val = str(val).strip()
            if not val:
                return ['h3'] if ntype in ['hysteria2', 'tuic'] else []
            return [x.strip() for x in val.split(',') if x.strip()]

        def build_tls(allow_utls=True, default_alpn=None):
            sni = (n.get('sni') or n.get('servername') or '').strip()
            server_str = str(server)
            is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", server_str) or ':' in server_str)
            insecure = bool(n.get('skip-cert-verify') or (is_ip and sni) or (sni and server_str != sni))
            tls_obj = {"enabled": True}
            if sni: tls_obj["server_name"] = sni
            if insecure: tls_obj["insecure"] = True
            alpn = get_alpn_list(n)
            if not alpn and default_alpn:
                alpn = default_alpn
            if alpn: tls_obj["alpn"] = alpn
            if n.get('reality'):
                tls_obj["reality"] = {
                    "enabled": True,
                    "public_key": n.get('pbk', ''),
                    "short_id": n.get('sid', '')
                }
            if allow_utls:
                fp = n.get('fp') or ('chrome' if n.get('reality') else None)
                if fp:
                    tls_obj["utls"] = {"enabled": True, "fingerprint": fp}
            return tls_obj

        def build_transport():
            net = n.get('network') or 'tcp'
            if net == 'ws':
                ws = {"type": "ws", "path": n.get('ws-path') or "/"}
                if n.get('ws-host'):
                    ws["headers"] = {"Host": n['ws-host']}
                return ws
            elif net == 'grpc':
                grpc = {"type": "grpc"}
                if n.get('grpc-name'):
                    grpc["service_name"] = n['grpc-name']
                return grpc
            elif net in ['xhttp', 'splithttp']:
                xh = {
                    "type": "xhttp",
                    "path": n.get('xhttp-path') or n.get('ws-path') or "/",
                    "mode": n.get('xhttp-mode') or "packet-up"
                }
                host_val = n.get('xhttp-host') or n.get('ws-host')
                if host_val:
                    xh["headers"] = {"Host": host_val}
                return xh
            return None

        sb = {"type": ntype, "tag": tag, "server": server}

        if ntype == 'vless':
            sb.update({"server_port": port, "uuid": n['uuid']})
            if n.get('flow'): sb["flow"] = n['flow']
            def_alpn = ['h3'] if n.get('network') in ['xhttp', 'splithttp'] else None
            if n.get('tls') or n.get('reality'): sb["tls"] = build_tls(default_alpn=def_alpn)
            trans = build_transport()
            if trans: sb["transport"] = trans
            return sb

        elif ntype == 'vmess':
            sb.update({"server_port": port, "uuid": n['uuid'], "security": "auto", "alter_id": int(n.get('alterId', 0))})
            if n.get('tls'): sb["tls"] = build_tls()
            trans = build_transport()
            if trans: sb["transport"] = trans
            return sb

        elif ntype == 'trojan':
            sb.update({"server_port": port, "password": n.get('password', '')})
            sb["tls"] = build_tls()
            trans = build_transport()
            if trans: sb["transport"] = trans
            return sb

        elif ntype == 'hysteria2':
            sb.update({
                "server_port": port,
                "password": n.get('password', '') or n.get('auth', '')
            })
            if n.get('ports'):
                parts = parse_ports_spec(n.get('ports'))
                range_parts = [pp.replace(':', '-') for pp in parts if '-' in pp]
                if range_parts:
                    sb['server_ports'] = range_parts
            sb["tls"] = build_tls(allow_utls=False, default_alpn=['h3'])
            obfs_pass = n.get('obfs_password') or n.get('obfs-password') or ''
            if n.get('obfs') and obfs_pass:
                sb['obfs'] = {"type": n.get('obfs') if n.get('obfs') in ['salamander'] else 'salamander', "password": obfs_pass}
            if n.get('up_mbps'):
                try: sb['up_mbps'] = int(n['up_mbps'])
                except: pass
            elif n.get('up'):
                try: sb['up_mbps'] = int(re.sub(r'[^\d]', '', str(n['up'])))
                except: pass
            if n.get('down_mbps'):
                try: sb['down_mbps'] = int(n['down_mbps'])
                except: pass
            elif n.get('down'):
                try: sb['down_mbps'] = int(re.sub(r'[^\d]', '', str(n['down'])))
                except: pass
            return sb

        elif ntype == 'tuic':
            sb.update({
                "server_port": port,
                "uuid": n.get('uuid', ''),
                "password": n.get('password', ''),
                "congestion_control": n.get('congestion_control', 'bbr')
            })
            if n.get('udp_relay_mode'): sb['udp_relay_mode'] = n['udp_relay_mode']
            sb["tls"] = build_tls(allow_utls=False, default_alpn=['h3'])
            return sb

        elif ntype == 'ss':
            sb.update({"server_port": port, "method": n.get('cipher', ''), "password": n.get('password', '')})
            if n.get('plugin') == 'v2ray-plugin':
                popts = n.get('plugin_opts', {})
                sb["plugin"] = "v2ray-plugin"
                sb["plugin_opts"] = f"mode={popts.get('mode','websocket')};host={popts.get('host','')};path={popts.get('path','/')};tls={popts.get('tls',False)}"
            elif n.get('plugin'):
                return None
            return sb

        elif ntype == 'anytls':
            sb.update({"server_port": port, "password": n.get('password', '')})
            sb["tls"] = build_tls()
            if n.get('idle-session-check-interval'):
                sb['idle_session_check_interval'] = f"{n['idle-session-check-interval']}s"
            return sb

        elif ntype == 'shadowtls':
            sb.update({"server_port": port, "password": n.get('password', ''), "version": int(n.get('version', 1))})
            sb["tls"] = build_tls()
            return sb

        elif ntype == 'naive':
            sb.update({"server_port": port, "username": n.get('username', ''), "password": n.get('password', '')})
            sb["tls"] = build_tls()
            if n.get('quic'): sb['network'] = 'quic'
            return sb

        elif ntype in ['wireguard', 'awg']:
            pub_key = (n.get('public-key') or '').strip().replace(' ', '+')
            pri_key = (n.get('private-key') or '').strip().replace(' ', '+')
            psk_key = (n.get('psk') or '').strip().replace(' ', '+')
            sb.update({
                "type": "wireguard",
                "tag": tag,
                "server": server,
                "server_port": port,
                "local_address": [f"{n.get('ip', '10.8.0.2')}/32"],
                "private_key": pri_key,
                "peer_public_key": pub_key
            })
            if psk_key:
                sb["pre_shared_key"] = psk_key
            if n.get('jc') is not None or n.get('s1') is not None:
                sb.update({
                    "jc": int(n.get('jc', 4)),
                    "jmin": int(n.get('jmin', 50)),
                    "jmax": int(n.get('jmax', 1000)),
                    "s1": int(n.get('s1', 15)),
                    "s2": int(n.get('s2', 20)),
                    "h1": int(n.get('h1', 1)),
                    "h2": int(n.get('h2', 2)),
                    "h3": int(n.get('h3', 3)),
                    "h4": int(n.get('h4', 4))
                })
            return sb

        return None
    except:
        return None

def fetch_cf_ips(user_input):
    """从给定的测速 API 订阅地址或优选域名拉取并提取优选 IP 列表"""
    if not requests:
        return False, "requests 依赖缺失", []
    user_input = str(user_input or '').strip()
    if not user_input:
        return False, "API 地址为空", []
    
    target_url = user_input
    if not user_input.startswith('http'):
        target_url = f"https://{user_input}/sub?host=speed.cloudflare.com&uuid=00000000-0000-0000-0000-000000000000"
        
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': '*/*'
    }
    try:
        r = requests.get(target_url, timeout=20, verify=False, headers=headers, allow_redirects=True)
        if r.status_code != 200:
            return False, f"下载失败 (HTTP {r.status_code})", []
        content = r.text
        if not content:
            return False, "返回内容为空", []
            
        extracted = extract_speedtest_ips(content)
        if not extracted:
            try:
                clean_b64 = content.strip().replace('-', '+').replace('_', '/')
                pad = len(clean_b64) % 4
                if pad: clean_b64 += '=' * (4 - pad)
                decoded = base64.b64decode(clean_b64).decode('utf-8', errors='ignore')
                extracted = extract_speedtest_ips(decoded)
            except:
                pass
                
        if not extracted:
            return False, "未在返回内容中找到有效 IP (格式不匹配)", []
            
        return True, "成功", list(dict.fromkeys(extracted))
    except Exception as e:
        return False, f"网络请求异常: {e}", []

async def async_process_subs():
    d = load_data()
    subs = d.get('remote_subs', [])
    write_log(f"Sync Start (v43.00, subs: {len(subs)})")
    cfg = d.get('config', {})
    
    try:
        if subs:
            all_nodes = []
            sem = asyncio.Semaphore(int(cfg.get('threads', 8))) 

            # 1. 如果配置了探针 (Komari / 哪吒)，异步拉取服务器实时网卡进出流量
            probe_servers = {}
            probe_type = str(cfg.get('probe_type', 'komari')).lower()
            probe_url = (cfg.get('probe_url') or cfg.get('nezha_url', '')).strip()
            probe_token = (cfg.get('probe_token') or cfg.get('nezha_token', '')).strip()

            if probe_url and aiohttp:
                try:
                    async with aiohttp.ClientSession() as ps_session:
                        if probe_type == 'komari':
                            probe_servers = await fetch_komari_stats(ps_session, probe_url, probe_token)
                            if probe_servers:
                                ucnt = len({v.get('uuid') for v in probe_servers.values() if isinstance(v, dict) and v.get('uuid')}) or len(probe_servers)
                                write_log(f"Komari Probe synced: {ucnt} nodes loaded")
                        else:
                            probe_servers = await fetch_nezha_stats(ps_session, probe_url, probe_token)
                            if probe_servers:
                                write_log(f"Nezha Probe synced: {len(probe_servers)} servers loaded")
                except Exception as e:
                    write_log(f"Probe Sync Error ({probe_type}): {e}")

            # 🌟 关键降级保障：若实时拉取探针失败（网络抖动或临时超时），自动读取历史 cached_probe_nodes 缓存
            if not probe_servers and d.get('cached_probe_nodes'):
                write_log(f"Probe live fetch empty/failed ({probe_type}), falling back to cached_probe_nodes ({len(d['cached_probe_nodes'])} nodes)")
                for pn in d['cached_probe_nodes']:
                    if isinstance(pn, dict):
                        k_name = str(pn.get('name', '')).strip()
                        k_uuid = str(pn.get('uuid', '')).strip().lower()
                        k_id = str(pn.get('id', '')).strip().lower()
                        if k_name:
                            probe_servers[k_name.lower()] = pn
                            probe_servers[k_name] = pn
                        if k_uuid: probe_servers[k_uuid] = pn
                        if k_id: probe_servers[k_id] = pn

            if probe_servers:
                unique_nodes_list = []
                seen_nodes = set()
                for v in probe_servers.values():
                    if isinstance(v, dict):
                        k = v.get('uuid') or v.get('id') or v.get('name')
                        if k and k not in seen_nodes:
                            seen_nodes.add(k)
                            p_name = str(v.get('name', ''))
                            p_country, p_flag = detect_country_info(p_name)
                            unique_nodes_list.append({
                                "uuid": str(v.get('uuid', '')),
                                "id": str(v.get('id', '')),
                                "name": p_name,
                                "used": v.get('used', 0),
                                "limit": v.get('limit', 0),
                                "limit_gb": v.get('limit_gb', 0),
                                "country": p_country,
                                "flag": p_flag
                            })
                d['cached_probe_nodes'] = unique_nodes_list

            async def process_single_sub(session, sub_item):
                raw_text = sub_item.get('url', '')
                tag = sub_item.get('tag', '')
                enabled = sub_item.get('enabled', True)
                quota_gb = 0
                try: quota_gb = float(sub_item.get('quota_gb', 0) or 0)
                except: quota_gb = 0
                probe_id = str(sub_item.get('probe_id') or sub_item.get('nezha_id', '')).strip()
                old_info = sub_item.get('info')
                
                lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
                http_links = []; direct_nodes = []; raw_content_parts = []

                for line in lines:
                    if line.startswith('http'):
                        http_links.append(line)
                    elif any(line.startswith(p) for p in ['vless://', 'vmess://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://', 'tuic://', 'anytls://', 'shadowtls://', 'stls://', 'naive+https://', 'naive+quic://', 'naive://', 'awg://', 'wireguard://']):
                        node = parse_uri(line)
                        if node: 
                            node['_tag'] = tag; node['_opt'] = enabled; direct_nodes.append(node)
                    else:
                        raw_content_parts.append(line)

                async def fetch_job(url):
                    async with sem:
                        try:
                            res = await fetch_single_url(session, url, int(cfg.get('timeout', 20)))
                            if isinstance(res, tuple) and len(res) == 2:
                                return res
                        except: pass
                        return "", None
                
                fetched_info = None
                if http_links:
                    fetch_results = await asyncio.gather(*[fetch_job(u) for u in http_links], return_exceptions=True)
                    for item in fetch_results:
                        if isinstance(item, tuple) and len(item) == 2:
                            text, info = item
                            if info and not fetched_info: fetched_info = info
                            if text: raw_content_parts.append(text)

                # 流量计算：优先使用探针实时数据 (Komari / 哪吒) -> 其次使用真实机场订阅信息 -> 自定义配额
                matched_probe = None
                matched_name = ""
                auto_matched = False
                is_probe_disabled = probe_id.lower() in ('__none__', 'none', 'off', 'disable', 'disabled')
                
                if is_probe_disabled:
                    sub_item['probe_id'] = '__none__'
                    sub_item['nezha_id'] = '__none__'
                    matched_probe = None
                    if old_info and isinstance(old_info, dict) and old_info.get('matched_probe'):
                        old_info = None
                elif probe_servers:
                    # 1. 优先使用用户手动填写的绑定进行容错匹配
                    if probe_id:
                        matched_probe, score, mc = find_best_probe_node([probe_id], probe_servers, min_threshold=0.78, is_explicit_id=True)
                    
                    # 2. 只有在用户未手动填写(留空)时，才执行自动智能容错匹配
                    if not matched_probe and not probe_id:
                        auto_cands = []
                        if tag and not is_generic_or_spec_only(tag):
                            auto_cands.append(tag)
                            stripped_argo = re.sub(r'[\-_\s]*argo[\-_\s]*', '', tag, flags=re.IGNORECASE).strip()
                            if stripped_argo and stripped_argo != tag and not is_generic_or_spec_only(stripped_argo):
                                auto_cands.append(stripped_argo)
                        for dn in direct_nodes[:6]:
                            dn_name = dn.get('name')
                            if dn_name and not is_generic_or_spec_only(dn_name):
                                auto_cands.append(dn_name)
                                dn_no_argo = re.sub(r'[\-_\s]*argo[\-_\s]*', '', dn_name, flags=re.IGNORECASE).strip()
                                if dn_no_argo and dn_no_argo != dn_name and not is_generic_or_spec_only(dn_no_argo):
                                    auto_cands.append(dn_no_argo)
                        
                        matched_probe, score, mc = find_best_probe_node(auto_cands, probe_servers, min_threshold=0.78, is_explicit_id=False)
                        if matched_probe:
                            auto_matched = True
                            matched_name = matched_probe.get('name') or matched_probe.get('uuid') or ''
                            if not probe_id:
                                sub_item['probe_id'] = matched_name
                                sub_item['nezha_id'] = matched_name

                if matched_probe:
                    if not matched_name:
                        matched_name = matched_probe.get('name') or matched_probe.get('uuid') or ''
                    used_bytes = int(matched_probe.get('used', 0))
                    limit_bytes = int(matched_probe.get('limit', 0))
                    probe_limit_gb = matched_probe.get('limit_gb', 0) or bytes_to_gb_smart(limit_bytes)

                    # 🌟 核心特性：探针若有总流量配额限制（如 1000GB / 10TB），自动匹配并填写至 VPS 总配额！
                    if quota_gb <= 0 and probe_limit_gb > 0:
                        quota_gb = probe_limit_gb
                        sub_item['quota_gb'] = probe_limit_gb

                    real_t = int(quota_gb * 1073741824) if quota_gb > 0 else (limit_bytes if limit_bytes > 0 else 0)
                    pct = min(100, int((used_bytes / real_t) * 100)) if real_t > 0 else 0
                    sub_item['info'] = {
                        "used": format_bytes_smart(used_bytes),
                        "used_bytes": used_bytes,
                        "total": format_bytes_smart(real_t) if real_t > 0 else "",
                        "total_bytes": real_t,
                        "percent": pct,
                        "has_total": real_t > 0,
                        "expire": "",
                        "color": "#dc3545" if pct >= 90 else ("#f59e0b" if pct >= 75 else "#10b981"),
                        "source": probe_type,
                        "matched_probe": matched_name,
                        "auto_matched": auto_matched
                    }
                elif is_probe_disabled:
                    # 显式不匹配探针：若有真实机场订阅信息保留，否则清空虚假探针流量
                    if fetched_info:
                        if quota_gb > 0:
                            real_t = int(quota_gb * 1073741824)
                            used_b = fetched_info.get('used_bytes', 0)
                            pct = min(100, int((used_b / real_t) * 100)) if real_t > 0 else 0
                            fetched_info['total'] = format_bytes_smart(real_t)
                            fetched_info['total_bytes'] = real_t
                            fetched_info['percent'] = pct
                            fetched_info['has_total'] = True
                            fetched_info['color'] = "#dc3545" if pct >= 90 else ("#f59e0b" if pct >= 75 else "#10b981")
                        sub_item['info'] = fetched_info
                    else:
                        sub_item['info'] = None
                elif fetched_info:
                    # 如果用户指定了该 VPS 的真实配额，使用用户设定的真实配额计算百分比
                    if quota_gb > 0:
                        real_t = int(quota_gb * 1073741824)
                        used_b = fetched_info.get('used_bytes', 0)
                        pct = min(100, int((used_b / real_t) * 100)) if real_t > 0 else 0
                        fetched_info['total'] = format_bytes_smart(real_t)
                        fetched_info['total_bytes'] = real_t
                        fetched_info['percent'] = pct
                        fetched_info['has_total'] = True
                        fetched_info['color'] = "#dc3545" if pct >= 90 else ("#f59e0b" if pct >= 75 else "#10b981")
                    sub_item['info'] = fetched_info
                elif old_info and isinstance(old_info, dict) and old_info.get('used_bytes', 0) > 0 and old_info.get('used') != 'VPS':
                    # 🌟 关键数据保护：若本次探针连接暂时未响应或解析中，但历史已有真实探针流量数据，保留历史真实数据，绝不抹除为 VPS！
                    if quota_gb > 0:
                        real_t = int(quota_gb * 1073741824)
                        used_b = old_info.get('used_bytes', 0)
                        pct = min(100, int((used_b / real_t) * 100)) if real_t > 0 else 0
                        old_info['total'] = format_bytes_smart(real_t)
                        old_info['total_bytes'] = real_t
                        old_info['percent'] = pct
                        old_info['has_total'] = True
                    sub_item['info'] = old_info
                elif quota_gb > 0:
                    # 纯自建 VPS 用户配置了总配额，无探针且无 HTTP 订阅且无历史真实数据
                    sub_item['info'] = {
                        "used": "0B",
                        "used_bytes": 0,
                        "total": f"{quota_gb:.0f}GB",
                        "total_bytes": int(quota_gb * 1073741824),
                        "percent": 0,
                        "has_total": True,
                        "expire": "",
                        "color": "#10b981",
                        "source": "custom"
                    }
                else:
                    # 普通 VPS 或无真实数据，直接清空，绝不展示虚假的 24TB 胶囊
                    sub_item['info'] = None

                if raw_content_parts:
                    combined_content = "\n".join(raw_content_parts)
                    decoded_nodes = decode_sub_content(combined_content)
                    for n in decoded_nodes:
                        if isinstance(n, dict):
                            n['_tag'] = tag; n['_opt'] = enabled; direct_nodes.append(n)
                
                return direct_nodes

            async with aiohttp.ClientSession(headers={'User-Agent': cfg.get('ua', 'v2rayNG/1.8.5')}) as session:
                tasks = [process_single_sub(session, sub) for sub in subs]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for res in results:
                    if isinstance(res, list): all_nodes.extend(res)
                    elif isinstance(res, Exception): write_log(f"Sub Error: {res}")
                
                unique = {}; valid_nodes = []
                for n in all_nodes:
                    if not isinstance(n, dict): continue
                    ports_fp = ''
                    if n.get('ports'): ports_fp = str(n.get('ports'))
                    elif n.get('server_ports'): ports_fp = ','.join([str(x) for x in n.get('server_ports')])
                    path_fp = n.get('ws-path') or n.get('grpc-name') or n.get('xhttp-path') or ''
                    host_fp = n.get('ws-host') or n.get('xhttp-host') or n.get('sni') or ''
                    name_fp = n.get('name') or ''
                    tag_fp = n.get('_tag') or ''
                    fp = f"{n.get('type')}|{n.get('uuid','')}|{n.get('password','')}|{n.get('server')}|{n.get('port')}|{ports_fp}|{path_fp}|{host_fp}|{name_fp}|{tag_fp}"
                    if fp not in unique: unique[fp] = n
                
                for n in unique.values():
                    n['_clean_name'] = await smart_identify_region(n, n.get('_tag', ''))
                    valid_nodes.append(n)
                    
                d['cached_nodes'] = valid_nodes
                # 安全合并：从磁盘重新读取最新数据，避免覆盖在异步期间新增或推送的订阅源
                latest_d = load_data()
                latest_subs = latest_d.get('remote_subs', [])
                sub_info_map = {s.get('tag', ''): s.get('info') for s in subs if s.get('tag')}
                sub_quota_map = {s.get('tag', ''): s.get('quota_gb') for s in subs if s.get('tag')}
                sub_probe_map = {s.get('tag', ''): (s.get('probe_id') or s.get('nezha_id')) for s in subs if s.get('tag') and (s.get('probe_id') or s.get('nezha_id'))}
                for ls in latest_subs:
                    ltag = ls.get('tag', '')
                    if ltag in sub_info_map:
                        ls['info'] = sub_info_map[ltag]
                    if ltag in sub_quota_map and sub_quota_map[ltag]:
                        ls['quota_gb'] = sub_quota_map[ltag]
                    if ltag in sub_probe_map:
                        p_val = sub_probe_map[ltag]
                        if p_val and (not (ls.get('probe_id') or ls.get('nezha_id')) or p_val == '__none__'):
                            ls['probe_id'] = p_val
                            ls['nezha_id'] = p_val
                
                latest_d['remote_subs'] = latest_subs
                latest_d['cached_nodes'] = valid_nodes
                if 'cached_probe_nodes' in d:
                    latest_d['cached_probe_nodes'] = d['cached_probe_nodes']
                d = latest_d
    except Exception as e:
        write_log(f"Subs Sync Fatal Error: {e}")
    finally:
        d['last_sync'] = int(time.time())
        save_data(d)
        save_cache()
        write_log(f"Sync End. Nodes: {len(d.get('cached_nodes', []))}")

def update_ips_with_separator(current_text, new_ips_list):
    manual_part = current_text.split(IP_SEPARATOR)[0].strip() if IP_SEPARATOR in current_text else current_text.strip()
    return f"{manual_part}\n\n{IP_SEPARATOR}\n" + "\n".join(new_ips_list)

def run_sync_thread(include_ip_fetch=True): 
    global IS_SYNCING
    if IS_SYNCING:
        write_log("Sync skipped: already running")
        return
    try:
        IS_SYNCING = True
        d = load_data()
        
        # 1. 如果配置了测速 API 地址，先行抓取并自动追加 IP 库
        if include_ip_fetch and d.get('cf_api_url'):
            api_url = str(d.get('cf_api_url', '')).strip()
            if api_url:
                write_log(f"Auto Fetching CF IPs from: {api_url}")
                ok, msg, extracted = fetch_cf_ips(api_url)
                if ok and extracted:
                    d['ips'] = update_ips_with_separator(d.get('ips', ''), extracted)
                    save_data(d)
                    write_log(f"CF IP Auto-Updated: {len(extracted)} IPs")
                else:
                    write_log(f"CF IP Auto-Fetch Failed: {msg}")
                    
        # 2. 异步处理订阅源
        asyncio.run(async_process_subs())
    except Exception as e:
        write_log(f"Sync Thread Error: {e}")
    finally:
        IS_SYNCING = False

def auto_sync_task():
    global IS_SYNCING
    write_log("Scheduler Started (v43.00)")
    while True:
        try:
            time.sleep(5)
            if IS_SYNCING: continue
            d = load_data()
            interval = int(d.get('config', {}).get('interval', 14400))
            last = int(d.get('last_sync', 0))
            now = time.time()
            if interval > 0 and (now - last) >= interval:
                write_log(f"Auto Sync Triggered (interval: {interval}s, elapsed: {int(now - last)}s)...")
                run_sync_thread(include_ip_fetch=True)
        except Exception as e:
            write_log(f"Scheduler Critical Error: {e}")
            time.sleep(30)
threading.Thread(target=auto_sync_task, daemon=True).start()

@app.before_request
def require_auth():
    allowed_prefixes = [f"/{LOGIN_PATH}", "/static", "/api/status", "/sub"]
    if any(request.path == p or request.path.startswith(p + '/') or request.path.startswith(p + '?') for p in allowed_prefixes):
        return None
    if not is_authenticated():
        if request.path.startswith('/api/'):
            return jsonify({"status": "error", "msg": "未授权访问，请先登录"}), 401
        return redirect(f"/{LOGIN_PATH}")

@app.route('/')
def root(): return redirect(f'/{LOGIN_PATH}')

@app.route(f'/{LOGIN_PATH}', methods=['GET', 'POST'])
def admin_entry():
    current_pwd = get_current_password()
    if request.method == 'POST':
        if request.form.get('password') == current_pwd:
            resp = make_response(redirect(f'/{LOGIN_PATH}'))
            resp.set_cookie('auth', current_pwd, max_age=86400*30, httponly=True, samesite='Lax')
            return resp
        return render_template('index.html', authorized=False)
    if is_authenticated():
        d = load_data()
        logs = ""
        if os.path.exists(LOG_FILE):
            try:
                with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                    logs = "".join(deque(f, maxlen=50))
            except: pass
        token = d.get('config', {}).get('sub_token') or current_pwd
        return render_template('index.html', authorized=True, data=d, node_count=len(d.get('cached_nodes',[])), logs=logs, sub_url=f"{request.url_root}sub?token={token}")
    return render_template('index.html', authorized=False)

@app.route('/logout')
def logout():
    resp = make_response(redirect(f'/{LOGIN_PATH}'))
    resp.delete_cookie('auth')
    return resp

@app.route('/login', methods=['POST'])
def login_compat(): return redirect(f'/{LOGIN_PATH}')

@app.route('/api/status', methods=['GET'])
def api_status():
    d = load_data()
    raw_ips = d.get('ips', '').splitlines()
    ip_list = [x.strip() for x in raw_ips if x.strip() and IP_SEPARATOR not in x and "#####" not in x]
    interval = int(d.get('config', {}).get('interval', 14400))
    last = int(d.get('last_sync', 0))
    ttl = 0
    if interval > 0: ttl = max(0, int((last + interval) - time.time()))
    return jsonify({
        "app_version": APP_VERSION,
        "last_sync": last,
        "ip_count": len(ip_list),
        "node_count": len(d.get('cached_nodes', [])),
        "is_syncing": IS_SYNCING,
        "ttl": ttl,
        "ips": d.get('ips', '')
    })

@app.route('/save', methods=['POST'])
def save():
    d = load_data()
    d['ips'] = request.form.get('ips', '')
    d['cf_api_url'] = request.form.get('cf_api_url', '')
    d['max_ips_per_node'] = int(request.form.get('max_ips_per_node', 0))
    d['clash_tpl'] = request.form.get('clash_tpl', 'proxies:\n#PLACEHOLDER#')
    d['singbox_tpl'] = request.form.get('singbox_tpl', DEFAULT_SINGBOX_TPL)
    d['config']['interval'] = int(request.form.get('cfg_interval', 14400))
    d['config']['threads'] = int(request.form.get('cfg_threads', 8))
    d['config']['timeout'] = int(request.form.get('cfg_timeout', 20))
    d['config']['ua'] = request.form.get('cfg_ua', 'v2rayNG/1.8.5')
    d['config']['sub_token'] = request.form.get('cfg_sub_token', '').strip() or get_current_password()
    d['config']['custom_groups'] = request.form.get('cfg_custom_groups', '').replace('，', ',')
    d['config']['probe_type'] = request.form.get('cfg_probe_type', 'komari').strip()
    d['config']['probe_url'] = request.form.get('cfg_probe_url', '').strip() or request.form.get('cfg_nezha_url', '').strip()
    d['config']['probe_token'] = request.form.get('cfg_probe_token', '').strip() or request.form.get('cfg_nezha_token', '').strip()
    d['config']['nezha_url'] = d['config']['probe_url']
    d['config']['nezha_token'] = d['config']['probe_token']
    
    new_web_password = request.form.get('cfg_web_password', '').strip()
    if new_web_password:
        d['config']['web_password'] = new_web_password
        
    urls = request.form.getlist('sub_urls[]')
    tags = request.form.getlist('sub_tags[]')
    enables = request.form.getlist('sub_enables[]')
    quotas = request.form.getlist('sub_quotas[]')
    probe_ids = request.form.getlist('sub_probe_ids[]')
    if not probe_ids:
        probe_ids = request.form.getlist('sub_nezha_ids[]')

    new_subs = []
    for i, u in enumerate(urls):
        if u.strip():
            old_info = d['remote_subs'][i].get('info') if i < len(d['remote_subs']) else None
            if isinstance(old_info, dict):
                tot = str(old_info.get('total', ''))
                exp = str(old_info.get('expire', ''))
                if '24576' in tot or '26388' in tot or '270' in exp or '267' in exp:
                    old_info = None
            is_enabled = (enables[i] == '1') if i < len(enables) else True
            q_val = 0
            if i < len(quotas) and quotas[i].strip():
                try: q_val = float(quotas[i].strip())
                except: q_val = 0
            pid_val = probe_ids[i].strip() if i < len(probe_ids) else ""
            if pid_val.lower() in ('__none__', 'none', 'off', 'disable', 'disabled'):
                pid_val = '__none__'
                if isinstance(old_info, dict) and old_info.get('matched_probe'):
                    old_info = None
            
            new_subs.append({
                "url": u.strip(),
                "tag": tags[i].strip(),
                "enabled": is_enabled,
                "quota_gb": q_val,
                "probe_id": pid_val,
                "nezha_id": pid_val,
                "info": old_info
            })
    d['remote_subs'] = new_subs
    save_data(d)
    threading.Thread(target=run_sync_thread, kwargs={"include_ip_fetch": True}).start()
    
    resp = make_response(redirect(f'/{LOGIN_PATH}?status=saved'))
    if new_web_password:
        resp.set_cookie('auth', new_web_password, max_age=86400*30, httponly=True, samesite='Lax')
    return resp

@app.route('/api/fetch_ips', methods=['POST'])
def api_fetch_ips():
    try:
        user_input = request.json.get('url', '').strip()
        if not user_input: return jsonify({"status":"error", "msg":"输入为空"})
        
        ok, msg, extracted = fetch_cf_ips(user_input)
        if not ok or not extracted:
            return jsonify({"status":"error", "msg": msg})
            
        d = load_data()
        d['ips'] = update_ips_with_separator(d.get('ips', ''), extracted)
        d['cf_api_url'] = user_input
        save_data(d)
        write_log(f"Manual IP Fetch Success: {len(extracted)} IPs")
        return jsonify({"status":"success", "count": len(extracted), "ips": d['ips']})
    except Exception as e: return jsonify({"status":"error", "msg":str(e)})

@app.route('/api/parse_csv_ips', methods=['POST'])
def api_parse_csv_ips():
    try:
        content = request.json.get('content', '').strip()
        limit = int(request.json.get('limit', 0))
        mode = request.json.get('mode', 'append')
        if not content: return jsonify({"status": "error", "msg": "内容为空"})
        
        ips = extract_speedtest_ips(content, limit=limit)
        if not ips:
            return jsonify({"status": "error", "msg": "未在内容中找到有效 IP 或测速记录"})
        
        d = load_data()
        if mode == 'overwrite':
            d['ips'] = "\n".join(ips)
        else:
            existing = [x.strip() for x in d.get('ips', '').splitlines() if x.strip()]
            for ip in ips:
                if ip not in existing:
                    existing.append(ip)
            d['ips'] = "\n".join(existing)
        save_data(d)
        return jsonify({"status": "success", "count": len(ips), "ips": d['ips']})
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)})

@app.route('/api/push_nodes', methods=['POST'])
def api_push_nodes():
    try:
        if not is_authenticated():
            return jsonify({"status": "error", "msg": "未授权访问，请提供正确的 Token 或密码"}), 401
        
        data_payload = request.get_json(silent=True) if request.is_json else (request.form or {})
        if not data_payload:
            data_payload = {}
        
        replace = data_payload.get('replace', True)
        if isinstance(replace, str):
            replace = replace.lower() not in ('false', '0', 'no')
        trigger_sync = data_payload.get('sync', True)
        if isinstance(trigger_sync, str):
            trigger_sync = trigger_sync.lower() not in ('false', '0', 'no')

        # 支持单源推送或多源批量推送 (sources: [...])
        sources_input = data_payload.get('sources')
        if not isinstance(sources_input, list) or not sources_input:
            single_tag = str(data_payload.get('tag', '')).strip()
            single_nodes = data_payload.get('nodes', '')
            if single_tag and single_nodes:
                sources_input = [{
                    "tag": single_tag,
                    "nodes": single_nodes,
                    "enabled": data_payload.get('enabled')
                }]
            else:
                sources_input = []

        if not sources_input:
            return jsonify({"status": "error", "msg": "缺少必要参数: tag/nodes 或 sources 列表"}), 400

        d = load_data()
        subs = d.get('remote_subs', [])
        processed_tags = []
        items_to_insert = []
        
        for s_item in sources_input:
            tag = str(s_item.get('tag', '')).strip()
            raw_nodes = s_item.get('nodes', '')
            if not tag or not raw_nodes:
                continue
                
            if isinstance(raw_nodes, list):
                nodes_list = [str(x).strip() for x in raw_nodes if str(x).strip()]
                nodes_str = "\n".join(nodes_list)
            else:
                nodes_str = str(raw_nodes).strip()
                nodes_list = [x.strip() for x in nodes_str.splitlines() if x.strip()]
            if not nodes_str:
                continue

            # 🌟 始终计算是否为 Argo 节点
            is_argo = ('argo' in tag.lower()) or ('argo' in nodes_str.lower())

            # 优选开关解析：优先显式传参；若未传，则根据节点/tag智能判断：argo 默认 True (开启优选)，非 argo 默认 False (关闭优选)
            item_enabled = s_item.get('enabled')
            if item_enabled is not None:
                if isinstance(item_enabled, str):
                    item_enabled = item_enabled.lower() in ('1', 'true', 'yes')
                else:
                    item_enabled = bool(item_enabled)
            else:
                item_enabled = is_argo

            # 检查是否已存在同名订阅源
            found_idx = -1
            for idx, s in enumerate(subs):
                if s.get('tag', '').strip() == tag:
                    found_idx = idx
                    break
                    
            if found_idx >= 0:
                existing_sub = subs.pop(found_idx)
                if replace:
                    existing_sub['url'] = nodes_str
                else:
                    old_url = existing_sub.get('url', '').strip()
                    existing_sub['url'] = f"{old_url}\n{nodes_str}".strip()
                existing_sub['enabled'] = item_enabled
                items_to_insert.append(existing_sub)
            else:
                new_sub = {
                    "url": nodes_str,
                    "tag": tag,
                    "enabled": item_enabled,
                    "quota_gb": 0,
                    "probe_id": "",
                    "nezha_id": "",
                    "info": None
                }
                # 如果是 Argo 独立订阅，自动尝试继承同 VPS 主订阅已有的探针与配额
                if is_argo:
                    base_tag = re.sub(r'[\-_\s]*argo[\-_\s]*', '', tag, flags=re.IGNORECASE).strip()
                    for s in (items_to_insert + subs):
                        if s.get('tag', '').strip() == base_tag or s.get('tag', '').strip().lower() == base_tag.lower():
                            if s.get('probe_id'):
                                new_sub['probe_id'] = s.get('probe_id')
                                new_sub['nezha_id'] = s.get('probe_id')
                            if s.get('quota_gb'):
                                new_sub['quota_gb'] = s.get('quota_gb')
                            if s.get('info') and isinstance(s.get('info'), dict) and s.get('info').get('used') != 'VPS':
                                new_sub['info'] = copy.deepcopy(s.get('info'))
                            break
                items_to_insert.append(new_sub)
                
            processed_tags.append(tag)

        if not processed_tags:
            return jsonify({"status": "error", "msg": "未提供有效的节点内容或订阅源名称"}), 400

        # 按照正向顺序置顶到 subs 最前面 (管理页面最上面)
        for item in reversed(items_to_insert):
            subs.insert(0, item)

        d['remote_subs'] = subs
        save_data(d)
        write_log(f"API Push: 成功推送并置顶订阅源: {', '.join(processed_tags)}")

        if trigger_sync:
            threading.Thread(target=run_sync_thread, kwargs={"include_ip_fetch": False}).start()

        return jsonify({
            "status": "success",
            "msg": f"成功推送并置顶订阅源【{', '.join(processed_tags)}】",
            "tags": processed_tags,
            "count": len(processed_tags)
        })
    except Exception as e:
        write_log(f"API Push Fatal Error: {e}")
        return jsonify({"status": "error", "msg": f"推送异常: {str(e)}"}), 500

@app.route('/api/delete_pushed_nodes', methods=['POST'])
def api_delete_pushed_nodes():
    try:
        if not is_authenticated():
            return jsonify({"status": "error", "msg": "未授权访问，请提供正确的 Token 或密码"}), 401

        data_payload = request.get_json(silent=True) if request.is_json else (request.form or {})
        if not data_payload:
            data_payload = {}

        tags_to_delete = data_payload.get('tags')
        if not isinstance(tags_to_delete, list):
            single_tag = str(data_payload.get('tag', '')).strip()
            tags_to_delete = [single_tag] if single_tag else []

        tags_to_delete = [str(t).strip() for t in tags_to_delete if str(t).strip()]
        if not tags_to_delete:
            return jsonify({"status": "error", "msg": "缺少必要参数: tag 或 tags 列表"}), 400

        d = load_data()
        subs = d.get('remote_subs', [])
        deleted_tags = []
        new_subs = []
        for s in subs:
            s_tag = s.get('tag', '').strip()
            if s_tag in tags_to_delete:
                deleted_tags.append(s_tag)
            else:
                new_subs.append(s)

        if deleted_tags:
            d['remote_subs'] = new_subs
            # 同步清理缓存节点中属于这些 tag 的节点
            cached = d.get('cached_nodes', [])
            d['cached_nodes'] = [n for n in cached if n.get('_tag', '').strip() not in deleted_tags]
            save_data(d)
            write_log(f"API Delete: 已成功注销并清理订阅源: {', '.join(deleted_tags)}")

            trigger_sync = data_payload.get('sync', True)
            if trigger_sync:
                threading.Thread(target=run_sync_thread, kwargs={"include_ip_fetch": False}).start()

            return jsonify({
                "status": "success",
                "msg": f"成功删除订阅源及关联节点【{', '.join(deleted_tags)}】",
                "deleted": deleted_tags
            })
        else:
            return jsonify({
                "status": "success",
                "msg": "未找到匹配的订阅源，无需删除",
                "deleted": []
            })
    except Exception as e:
        write_log(f"API Delete Fatal Error: {e}")
        return jsonify({"status": "error", "msg": f"删除异常: {str(e)}"}), 500

@app.route('/api/sync_subs', methods=['POST'])
def api_sync_subs():
    threading.Thread(target=run_sync_thread, kwargs={"include_ip_fetch": True}).start()
    return jsonify({"msg": "已触发全量同步任务（含优选 IP 与节点）"})

@app.route('/api/sync_single', methods=['POST'])
def api_sync_single():
    idx = request.json.get('index')
    d = load_data()
    subs = d.get('remote_subs', [])
    if idx is not None and 0 <= idx < len(subs):
        threading.Thread(target=run_sync_thread).start()
        return jsonify({"status": "ok", "msg": f"已触发【{subs[idx].get('tag') or '节点'}】同步"})
    return jsonify({"status": "error", "msg": "未找到指定订阅"})

@app.route('/api/logs', methods=['GET'])
def api_logs():
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                return "".join(deque(f, maxlen=50))
        except: pass
    return ""

@app.route('/api/nodes', methods=['GET'])
def api_nodes():
    nodes = copy.deepcopy(load_data().get('cached_nodes', []))
    for n in nodes:
        try:
            n['name'] = ensure_node_flag(n.get('name', ''), n.get('_tag', ''), n.get('server', ''))
            n['uri'] = gen_uri(n) or ''
        except:
            n['uri'] = ''
    return jsonify(nodes)

@app.route('/api/probe_nodes', methods=['GET'])
def api_probe_nodes():
    d = load_data()
    cached = d.get('cached_probe_nodes', [])
    force_refresh = request.args.get('refresh') == '1'
    if (not cached or force_refresh) and aiohttp:
        cfg = d.get('config', {})
        probe_type = str(cfg.get('probe_type', 'komari')).lower()
        probe_url = (cfg.get('probe_url') or cfg.get('nezha_url', '')).strip()
        probe_token = (cfg.get('probe_token') or cfg.get('nezha_token', '')).strip()
        if probe_url:
            try:
                async def _fetch():
                    async with aiohttp.ClientSession() as ps_session:
                        if probe_type == 'komari':
                            return await fetch_komari_stats(ps_session, probe_url, probe_token)
                        else:
                            return await fetch_nezha_stats(ps_session, probe_url, probe_token)
                res = asyncio.run(_fetch())
                if res:
                    unique_nodes_list = []
                    seen_nodes = set()
                    for v in res.values():
                        if isinstance(v, dict):
                            k = v.get('uuid') or v.get('id') or v.get('name')
                            if k and k not in seen_nodes:
                                seen_nodes.add(k)
                                p_name = str(v.get('name', ''))
                                p_country, p_flag = detect_country_info(p_name)
                                unique_nodes_list.append({
                                    "uuid": str(v.get('uuid', '')),
                                    "id": str(v.get('id', '')),
                                    "name": p_name,
                                    "used": v.get('used', 0),
                                    "limit": v.get('limit', 0),
                                    "limit_gb": v.get('limit_gb', 0),
                                    "country": p_country,
                                    "flag": p_flag
                                })
                    d['cached_probe_nodes'] = unique_nodes_list
                    save_data(d)
                    return jsonify(unique_nodes_list)
            except Exception as e:
                write_log(f"API Probe Nodes Fetch Error: {e}")
    return jsonify(cached)

@app.route('/api/auto_match_all', methods=['POST'])
def api_auto_match_all():
    """一键智能容错匹配所有订阅源对应的探针节点及总配额，并持久化保存至 data.json"""
    d = load_data()
    subs = d.get('remote_subs', [])
    cfg = d.get('config', {})
    probe_type = str(cfg.get('probe_type', 'komari')).lower()
    probe_url = (cfg.get('probe_url') or cfg.get('nezha_url', '')).strip()
    probe_token = (cfg.get('probe_token') or cfg.get('nezha_token', '')).strip()
    
    probe_servers = {}
    if probe_url and aiohttp:
        try:
            async def _fetch():
                async with aiohttp.ClientSession() as ps_session:
                    if probe_type == 'komari':
                        return await fetch_komari_stats(ps_session, probe_url, probe_token)
                    else:
                        return await fetch_nezha_stats(ps_session, probe_url, probe_token)
            probe_servers = asyncio.run(_fetch())
        except Exception as e:
            write_log(f"Auto Match All Fetch Error: {e}")
            
    if not probe_servers and d.get('cached_probe_nodes'):
        for pn in d['cached_probe_nodes']:
            probe_servers[pn.get('name', '')] = pn
            if pn.get('uuid'): probe_servers[pn['uuid']] = pn

    if not probe_servers:
        return jsonify({"status": "error", "message": "未连接到探针或未配置探针地址，请在高级参数中检查探针配置"})
        
    matched_count = 0
    match_details = []
    
    for sub in subs:
        tag = sub.get('tag', '')
        raw_text = sub.get('url', '')
        current_probe = str(sub.get('probe_id') or sub.get('nezha_id', '')).strip()
        current_quota = 0
        try: current_quota = float(sub.get('quota_gb', 0) or 0)
        except: current_quota = 0
        
        # 🌟 关键：如果用户已明确指定“不匹配探针”(__none__)，严格跳过！
        if current_probe.lower() in ('__none__', 'none', 'off', 'disable', 'disabled'):
            sub['probe_id'] = '__none__'
            sub['nezha_id'] = '__none__'
            if sub.get('info') and sub['info'].get('matched_probe'):
                sub['info'] = None
            continue
        
        cands = []
        if tag and not is_generic_or_spec_only(tag):
            cands.append(tag)
            stripped_argo = re.sub(r'[\-_\s]*argo[\-_\s]*', '', tag, flags=re.IGNORECASE).strip()
            if stripped_argo and stripped_argo != tag and not is_generic_or_spec_only(stripped_argo):
                cands.append(stripped_argo)
        for line in raw_text.splitlines():
            line = line.strip()
            if '#' in line:
                m_part = line.split('#')[-1].split('&')[0].strip()
                if m_part and not is_generic_or_spec_only(m_part):
                    cands.append(m_part)
                    m_no_argo = re.sub(r'[\-_\s]*argo[\-_\s]*', '', m_part, flags=re.IGNORECASE).strip()
                    if m_no_argo and m_no_argo != m_part and not is_generic_or_spec_only(m_no_argo):
                        cands.append(m_no_argo)
                
        best_e, score, mc = find_best_probe_node(cands, probe_servers, min_threshold=0.78, is_explicit_id=False)
        if best_e:
            matched_name = best_e.get('name') or best_e.get('uuid') or ''
            sub['probe_id'] = matched_name
            sub['nezha_id'] = matched_name
            
            p_limit_gb = best_e.get('limit_gb', 0)
            if (current_quota <= 0) and p_limit_gb > 0:
                sub['quota_gb'] = p_limit_gb
                current_quota = p_limit_gb

            # 🌟 立即更新该订阅的分组流量胶囊与进度条
            used_bytes = int(best_e.get('used', 0))
            limit_bytes = int(best_e.get('limit', 0))
            real_t = int(current_quota * 1073741824) if current_quota > 0 else (limit_bytes if limit_bytes > 0 else 0)
            pct = min(100, int((used_bytes / real_t) * 100)) if real_t > 0 else 0
            sub['info'] = {
                "used": format_bytes_smart(used_bytes),
                "used_bytes": used_bytes,
                "total": format_bytes_smart(real_t) if real_t > 0 else "",
                "total_bytes": real_t,
                "percent": pct,
                "has_total": real_t > 0,
                "expire": "",
                "color": "#dc3545" if pct >= 90 else ("#f59e0b" if pct >= 75 else "#10b981"),
                "source": probe_type,
                "matched_probe": matched_name,
                "auto_matched": True
            }
                
            matched_count += 1
            match_details.append({
                "tag": tag,
                "matched": matched_name,
                "quota_gb": sub.get('quota_gb', 0),
                "score": round(score, 3)
            })
        else:
            # 未匹配到高置信度探针：若此前是自动匹配残留的，清除错误探针数据
            if sub.get('info') and sub['info'].get('auto_matched'):
                sub['info'] = None
                if not current_probe:
                    sub['probe_id'] = ''
                    sub['nezha_id'] = ''
            
    d['remote_subs'] = subs
    save_data(d)
    threading.Thread(target=run_sync_thread, kwargs={"include_ip_fetch": False}).start()
    return jsonify({
        "status": "ok",
        "matched_count": matched_count,
        "details": match_details,
        "subs": subs
    })

@app.route('/api/node_delete', methods=['POST'])
def api_node_delete():
    idx = request.json.get('index')
    d = load_data()
    if 0 <= idx < len(d.get('cached_nodes', [])):
        del d['cached_nodes'][idx]
        save_data(d)
        return jsonify({"status": "ok"})
    return jsonify({"status": "error"})

@app.route('/api/snapshot_dl')
def snapshot_dl():
    mem = io.BytesIO()
    with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as zf:
        if os.path.exists(DATA_FILE): zf.write(DATA_FILE, 'data.json')
    mem.seek(0)
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    return send_file(mem, as_attachment=True, download_name=f"cf_backup_{ts}.zip", mimetype='application/zip')

@app.route('/api/export_json')
def export_json():
    d = load_data()
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    resp = make_response(json.dumps(d, indent=2, ensure_ascii=False))
    resp.headers['Content-Type'] = 'application/json; charset=utf-8'
    resp.headers['Content-Disposition'] = f"attachment; filename=cf_backup_{ts}.json"
    return resp

@app.route('/api/snapshot_restore', methods=['POST'])
def snapshot_restore():
    f = request.files.get('file')
    if not f or not f.filename:
        return jsonify({"status": "error", "msg": "未选择上传的备份文件"}), 400
    try:
        filename = f.filename.lower()
        if filename.endswith('.json'):
            raw_content = f.read().decode('utf-8', errors='ignore')
            data_obj = json.loads(raw_content)
            if not isinstance(data_obj, dict):
                return jsonify({"status": "error", "msg": "无效的 JSON 配置文件内容"}), 400
            save_data(data_obj)
            save_cache()
            write_log("Config restored successfully from uploaded JSON file")
            return jsonify({"status": "ok", "msg": "配置已成功从 JSON 备份文件还原！"})
        elif filename.endswith('.zip'):
            with zipfile.ZipFile(f) as zf:
                for member in zf.infolist():
                    target_path = os.path.abspath(os.path.join(DATA_DIR, member.filename))
                    if not target_path.startswith(os.path.abspath(DATA_DIR)):
                        return jsonify({"status": "error", "msg": "压缩包包含非法路径"}), 400
                    zf.extract(member, DATA_DIR)
            save_cache()
            write_log("Config restored successfully from uploaded ZIP backup")
            return jsonify({"status": "ok", "msg": "配置已成功从 ZIP 压缩包还原！"})
        else:
            file_bytes = f.read()
            try:
                data_obj = json.loads(file_bytes.decode('utf-8', errors='ignore'))
                if isinstance(data_obj, dict):
                    save_data(data_obj)
                    save_cache()
                    write_log("Config restored successfully from file content")
                    return jsonify({"status": "ok", "msg": "配置已成功还原！"})
            except: pass
            return jsonify({"status": "error", "msg": "仅支持上传 .zip 压缩包或 .json 数据文件"}), 400
    except Exception as e:
        write_log(f"Restore failed: {e}")
        return jsonify({"status": "error", "msg": f"还原失败: {e}"}), 500

@app.route('/sub')
def sub():
    d = load_data()
    token = request.args.get('token')
    correct_token = d.get('config', {}).get('sub_token') or get_current_password()
    if SUB_TOKEN_CHECK and token != correct_token: return "Access Denied", 403
    
    nodes = d.get('cached_nodes', [])
    raw_ips = d.get('ips', '').splitlines()
    ips = [x.strip() for x in raw_ips if x.strip() and IP_SEPARATOR not in x and "#####" not in x]
    
    flag = request.args.get('flag', '')
    raw_mode = request.args.get('raw') == '1'
    
    filter_kw = request.args.get('filter', '')
    exclude_kw = request.args.get('exclude', '')
    
    final_list = []
    pool = ips
    if d.get('max_ips_per_node', 0) > 0 and len(ips) > d.get('max_ips_per_node'):
        pool = random.sample(ips, d.get('max_ips_per_node'))

    tag_counters = {}

    for n in nodes:
        if not isinstance(n, dict) or 'type' not in n: continue
        name = n.get('name', 'node')
        
        tag = n.get('_tag', '')
        clean_name = n.get('_clean_name', '')
        search_target = f"{name} {tag} {clean_name}"
        
        if filter_kw and not re.search(re.escape(filter_kw), search_target, re.IGNORECASE): continue
        if exclude_kw and re.search(re.escape(exclude_kw), search_target, re.IGNORECASE): continue
        
        if tag not in tag_counters: tag_counters[tag] = 1
        
        node_name_base = clean_name if clean_name else name
        if tag and tag not in node_name_base: node_name_base = f"{node_name_base} {tag}"
        node_name_base = f"{node_name_base} {str(tag_counters[tag]).zfill(2)}"
        node_name_base = ensure_node_flag(node_name_base, tag, n.get('server', ''))
        
        target_ips = [None]
        if not raw_mode:
            is_opt_enable = n.get('_opt', True)
            is_protocol_support = n['type'] in ['vless', 'vmess', 'trojan'] and n.get('network') in ['ws', 'grpc', 'xhttp', 'splithttp']
            if n.get('reality'): is_protocol_support = False
            
            if is_opt_enable and is_protocol_support and ips:
                target_ips = pool
        
        for i, ip_str in enumerate(target_ips):
            ip = None; port = None
            if ip_str:
                ip, custom_port = split_host_port(ip_str)
                if custom_port:
                    port = custom_port
                else: 
                    is_secure = n.get('tls') or n.get('reality') or n['type'] in ['trojan', 'hysteria2', 'tuic']
                    if n['type'] == 'ss' and n.get('plugin_opts', {}).get('tls'): is_secure = True
                    port = 443 if is_secure else 80
                port = int(port)
            
            node_name = node_name_base
            if not raw_mode and len(target_ips) > 1: node_name = f"{node_name_base}-{i+1}"
            node_name = ensure_node_flag(node_name, tag, n.get('server', ''))
            
            obj = None
            if flag == 'clash': obj = gen_clash(n, ip, port, node_name)
            elif flag == 'singbox': obj = gen_singbox(n, ip, port, node_name)
            else: obj = gen_uri(n, ip, port, node_name)
            if obj: final_list.append(obj)
            if len(final_list) >= MAX_NODES_OUTPUT: break
        tag_counters[tag] += 1
        if len(final_list) >= MAX_NODES_OUTPUT: break

    filename = "subs"
    if filter_kw: filename += f"_{filter_kw}"
    filename = urllib.parse.quote(filename)
    
    headers = {}
    if flag in ['clash', 'openclash', 'meta']:
        if not yaml: return "PyYAML missing", 500
        y_str = yaml.dump(final_list, allow_unicode=True, sort_keys=False)
        format_mode = (request.args.get('format') or '').strip().lower()
        tpl = d.get('clash_tpl', '').strip()
        if format_mode == 'provider':
            tpl = "proxies:\n#PLACEHOLDER#"
        elif not tpl or tpl == "proxies:\n#PLACEHOLDER#":
            tpl = DEFAULT_OPENCLASH_TPL

        if "#PLACEHOLDER#" not in tpl: tpl += "\nproxies:\n#PLACEHOLDER#"
        y_str_indented = "\n".join(["  " + l for l in y_str.splitlines()])
        names = "\n".join([f"      - {n['name']}" for n in final_list])
        resp_data = tpl.replace("#PLACEHOLDER#", y_str_indented).replace("#PLACEHOLDER_NAMES#", names)
        headers = {'Content-Type': 'text/yaml; charset=utf-8', 'Content-Disposition': f'inline; filename={filename}.yaml'}
    elif flag == 'singbox':
        format_mode = request.args.get('format', 'full')
        if format_mode == 'outbounds':
            resp_data = json.dumps(final_list, indent=2, ensure_ascii=False)
        else:
            tpl_str = d.get('singbox_tpl') or DEFAULT_SINGBOX_TPL
            try:
                tpl_obj = json.loads(tpl_str)
            except Exception:
                tpl_obj = json.loads(DEFAULT_SINGBOX_TPL)
            
            node_tags = [n['tag'] for n in final_list if isinstance(n, dict) and 'tag' in n]
            
            selector_outbounds = ["♻️ 自动选择", "🎯 全球直连"] + node_tags
            selector_group = {
                "type": "selector",
                "tag": "🚀 节点选择",
                "outbounds": selector_outbounds,
                "default": "♻️ 自动选择" if node_tags else "🎯 全球直连"
            }
            
            urltest_group = {
                "type": "urltest",
                "tag": "♻️ 自动选择",
                "outbounds": node_tags if node_tags else ["🎯 全球直连"],
                "url": "https://www.gstatic.com/generate_204",
                "interval": "3m",
                "tolerance": 50
            }
            
            base_outbounds = [
                {"type": "direct", "tag": "🎯 全球直连"},
                {"type": "block", "tag": "🛑 全球拦截"},
                {"type": "dns", "tag": "dns-out"}
            ]
            
            tpl_obj['outbounds'] = [selector_group, urltest_group] + final_list + base_outbounds
            resp_data = json.dumps(tpl_obj, indent=2, ensure_ascii=False)
            
        headers = {'Content-Type': 'application/json; charset=utf-8', 'Content-Disposition': f'inline; filename={filename}.json'}
    else:
        resp_data = base64.b64encode("\n".join(final_list).encode()).decode()
        headers = {'Content-Type': 'text/plain', 'Content-Disposition': f'inline; filename={filename}.txt'}
    
    return Response(resp_data, headers=headers)

if __name__ == '__main__':
    if not os.path.exists(DATA_DIR): os.makedirs(DATA_DIR, exist_ok=True)
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
