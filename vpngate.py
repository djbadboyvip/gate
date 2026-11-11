#!/usr/bin/env python3
"""
VPN Gate SSTP 节点检测流水线 (精简版 + 多数据源 v2)
=================================================
流程:
  1. 获取 VPN Gate 原始节点 (多源合并, 不再是官方 API 失败才回退)
  2. 只保留带 TCP 入口的 SSTP 节点
  3. 去重
  4. 并发调用检测 Worker
  5. 获取并合并优选域名与优选 API (Cloudflare 入口)
  6. 生成 public/data.json + public/index.html + public/nodes.txt

v2 改动 (只加数据源, 其余功能原样保留):
  - CSV 源: 官方 API (http/https) + GeorgeXie 镜像的官方 CSV (jsDelivr / raw)
  - JSON 源: fdciabdul (原 VPNGATE_MIRROR) + GeorgeXie servers.json (单次快照)
            + GeorgeXie pool/servers.json (7 天滚动池, 补 US/PL/欧洲稀疏国家)
  - GeorgeXie 先读 latest.json 取 data_commit 再拉锁定版本, 并校验 SHA-256
  - 池子 (pool/servers.json) 的节点没有内嵌 OpenVPN 配置, 配置在
    pool/configs/<sha256>.json 里 (每个 13.5KB); 本脚本不逐个拉配置,
    直接用池节点自带的 probe_targets[0].port 合成最小 TCP 配置
    (proto tcp + remote), 再由检测 Worker 实测 SSTP 是否真通.
    probe_reason 为 udp / 无 TCP 端口的池节点直接跳过.
  - 默认只测目标国家 VPNGATE_COUNTRIES=US,PL,DE,FR,GB,NL,ES,IT,HK,SG
    (设为空字符串则恢复全部国家; JP/KR 不在默认里, 因为池子里 JP 1854 / KR 1678
     个会把 Worker 检查量撑爆, 需要时自己加 JP,KR)
  - 实测数据 (2026-11-11, GeorgeXie):
      单次快照 99 节点/10 国: US 1, IT 1, JP 44, KR 33, 无 PL/DE/FR/GB/NL/ES/HK/SG
      7 天池 4952 节点: US 138, PL 2, DE 4, FR 8, GB 16, NL 5, ES 3, IT 2, HK 3, SG 1
      所以 PL/欧洲想出节点, 必须拉 pool, 单次快照基本是 0
"""

import base64
import csv
import hashlib
import io
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import quote

import requests

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
REPO_DIR = os.path.dirname(os.path.abspath(__file__))

VPNGATE_API = os.environ.get("VPNGATE_API", "http://www.vpngate.net/api/iphone/")
VPNGATE_MIRROR = os.environ.get(
    "VPNGATE_MIRROR",
    "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
)

# --- v2 新增: 多数据源 (都可用环境变量整体覆盖, 逗号分隔) ---
def _env_list(name, default):
    raw = os.environ.get(name)
    if raw is None:
        return list(default)
    return [x.strip() for x in raw.split(",") if x.strip()]

# CSV 源: 格式与官方 API 完全一致, 直接走 parse_csv, 无需适配
VPNGATE_CSV_SOURCES = _env_list("VPNGATE_CSV_SOURCES", [
    VPNGATE_API,
    "https://www.vpngate.net/api/iphone/",
    "https://cdn.jsdelivr.net/gh/GeorgeXie2333/vpngate-list-mirror@latest/data/vpngate.csv",
    "https://raw.githubusercontent.com/GeorgeXie2333/vpngate-list-mirror/main/data/vpngate.csv",
])

# JSON 源: 格式各不相同, 走 parse_mirror_json / parse_georgexie_json 做适配
# 注意: pool/servers.json 约 7MB、4952 个节点, 拉取时 HTTP_TIMEOUT 要够
VPNGATE_JSON_SOURCES = _env_list("VPNGATE_JSON_SOURCES", [
    VPNGATE_MIRROR,
    "https://cdn.jsdelivr.net/gh/GeorgeXie2333/vpngate-list-mirror@latest/data/servers.json",
    "https://cdn.jsdelivr.net/gh/GeorgeXie2333/vpngate-list-mirror@latest/pool/servers.json",
])

GEORGEXIE_LATEST_URL = os.environ.get(
    "GEORGEXIE_LATEST_URL",
    "https://raw.githubusercontent.com/GeorgeXie2333/vpngate-list-mirror/main/latest.json",
)
GEORGEXIE_POOL_LATEST_URL = os.environ.get(
    "GEORGEXIE_POOL_LATEST_URL",
    "https://raw.githubusercontent.com/GeorgeXie2333/vpngate-list-mirror/main/pool/latest.json",
)
# 1=合并所有成功源 (默认, 稀疏国家只能靠合并才有数); 0=旧行为, 第一个成功就停
VPNGATE_MERGE = os.environ.get("VPNGATE_MERGE", "1") not in ("0", "false", "no", "")
# 1=拉 GeorgeXie 锁定 commit 的快照做校验 (默认开); 0=只用上面列表里的 @latest
GEORGEXIE_USE_LOCKED = os.environ.get("GEORGEXIE_USE_LOCKED", "1") not in ("0", "false", "no", "")

# 目标国家: 默认 US + PL + 欧洲 + HK/SG; 为空则不过滤 (恢复旧行为, 全量)
# JP/KR 默认不在里面, 原因见文件头注释; 需要就加, 如 "US,PL,DE,FR,GB,JP,KR"
_raw_countries = os.environ.get("VPNGATE_COUNTRIES", "US,PL,DE,FR,GB,NL,ES,IT,HK,SG")
TARGET_COUNTRIES = set()
if _raw_countries.strip():
    for _c in _raw_countries.split(","):
        _c = _c.strip().upper()
        if _c == "UK":
            _c = "GB"
        if _c:
            TARGET_COUNTRIES.add(_c)

WORKER_CHECK_URL = os.environ.get("CHECK_WORKER", "https://你的域名/check?sstp=vpn:vpn@")
CONCURRENCY = max(1, int(os.environ.get("CHECK_CONCURRENCY", "32")))
CHECK_TIMEOUT = float(os.environ.get("CHECK_TIMEOUT", "90"))
MAX_CHECK_NODES = int(os.environ.get("MAX_CHECK_NODES", "0"))
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "60"))
PUBLIC_DIR = os.environ.get("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))
TEMPLATE_HTML = os.path.join(REPO_DIR, "web", "index.html")

DATA_CENTER_ORG_KEYWORDS = [
    "GOOGLE", "AMAZON", "AWS", "MICROSOFT", "OVH", "HETZNER", "DIGITALOCEAN",
    "AKAMAI", "CLOUDFLARE", "FASTLY", "RACKSPACE", "EQUINIX", "LINODE", "VULTR",
    "HURRICANE", "TENCENT", "ALIBABA", "ALIYUN", "LEASWEB",
]
RESIDENTIAL_ORG_KEYWORDS = [
    "NTT EAST", "NTT WEST", "NTT COMMUNICATIONS", "NTT BROADBAND", "KDDI", "DOCOMO",
    "SOFTBANK", "AU COMMUNICATIONS", "J:COM", "JCOM", "OCN", "BIGLOBE",
    "IIJ", "SEIKO", "CLEVER-NET", "AT&T", "COMCAST", "XFINITY", "VERIZON",
    "TELUS", "ROGERS", "BELL CANADA", "VODAFONE", "ORANGE", "DEUTSCHE TELEKOM",
    "BREEZE", "TIM S.P.A", "LIBERO", "FASTWEB", "FREE FRANCE", "BT OPEN",
]

COUNTRY_ZH = {
    "JP": "日本", "KR": "韩国", "US": "美国", "CA": "加拿大", "RU": "俄罗斯",
    "RO": "罗马尼亚", "TH": "泰国", "VN": "越南", "DE": "德国", "FR": "法国",
    "GB": "英国", "UK": "英国", "SG": "新加坡", "TW": "台湾", "HK": "香港",
    "CN": "中国", "AU": "澳大利亚", "NL": "荷兰", "SE": "瑞典", "CH": "瑞士",
    "IT": "意大利", "ES": "西班牙", "PL": "波兰", "IN": "印度", "BR": "巴西",
    "MX": "墨西哥", "ID": "印度尼西亚", "MY": "马来西亚", "PH": "菲律宾",
    "TR": "土耳其", "UA": "乌克兰", "CZ": "捷克", "GR": "希腊", "PT": "葡萄牙",
    "FI": "芬兰", "NO": "挪威", "DK": "丹麦", "IE": "爱尔兰", "BE": "比利时",
    "AT": "奥地利", "HU": "匈牙利", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚",
    "NZ": "新西兰", "ZA": "南非", "IL": "以色列", "AE": "阿联酋", "SA": "沙特",
    "EG": "埃及", "HR": "克罗地亚", "BY": "白俄罗斯", "GD": "格林纳达",
    "LV": "拉脱维亚", "EE": "爱沙尼亚", "LT": "立陶宛", "SK": "斯洛伐克",
    "SI": "斯洛文尼亚", "BG": "保加利亚", "RS": "塞尔维亚", "GE": "格鲁吉亚",
    "MD": "摩尔多瓦", "AM": "亚美尼亚", "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦",
    "MN": "蒙古", "NP": "尼泊尔", "LK": "斯里兰卡", "MM": "缅甸",
}

# 静态优选域名池
EDGE_HOSTS = [
    h.strip()
    for h in os.environ.get(
        "EDGE_HOSTS",
        "saas.sin.fan:443,cdn.204910.best:443,www.mfyx.cn:443,p.etime.vip:443,cdn.ctn32.us.kg:443,cf.877774.xyz:443,spring.io:443,"
        "cf.nyanya.moe:443,www.sloomb.com:443,op.chinwa.eu.cc:443,www.leics.police.uk:443,securecircle.com:443,www.shopify.com:443,"
        "www.carousell.sg:443,www.dbs.com.sg:443,openai.com:443,linear.app:443,www.bilibili.com:443,uspto.gov:443,www.vmware.com:443",
    ).split(",")
    if h.strip()
]

# 优选 API 地址配置 (支持逗号分隔多个，可配置在 GitHub Action Secret / Env 中)
fallback_apis = [
    "https://cf.090227.xyz/ct?ips=6&port=443",
    "https://cf.090227.xyz/cmcc?ips=8"
]
OPTIMAL_API = os.environ.get("OPTIMAL_API") or fallback_apis[0]

NODES_URL = os.environ.get("NODES_URL", "https://djbadboyvip.github.io/gate/nodes.txt")

# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------
_section = None

def log(section, msg=""):
    global _section
    if section != _section:
        print(f"========== {section} ==========")
        _section = section
    if msg:
        print(msg, flush=True)

def die(msg):
    log("FATAL", f"[失败] {msg}")
    sys.exit(1)

# ---------------------------------------------------------------------------
# 数据抓取
# ---------------------------------------------------------------------------
def _fetch_text(session, url, timeout=None):
    resp = session.get(url, timeout=(timeout or HTTP_TIMEOUT),
                       headers={"User-Agent": "Mozilla/5.0 (compatible; gate-checker)"})
    resp.raise_for_status()
    return resp

def _fetch_csv_source(session, url):
    resp = _fetch_text(session, url)
    rows = parse_csv(resp.text)
    return rows

def _fetch_json_source(session, url):
    resp = _fetch_text(session, url)
    data = resp.json()
    # GeorgeXie 的 servers.json / pool/servers.json 字段名不同, 先走专用解析
    rows = parse_georgexie_json(data)
    if rows:
        return rows
    return parse_mirror_json(data)

def fetch_georgexie_locked(session):
    """读 latest.json 取 data_commit, 拉锁定版本的 servers.json 并校验 SHA-256.

    返回 (rows, source_label), 失败返回 ([], "") —— 不致命, 调用方继续走 @latest.
    已实测 2026-11-11: latest.json 里 files["data/servers.json"]["sha256"]
    = 22113ab2170b78a254f9c5e3c3f23dc7a97f58167040396715b07da2b434465.
    """
    try:
        idx = _fetch_text(session, GEORGEXIE_LATEST_URL).json()
        commit = str(idx.get("data_commit") or "").strip()
        files = idx.get("files") or {}
        want_sha = str((files.get("data/servers.json") or {}).get("sha256") or "").lower()
        if not commit or len(commit) != 40:
            log("GEORGEXIE", "latest.json 里没有合法的 data_commit, 跳过锁定快照")
            return [], ""
        candidates = [
            f"https://cdn.jsdelivr.net/gh/GeorgeXie2333/vpngate-list-mirror@{commit}/data/servers.json",
            f"https://raw.githubusercontent.com/GeorgeXie2333/vpngate-list-mirror/{commit}/data/servers.json",
        ]
        for url in candidates:
            try:
                resp = _fetch_text(session, url)
                if want_sha:
                    got_sha = hashlib.sha256(resp.content).hexdigest()
                    if got_sha != want_sha:
                        log("GEORGEXIE", f"锁定快照 SHA-256 不符 ({url[:60]}...), 跳过该候选")
                        continue
                rows = parse_georgexie_json(resp.json())
                if rows:
                    log("GEORGEXIE", f"锁定快照 commit {commit[:8]} 获取到 {len(rows)} 个节点")
                    return rows, f"georgexie-locked@{commit[:8]}"
            except Exception as exc:
                log("GEORGEXIE", f"锁定快照候选失败 {url[:60]}...: {exc}")
        return [], ""
    except Exception as exc:
        log("GEORGEXIE", f"读 latest.json 失败: {exc}")
        return [], ""

def fetch_vpngate():
    """多源合并抓取 (v2): CSV 源 + JSON 源 + GeorgeXie 锁定快照, 全部去重后返回.

    旧行为是官方 API 成功就直接返回、失败才试镜像; 新行为默认合并所有成功源,
    因为单次快照里 US 只有 1 个、PL/DE/FR/GB 经常是 0, 只有加上 7 天 pool
    才能在目标国家拿到数. 想恢复旧行为: VPNGATE_MERGE=0.
    返回 (rows, source_label), rows 已按 TARGET_COUNTRIES 过滤 (为空则不过滤).
    """
    session = requests.Session()
    all_rows = []
    used = []

    # 1) GeorgeXie 锁定快照 (有 SHA 校验, 最可信的镜像快照)
    if GEORGEXIE_USE_LOCKED:
        rows, label = fetch_georgexie_locked(session)
        if rows:
            all_rows.extend(rows)
            used.append(label)

    # 2) CSV 源 (官方 + GeorgeXie CSV, 格式一致)
    for url in VPNGATE_CSV_SOURCES:
        try:
            rows = _fetch_csv_source(session, url)
            if rows:
                log("VPN GATE", f"CSV 源 {url} 获取到 {len(rows)} 个原始节点")
                all_rows.extend(rows)
                used.append(url)
                if not VPNGATE_MERGE:
                    break
            else:
                log("VPN GATE", f"CSV 源 {url} 返回 0 行, 跳过")
        except Exception as exc:
            log("VPN GATE", f"CSV 源失败 {url}: {exc}")

    # 3) JSON 源 (fdciabdul + GeorgeXie servers.json + pool/servers.json)
    for url in VPNGATE_JSON_SOURCES:
        try:
            rows = _fetch_json_source(session, url)
            if rows:
                log("VPN GATE", f"JSON 源 {url} 获取到 {len(rows)} 个原始节点")
                all_rows.extend(rows)
                used.append(url)
                if not VPNGATE_MERGE:
                    break
            else:
                log("VPN GATE", f"JSON 源 {url} 返回 0 行, 跳过")
        except Exception as exc:
            log("VPN GATE", f"JSON 源失败 {url}: {exc}")

    if not all_rows:
        die("所有 VPN Gate 数据源均不可用, 数据源完全失败")

    # 去重: 同一个 host+ip 只留一条 (多源是同一份官方数据的不同托管, 重叠很大)
    seen = set()
    uniq = []
    for r in all_rows:
        key = ((r.get("host") or "").lower(), (r.get("ip") or ""))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(r)
    log("VPN GATE", f"多源合并: 原始 {len(all_rows)} -> 去重后 {len(uniq)}")

    # 目标国家过滤 (只影响本次测试量, 不改节点本身)
    if TARGET_COUNTRIES:
        before = len(uniq)
        uniq = [r for r in uniq
                if (r.get("country_short") or "").upper().replace("UK", "GB") in TARGET_COUNTRIES]
        log("VPN GATE", f"目标国家过滤 {sorted(TARGET_COUNTRIES)}: {before} -> {len(uniq)}")
        # 每个目标国家各有几个, 一眼看出 PL/欧洲有没有数
        counts = {}
        for r in uniq:
            counts[r.get("country_short") or "?"] = counts.get(r.get("country_short") or "?", 0) + 1
        log("VPN GATE", f"目标国家分布: {counts}")
        if not uniq:
            log("VPN GATE", "过滤后 0 个节点: 本轮快照+池子里目标国家都没有, "
                            "这是常态 (PL 单次常为 0, 靠 pool 7 天累积), 下次再跑或放宽 VPNGATE_COUNTRIES")

    source = "merged:" + "+".join(used) if used else "vpngate-merged"
    return uniq, source

def parse_csv(text):
    lines = [ln for ln in text.splitlines() if ln.strip()]
    header_idx = None
    for i, ln in enumerate(lines):
        if ln.lstrip("#").startswith("HostName"):
            header_idx = i
            break
    if header_idx is None:
        raise RuntimeError("找不到 CSV 表头行 (HostName)")

    header = lines[header_idx].lstrip("#").split(",")
    data_lines = lines[header_idx + 1:]
    idx = {}
    for col in ("hostname", "ip", "countrylong", "countryshort", "openvpn_configdata_base64"):
        for i, h in enumerate(header):
            if h.strip().lstrip("*").lower() == col:
                idx[col] = i
                break
    if "openvpn_configdata_base64" not in idx:
        for i, h in enumerate(header):
            if "base64" in h.lower():
                idx["openvpn_configdata_base64"] = i
                break
    pos = {
        "hostname": idx.get("hostname", 0),
        "ip": idx.get("ip", 1),
        "countrylong": idx.get("countrylong", 5),
        "countryshort": idx.get("countryshort", 6),
        "openvpn_configdata_base64": idx.get("openvpn_configdata_base64", len(header) - 1),
    }

    rows = []
    for ln in data_lines:
        fields = next(csv.reader(io.StringIO(ln)))
        if len(fields) < 7: continue
        host = fields[pos["hostname"]].strip()
        ip = fields[pos["ip"]].strip()
        if not host or not ip: continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": fields[pos["countrylong"]].strip(),
            "country_short": fields[pos["countryshort"]].strip(),
            "config_b64": fields[pos["openvpn_configdata_base64"]].strip(),
        })
    return rows

def _synth_tcp_config(ip, port):
    """给只有探测端口、没有内嵌配置的池节点合成最小 OpenVPN 配置.

    只含 to_sstp_nodes() 需要的两行 (proto tcp + remote), 其余什么都没有.
    SSTP 端口是否真的通, 由后面的检测 Worker 实测决定, 这里不作断言.
    """
    text = f"proto tcp\nremote {ip} {port}\n"
    return base64.b64encode(text.encode("utf-8")).decode("ascii")

def parse_georgexie_json(data):
    """GeorgeXie servers.json / pool/servers.json 专用解析.

    实测结构 (2026-11-11), 两种格式:
    - servers.json (单次快照): {"servers": [{"country_code": "JP",
      "country_name": "Japan", "hostname": "vpn961954281",
      "ip": "126.214.179.9", "openvpn_config_base64": "IyMj...", ...}]}
      内嵌配置, 直接用.
    - pool/servers.json (7 天池): 同样字段, 但 *没有* openvpn_config_base64,
      只有 config.path (如 pool/configs/<sha256>.json, 每个 13.5KB, 逐个拉
      90 个目标节点要多发 90 次请求) 和 probe_targets / tcp_probe.
      已实测: PL 节点 vpn191172008 的 probe_targets=[{"ip": ..., "port": 1382}],
      DE 节点 port 443, GB 节点 port 1708, 与 OpenVPN 配置里的 TCP remote 端口
      同一量级. 所以池节点不用拉配置文件, 直接用 probe_targets[0].port
      合成最小配置, 交给 to_sstp_nodes() + Worker 实测过滤.
      probe_reason == "udp" / probe_targets 为空的节点没有 TCP 端口,
      不能做 SSTP, 直接跳过 (不计入 rows).
    不是这个结构时返回 [], 调用方再走 parse_mirror_json.
    """
    servers = []
    if isinstance(data, dict) and isinstance(data.get("servers"), list):
        # 只有含 country_code / openvpn_config_base64 的才是 GeorgeXie 格式
        sample = data["servers"][:1]
        if sample and ("country_code" in sample[0] or "openvpn_config_base64" in sample[0]):
            servers = data["servers"]
        else:
            return []
    elif isinstance(data, list):
        return []
    else:
        return []
    rows = []
    for s in servers:
        if not isinstance(s, dict):
            continue
        host = str(s.get("hostname") or s.get("host") or "").strip()
        ip = str(s.get("ip") or "").strip()
        if not host or not ip:
            continue
        config_b64 = str(s.get("openvpn_config_base64")
                         or s.get("openvpn_configdata_base64")
                         or s.get("config_b64") or "").strip()
        if not config_b64:
            # 池格式: 从探测到的 TCP 端口合成最小配置 (见函数头注释)
            port = None
            targets = s.get("probe_targets") or []
            if targets and isinstance(targets, list):
                for t in targets:
                    if isinstance(t, dict) and t.get("port"):
                        try:
                            port = int(t["port"])
                        except (TypeError, ValueError):
                            port = None
                        break
            if port is None:
                ep = (s.get("tcp_probe") or {}).get("connected_endpoint") or {}
                if isinstance(ep, dict) and ep.get("port"):
                    try:
                        port = int(ep["port"])
                    except (TypeError, ValueError):
                        port = None
            if port is None or not (1 <= port <= 65535):
                continue
            config_b64 = _synth_tcp_config(ip, port)
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": str(s.get("country_name") or s.get("countrylong") or "").strip(),
            "country_short": str(s.get("country_code") or s.get("countryshort") or "").strip(),
            "config_b64": config_b64,
        })
    return rows

def parse_mirror_json(data):
    servers = []
    items = data if isinstance(data, list) else [data]
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("servers"), list):
            servers.extend(item["servers"])
        elif isinstance(item, dict):
            servers.append(item)
    rows = []
    for s in servers:
        host = str(s.get("hostname") or s.get("host") or "").strip()
        ip = str(s.get("ip") or "").strip()
        if not host or not ip: continue
        # v2: 兼容 GeorgeXie 的字段别名 country_code / country_name /
        # openvpn_config_base64 (fdciabdul 原字段仍优先)
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": str(s.get("countrylong") or s.get("country_long")
                                or s.get("country_name") or s.get("country") or "").strip(),
            "country_short": str(s.get("countryshort") or s.get("country_short")
                                 or s.get("country_code") or "").strip(),
            "config_b64": str(s.get("openvpn_configdata_base64")
                              or s.get("openvpn_config_base64")
                              or s.get("config_b64") or "").strip(),
        })
    return rows

# ---------------------------------------------------------------------------
# 优选 API 获取与解析
# ---------------------------------------------------------------------------
def fetch_optimal_api_endpoints(api_urls_str):
    """
    拉取优选 API，解析如: 172.66.1.179:443#CF 电信优选 格式的内容
    提取出纯 'IP:端口' (例如 172.66.1.179:443)
    """
    if not api_urls_str.strip():
        return []

    endpoints = []
    urls = [u.strip() for u in api_urls_str.split(",") if u.strip()]
    for url in urls:
        try:
            log("OPTIMAL API", f"请求优选 API: {url}")
            resp = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                lines = resp.text.strip().splitlines()
                count = 0
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # 剥离 # 后的备注，提取 IP:端口
                    endpoint = line.split("#")[0].strip()
                    if endpoint:
                        # 补充缺失端口默认 443
                        if ":" not in endpoint:
                            endpoint = f"{endpoint}:443"
                        endpoints.append(endpoint)
                        count += 1
                log("OPTIMAL API", f"成功从 API 获取到 {count} 个优选端点")
            else:
                log("OPTIMAL API", f"API 返回状态码异常: {resp.status_code}")
        except Exception as e:
            log("OPTIMAL API", f"拉取优选 API 失败 ({url}): {e}")
    return endpoints

def get_combined_edge_hosts():
    """
    合并静态优选域名与优选 API 端点
    """
    # 1. 优先读取 HOSTS_ENTRY 或 EDGE_HOSTS
    _entry = os.environ.get("HOSTS_ENTRY", "").strip()
    static_hosts = [e.strip() for e in _entry.split(",") if e.strip()] if _entry else EDGE_HOSTS

    # 2. 拉取优选 API 端点
    api_hosts = fetch_optimal_api_endpoints(OPTIMAL_API)

    # 3. 合并与去重 (保留原始列表顺序)
    combined = []
    seen = set()
    for h in static_hosts + api_hosts:
        if h and h not in seen:
            seen.add(h)
            combined.append(h)

    log("EDGE POOL", f"汇总入口地址池: 静态域名 {len(static_hosts)} 个, API 获取 {len(api_hosts)} 个, 合并有效入口共 {len(combined)} 个")
    return combined if combined else EDGE_HOSTS

# ---------------------------------------------------------------------------
# 筛选 SSTP 节点
# ---------------------------------------------------------------------------
_PROTO_TCP_RE = re.compile(r"^proto\s+(tcp|tcp4|tcp6)\b", re.M)
_REMOTE_RE = re.compile(r"^remote\s+\S+\s+(\d+)", re.M)

def to_sstp_nodes(rows):
    nodes = []
    for r in rows:
        cfg = ""
        if r["config_b64"]:
            try:
                cfg = base64.b64decode(r["config_b64"], validate=False).decode("utf-8", "replace")
            except Exception:
                cfg = ""
        if not _PROTO_TCP_RE.search(cfg): continue
        m = _REMOTE_RE.search(cfg)
        if not m: continue
        port = int(m.group(1))
        if not (1 <= port <= 65535): continue
        host = r["host"]
        if not host.endswith(".opengw.net"):
            host = f"{host}.opengw.net"
        nodes.append({"host": host, "port": port, "ip": r["ip"], "country": r["country_long"], "country_code": r["country_short"]})
    return nodes

def dedupe(nodes):
    seen = set()
    out = []
    for n in nodes:
        key = (n["host"].lower(), n["port"], "sstp")
        if key in seen: continue
        seen.add(key)
        out.append(n)
    return out

# ---------------------------------------------------------------------------
# 检测 Worker
# ---------------------------------------------------------------------------
def classify_network(host, exit_org, is_datacenter=None):
    if is_datacenter is True: return "datacenter"
    if is_datacenter is False: return "residential"
    org = (exit_org or "").upper()
    if org:
        if any(k in org for k in DATA_CENTER_ORG_KEYWORDS): return "datacenter"
        if any(k in org for k in RESIDENTIAL_ORG_KEYWORDS): return "residential"
    h = host.lower()
    if h.startswith("public-vpn"): return "datacenter"
    if re.match(r"^vpn\d{5,}", h) or re.match(r"^vpnv\d+", h): return "residential"
    return "unknown"

def check_one(node, session):
    url = WORKER_CHECK_URL + quote(f"{node['host']}:{node['port']}", safe="")
    out = dict(node)
    out["protocol"] = "sstp"
    out["link"] = f"sstp://vpn:vpn@{node['host']}:{node['port']}"
    out["status"] = "failed"
    out["checked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out["exit"] = None
    out["residential"] = "unknown"
    try:
        r = session.get(url, timeout=CHECK_TIMEOUT, headers={"User-Agent": "Mozilla/5.0 (gate-checker)"})
        if r.status_code != 200:
            out["error"] = f"HTTP {r.status_code}"
            out["worker_error"] = True
            return out
        j = r.json()
        ok = bool(j.get("success"))
        out["success"] = ok
        out["status"] = "success" if ok else "failed"
        out["latency_ms"] = j.get("responseTime")
        out["colo"] = j.get("colo")
        out["error"] = (None if ok else (j.get("error") or j.get("message") or "check failed"))
        exit_info = j.get("exit") or {}
        if exit_info:
            asn = exit_info.get("asn") or {}
            org = asn.get("org") or asn.get("name") or ""
            out["exit"] = {
                "ip": exit_info.get("ip"),
                "country": exit_info.get("country"),
                "country_code": exit_info.get("country_code"),
                "city": exit_info.get("city"),
                "continent": exit_info.get("continent"),
                "asn": asn.get("asn"),
                "org": org,
                "type": asn.get("type"),
                "is_datacenter": exit_info.get("is_datacenter"),
            }
            out["residential"] = classify_network(out["host"], org, exit_info.get("is_datacenter"))
        else:
            out["residential"] = classify_network(out["host"], None, None)
        return out
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["worker_error"] = True
        return out

def check_all(nodes, session):
    results = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(check_one, n, session) for n in nodes]
        for fut in as_completed(futures):
            results.append(fut.result())
    return results

# ---------------------------------------------------------------------------
# 生成数据
# ---------------------------------------------------------------------------
def build_outputs(results, raw_count, sstp_count, source):
    available = [r for r in results if r.get("success")]
    countries = {}
    for n in available:
        c = n["country"] or "未知"
        countries.setdefault(c, {"code": n["country_code"] or "?", "nodes": []})["nodes"].append(n)

    stats = {
        "raw_nodes": raw_count,
        "sstp_nodes": sstp_count,
        "checked": len(results),
        "success": len(available),
        "failed": len(results) - len(available),
        "countries": len(countries),
        "residential_est": sum(1 for n in available if n["residential"] == "residential"),
        "datacenter_est": sum(1 for n in available if n["residential"] == "datacenter"),
    }
    by_country = {}
    for name, grp in countries.items():
        grp["count"] = len(grp["nodes"])
        grp["residential"] = sum(1 for n in grp["nodes"] if n["residential"] == "residential")
        grp["datacenter"] = sum(1 for n in grp["nodes"] if n["residential"] == "datacenter")
        grp["nodes"].sort(key=lambda n: (n.get("latency_ms") is None, n.get("latency_ms") or 0, n["host"]))
        by_country[name] = grp

    data = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": source,
        "worker": WORKER_CHECK_URL,
        "stats": stats,
        "countries": by_country,
        "available": available,
    }
    return data

def build_nodes_text(data, edge_hosts):
    """
    生成纯节点行版本 (无注释): 每行 = 入口地址#名字$sstp://...
    """
    countries = data["countries"]
    edge = edge_hosts
    lines = []
    idx = 0
    ordered = sorted(countries.items(), key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])))
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        nodes = sorted(grp["nodes"], key=lambda n: (0 if n.get("residential") == "residential" else 1, n.get("latency_ms") is None, n.get("latency_ms") or 0, n.get("host") or ""))
        res_nodes = [n for n in nodes if n.get("residential") == "residential"]
        dc_nodes = [n for n in nodes if n.get("residential") != "residential"]
        for i, n in enumerate(res_nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            lines.append(f"{entry}#{zh}-住宅-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
        for i, n in enumerate(dc_nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            lines.append(f"{entry}#{zh}-机房-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
    return "\n".join(lines) + "\n"

def write_outputs(data, edge_hosts):
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    data_path = os.path.join(PUBLIC_DIR, "data.json")
    with open(data_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)

    html_path = os.path.join(PUBLIC_DIR, "index.html")
    if os.path.exists(TEMPLATE_HTML):
        with open(TEMPLATE_HTML, "r", encoding="utf-8") as f:
            html = f.read()
    else:
        html = (
            "<html><head><meta charset='utf-8'><title>VPN Gate SSTP 节点</title></head>"
            "<body><h1>VPN Gate SSTP 节点</h1><pre id='out'></pre></body>"
            "<script>fetch('data.json').then(r=>r.json()).then(d=>out.textContent=JSON.stringify(d.stats)).catch(e=>out.textContent='加载失败:'+e)</script></html>"
        )
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    nodes_path = os.path.join(PUBLIC_DIR, "nodes.txt")
    with open(nodes_path, "w", encoding="utf-8") as f:
        f.write(build_nodes_text(data, edge_hosts))

    return data_path, html_path, nodes_path

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    session = requests.Session()
    rows, source = fetch_vpngate()
    raw_count = len(rows)
    if raw_count == 0:
        die("VPN Gate 返回 0 个原始节点 (数据源异常, 不允许生成空结果)")

    sstp_nodes = to_sstp_nodes(rows)
    sstp_count = len(sstp_nodes)
    if sstp_count == 0:
        die(f"从 {raw_count} 个原始节点中没有解析出任何 SSTP(TCP) 节点 — 数据格式可能已变化, 需要人工适配")
    uniq = dedupe(sstp_nodes)

    if MAX_CHECK_NODES > 0:
        uniq = uniq[:MAX_CHECK_NODES]

    log("VPN GATE", f"获取原始节点: {raw_count}")
    log("VPN GATE", f"SSTP 节点: {sstp_count}")
    log("VPN GATE", f"去重后: {len(uniq)}")

    log("CLOUDFLARE WORKER", f"提交检测: {len(uniq)} (并发 {CONCURRENCY}, 单请求超时 {CHECK_TIMEOUT}s)")
    t0 = time.time()
    results = check_all(uniq, session)
    elapsed = time.time() - t0

    success = [r for r in results if r.get("success")]
    failed = [r for r in results if not r.get("success")]
    worker_errors = [r for r in failed if r.get("worker_error")]

    log("CLOUDFLARE WORKER", f"检测成功: {len(success)}")
    log("CLOUDFLARE WORKER", f"检测失败: {len(failed)}" + (f" (其中 Worker 异常 {len(worker_errors)})" if worker_errors else ""))
    log("CLOUDFLARE WORKER", f"耗时: {elapsed:.1f}s")

    if uniq and not success and len(worker_errors) == len(uniq):
        die("Worker 全部请求异常, 检测服务不可用 — 本次运行判定失败 (不生成空结果)")

    data = build_outputs(results, raw_count, sstp_count, source)
    log("RESULT", f"可用节点: {len(success)}")
    log("RESULT", f"国家数量: {data['stats']['countries']}")

    # 动态拉取 API 并与静态优选域名混合
    edge_hosts = get_combined_edge_hosts()

    data_path, html_path, nodes_path = write_outputs(data, edge_hosts)
    log("WEBSITE", f"生成 {os.path.relpath(data_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(html_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(nodes_path, REPO_DIR)}")
    log("USAGE", f"自动轮换: 把 {NODES_URL} 填入 edgetunnel 后台「自定义优选IP」框 (一次配置, 之后自动更新)")
    log("WEBSITE", "完成 (GitHub Pages 部署由 workflow 执行)")

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"程序异常: {type(exc).__name__}: {exc}")
