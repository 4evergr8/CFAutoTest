# -*- coding: utf-8 -*-
"""
cron: 0 0,2,4,6,8,10,12,14,16,18,20,22 * * *
new Env('CF 域名优选')

CF 优选域名延迟筛选

流程: 下载域名列表 -> DoT 解析 IPv4 -> 只保留 CF 网段 -> 并发 TLS 握手(SNI=域名)
      每个 IP 测 N 次取平均, 域名取各 IP 最小 -> 排序取前 N -> 写 txt/csv -> 上传 GitHub Release

环境变量:
    GITHUB_REPO   owner/repo, 例 4evergr8/CFAutoTest
    GITHUB_TOKEN  有 repo 权限的 PAT
    RELEASE_TAG   Release 标签, 默认 latest
    RELEASE_NAME  Release 标题, 可选
    PROXY         局域网 clash, 例 192.168.123.100:7890
    SNI           TLS 握手用的 SNI, 留空则用域名自身
"""
import asyncio
import csv
import ipaddress
import json
import os
import socket
import ssl
import struct
import sys
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

# ============================================================
#                      可配置参数
# ============================================================

SOURCE_URL = "https://raw.githubusercontent.com/cmliu/CF-Pages-BestCF/main/cf_domains.txt"
PORT = 443

# 域名解析走 DoT (tls://host:port, 端口默认 853)
DNS = "tls://223.5.5.5"
DNS_SNI = "dns.alidns.com"    # 证书校验用的 SNI, 留空则用 DNS 里的主机名
DNS_TIMEOUT = 5.0             # 单次查询超时(秒)
DNS_CONCURRENCY = 10          # 查询并发, 每次新建 TLS 连接, 太高会被限流

PING_ATTEMPTS = 3             # 每个 IP 测几次, 取平均值作为该 IP 成绩
PING_TIMEOUT_MS = 2000        # 单次 TLS 握手超时(含完整握手, 别设太小)
PING_CONCURRENCY = 50         # 并发数(TLS 握手吃 CPU, 太高会虚高)

LATENCY_MAX_MS = 800          # 延迟上限, 超过的不入选(含 TLS, 比纯 RTT 大 3-5 倍)
TOP_N = 15                    # 最终取前几个

# 只测落在这些网段里的 A 记录(Cloudflare 官方 ips-v4)
CF_CIDRS = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]

OUT_DIR = "."                 # 输出目录(相对脚本所在目录)
OUT_TXT = "cf_domains_result.txt"
OUT_CSV = "cf_domains_result.csv"
LIST_FILE = "cf_domains.txt"

# 下载顺序: 裸连 -> 局域网 clash -> GitHub 反代(按列表顺序)
PROXY = os.environ.get("PROXY", "192.168.123.100:7890").strip()   # 局域网 clash, 置空则跳过
PROXY_URL = f"http://{PROXY}" if PROXY else ""
SNI = os.environ.get("SNI", "").strip()                           # 握手用的 SNI, 留空则用域名自身
GITHUB_MIRRORS = [
    "https://ghfast.top/",
    "https://gh-proxy.com/",
    "https://ghproxy.net/",
]
NET_TIMEOUT = 15.0

GITHUB_REPO = os.environ.get("GITHUB_REPO", "")        # 例: 4evergr8/CFAutoTest
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")      # 需要 repo 权限的 PAT
RELEASE_TAG = os.environ.get("RELEASE_TAG", "latest")  # 固定 tag, 每次覆盖里面的附件
RELEASE_NAME = os.environ.get("RELEASE_NAME", "CF Domain Top")
API_TIMEOUT = 15.0

# ============================================================

BASE = Path(__file__).resolve().parent
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

TLS_CTX = ssl.create_default_context()
CF_NETS = [ipaddress.ip_network(c) for c in CF_CIDRS]

_u = urlparse(DNS)
if _u.scheme != "tls":
    raise SystemExit(f"DNS 只支持 tls:// 形式, 当前: {DNS}")
DNS_HOST = _u.hostname
DNS_PORT = _u.port or 853
DNS_SNI = DNS_SNI or DNS_HOST


def skip_name(b, i):
    """跳过 DNS 报文里的域名(含压缩指针)"""
    while True:
        n = b[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:
            return i + 2
        i += 1 + n


def dns_a(dom):
    """DoT 查询 A 记录, 返回 IP 列表"""
    q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    for p in dom.rstrip(".").split("."):
        q += bytes([len(p)]) + p.encode()
    q += b"\x00" + struct.pack(">HH", 1, 1)

    with socket.create_connection((DNS_HOST, DNS_PORT), DNS_TIMEOUT) as s:
        with TLS_CTX.wrap_socket(s, server_hostname=DNS_SNI) as ss:
            ss.sendall(struct.pack(">H", len(q)) + q)
            n = struct.unpack(">H", ss.recv(2))[0]
            buf = b""
            while len(buf) < n:
                buf += ss.recv(n - len(buf))

    qd, an = struct.unpack(">HH", buf[4:8])
    i = 12
    for _ in range(qd):
        i = skip_name(buf, i) + 4
    ips = []
    for _ in range(an):
        i = skip_name(buf, i)
        typ, _, _, rdlen = struct.unpack(">HHIH", buf[i:i + 10])
        i += 10
        if typ == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(buf[i:i + 4]))
        i += rdlen
    return ips


def is_cf(ip):
    a = ipaddress.ip_address(ip)
    return any(a in n for n in CF_NETS)


def download():
    """按顺序尝试: 裸连 -> 局域网 clash -> GitHub 反代, 第一个成功的返回"""
    plans = [(SOURCE_URL, {}, "裸连")]
    if PROXY_URL:
        plans.append((SOURCE_URL, {"http": PROXY_URL, "https": PROXY_URL}, f"clash {PROXY}"))
    for m in GITHUB_MIRRORS:
        plans.append((m + SOURCE_URL, {}, f"反代 {urlparse(m).netloc}"))

    last = None
    for url, proxies, name in plans:
        op = urllib.request.build_opener(urllib.request.ProxyHandler(proxies))
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
        try:
            with op.open(req, timeout=NET_TIMEOUT) as r:
                data = r.read()
            if data:
                print(f"[下载] {name} 成功, {len(data)} 字节")
                return data
        except Exception as e:
            last = e
            print(f"[下载] {name} 失败: {type(e).__name__}: {e}")
    raise RuntimeError(f"列表下载失败: {last}")


def fetch(req, timeout=NET_TIMEOUT):
    """先走代理, 失败再直连, 各尝试一次。返回 (status, body, err)"""
    plans = []
    if PROXY_URL:
        plans.append(({"http": PROXY_URL, "https": PROXY_URL}, "代理"))
    plans.append(({}, "直连"))

    def clone():
        r = urllib.request.Request(req.full_url, data=req.data, method=req.get_method())
        for k, v in req.header_items():
            r.add_header(k, v)
        for k, v in getattr(req, "unredirected_hdrs", {}).items():
            r.add_unredirected_header(k, v)
        return r

    last = None
    for proxies, name in plans:
        op = urllib.request.build_opener(urllib.request.ProxyHandler(proxies))
        try:
            with op.open(clone(), timeout=timeout) as r:
                return r.status, r.read(), None
        except urllib.error.HTTPError as e:
            return e.code, e.read(), None
        except Exception as e:
            last = e
            print(f"[网络] {name}失败: {type(e).__name__}: {e}")
    return None, b"", last


async def probe(dom, sem, dns_sem):
    """每个 IP 测 N 次取平均作为该 IP 成绩, 域名取所有 IP 成绩里的最小值"""
    async with sem:
        try:
            loop = asyncio.get_running_loop()
            async with dns_sem:
                ips = await loop.run_in_executor(None, dns_a, dom)
        except Exception as e:
            return {"domain": dom, "ip": "", "ping_ms": None,
                    "status": f"dns_{type(e).__name__}"}
        ips = [ip for ip in ips if is_cf(ip)]
        if not ips:
            return {"domain": dom, "ip": "", "ping_ms": None, "status": "not_cf"}

        best, best_ip, err = None, "", ""
        for ip in ips:
            vals = []
            for _ in range(PING_ATTEMPTS):
                t0 = time.perf_counter()
                try:
                    _, w = await asyncio.wait_for(
                        asyncio.open_connection(ip, PORT, ssl=TLS_CTX, server_hostname=SNI or dom),
                        PING_TIMEOUT_MS / 1000)
                    vals.append((time.perf_counter() - t0) * 1000)
                    w.close()
                    try:
                        await asyncio.wait_for(w.wait_closed(), 0.3)
                    except Exception:
                        pass
                except Exception as e:
                    err = type(e).__name__
            if not vals:
                continue
            avg = sum(vals) / len(vals)
            if best is None or avg < best:
                best, best_ip = avg, ip
        if best is None:
            return {"domain": dom, "ip": ips[0], "ping_ms": None,
                    "status": err or "fail"}
        return {"domain": dom, "ip": best_ip, "ping_ms": best, "status": "ok"}


async def run(domains):
    sem = asyncio.Semaphore(PING_CONCURRENCY)
    dns_sem = asyncio.Semaphore(DNS_CONCURRENCY)
    tasks = [asyncio.create_task(probe(d, sem, dns_sem)) for d in domains]
    out = []
    for i, t in enumerate(asyncio.as_completed(tasks), 1):
        r = await t
        out.append(r)
        ms = f"{r['ping_ms']:.1f}ms" if r["ping_ms"] is not None else "-"
        print(f"[{i:>3}/{len(domains)}] {r['domain']:<36}{r['ip']:<16}{ms:>9}  {r['status']}",
              flush=True)
    return out


def main():
    try:
        stage = "启动"
        t0 = time.perf_counter()

        print("=" * 68)
        print("CF 优选域名延迟筛选")
        print(f"  列表来源  : {SOURCE_URL}")
        print(f"  DNS 解析  : {DNS} (DoT, SNI {DNS_SNI})")
        print(f"  入选条件  : 解析到 CF 网段 且 TLS 握手 <= {LATENCY_MAX_MS} ms, 取前 {TOP_N} 个")
        print(f"  测试方式  : 每个 IP 测 {PING_ATTEMPTS} 次取平均, 域名取各 IP 最小, 并发 {PING_CONCURRENCY}")
        print(f"  握手 SNI  : {SNI or '域名自身'}")
        print(f"  单次超时  : {PING_TIMEOUT_MS} ms")
        print(f"  网络代理  : {PROXY_URL or '未配置'}")
        print(f"  反代列表  : {', '.join(urlparse(m).netloc for m in GITHUB_MIRRORS) or '无'}")
        if GITHUB_REPO and GITHUB_TOKEN:
            print(f"  Release   : {GITHUB_REPO} @ {RELEASE_TAG}")
        else:
            print(f"  Release   : 未配置 (需 GITHUB_REPO / GITHUB_TOKEN)")
        print("=" * 68 + "\n")

        # ---- 1. 下载列表 ----
        stage = "下载列表"
        list_path = BASE / LIST_FILE
        data = download()
        list_path.write_bytes(data)
        print()

        # ---- 2. 解析去重 ----
        stage = "解析列表"
        domains = []
        for line in data.decode("utf-8", "ignore").splitlines():
            d = line.strip()
            if d and not d.startswith("#") and d not in domains:
                domains.append(d)
        if not domains:
            raise RuntimeError("列表里没有任何域名")
        print(f"[解析] 待测 {len(domains)} 个域名\n")

        # ---- 3. 并发测延迟 ----
        stage = "测延迟"
        rows = asyncio.run(run(domains))

        # ---- 4. 排序取前 N ----
        stage = "筛选"
        cand = [r for r in rows if r["ping_ms"] is not None and r["ping_ms"] <= LATENCY_MAX_MS]
        cand.sort(key=lambda x: x["ping_ms"])
        picked = cand[:TOP_N]
        for r in picked:
            r["selected"] = True
        print(f"\n[筛选] 可达且 <= {LATENCY_MAX_MS}ms: {len(cand)} 个, 取前 {len(picked)} 个\n")

        # ---- 5. 写文件 ----
        stage = "写文件"
        out_dir = BASE / OUT_DIR
        out_dir.mkdir(parents=True, exist_ok=True)
        txt_path = out_dir / OUT_TXT
        csv_path = out_dir / OUT_CSV

        with txt_path.open("w", encoding="utf-8") as f:
            for r in picked:
                f.write(f"{r['domain']}#{r['domain']} {r['ping_ms']:.1f}\n")

        with csv_path.open("w", encoding="utf-8-sig", newline="") as f:
            w = csv.writer(f)
            w.writerow(["domain", "ip", "ping_ms", "status", "selected"])
            for r in rows:
                w.writerow([r["domain"], r["ip"],
                            f"{r['ping_ms']:.1f}" if r["ping_ms"] is not None else "",
                            r["status"], "Y" if r.get("selected") else "N"])

        print(f"{'=' * 68}")
        for i, r in enumerate(picked, 1):
            print(f"  {i:>2}. {r['domain']:<36}{r['ip']:<16}{r['ping_ms']:>7.1f} ms")
        print(f"{'=' * 68}")
        print(f"完成 | 耗时 {time.perf_counter() - t0:.1f}s | "
              f"共测 {len(rows)} 个 | 入选 {len(picked)} 个")
        print(f"txt: {txt_path}")
        print(f"csv: {csv_path}")

        # ---- 6. 上传到 GitHub Release ----
        stage = "上传 Release"
        if not (GITHUB_REPO and GITHUB_TOKEN):
            print("\n[release] 未配置 GITHUB_REPO / GITHUB_TOKEN, 跳过上传")
            return

        lines = [
            f"耗时 {time.perf_counter() - t0:.1f}s | 共测 {len(rows)} 个域名 | "
            f"入选 {len(picked)} 个 (TLS 握手 <= {LATENCY_MAX_MS}ms, 仅 CF 网段)",
            "",
        ]
        for r in picked:
            lines.append(f"`{r['domain']}` {r['ping_ms']:.1f} ms")
        summary = "\n".join(lines)

        api = f"https://api.github.com/repos/{GITHUB_REPO}"
        hdr = {
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": UA,
        }

        def gh(path, method="GET", payload=None, raw=None, ctype=None):
            url = path if path.startswith("http") else api + path
            data = raw if raw is not None else (
                json.dumps(payload).encode() if payload is not None else None)
            rq = urllib.request.Request(url, data=data, method=method)
            for k, v in hdr.items():
                rq.add_header(k, v)
            if ctype:
                rq.add_header("Content-Type", ctype)
            st, body, err = fetch(rq, timeout=API_TIMEOUT)
            if st is None:
                raise RuntimeError(f"请求 {path} 失败: {err}")
            return st, body

        # 取或建 release
        st, rb = gh(f"/releases/tags/{RELEASE_TAG}")
        if st == 200:
            rel_id = json.loads(rb)["id"]
            gh(f"/releases/{rel_id}", "PATCH", {"name": RELEASE_NAME, "body": summary})
            print(f"\n[release] 复用已有 release: {RELEASE_TAG}")
        else:
            st, rb = gh("/releases", "POST", {
                "tag_name": RELEASE_TAG,
                "name": RELEASE_NAME,
                "body": summary,
                "draft": False,
                "prerelease": False,
            })
            if st not in (200, 201):
                raise RuntimeError(f"创建 release 失败 HTTP {st}: {rb[:200]}")
            rel_id = json.loads(rb)["id"]
            print(f"\n[release] 已创建 release: {RELEASE_TAG}")

        # 删掉同名旧附件
        st, rb = gh(f"/releases/{rel_id}/assets")
        if st == 200:
            for a in json.loads(rb):
                if a["name"] in (OUT_TXT, OUT_CSV):
                    gh(f"/releases/assets/{a['id']}", "DELETE")
                    print(f"[release] 删除旧附件 {a['name']}")

        # 上传新附件
        for fp in (txt_path, csv_path):
            st, rb = gh(
                f"https://uploads.github.com/repos/{GITHUB_REPO}"
                f"/releases/{rel_id}/assets?name={fp.name}",
                "POST", raw=fp.read_bytes(), ctype="application/octet-stream")
            if st not in (200, 201):
                raise RuntimeError(f"上传 {fp.name} 失败 HTTP {st}: {rb[:200]}")
            print(f"[release] 已上传 {fp.name} ({fp.stat().st_size} 字节)")

        print(f"[release] 下载地址: "
              f"https://github.com/{GITHUB_REPO}/releases/download/{RELEASE_TAG}/{OUT_TXT}")
        print(f"\n全部完成, 用时 {time.perf_counter() - t0:.1f}s")

    except Exception as e:
        # ---- 通知: 已注释 ----
        stage = locals().get("stage", "启动")
        title = f"CF 域名优选失败 [{stage}]"
        body = f"{type(e).__name__}: {e}\n\n{traceback.format_exc()[-800:]}"
        print(f"\n[异常] {title}")
        print(body)
        # from notify import send
        # send(title, body)
        # print("[通知] 已推送")
        sys.exit(1)


if __name__ == "__main__":
    main()
