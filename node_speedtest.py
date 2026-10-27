# -*- coding: utf-8 -*-
"""
cron: 0 2,7,12,17,22 * * *
new Env('CF 节点测速')

节点延迟 + 下载速度批量筛选

流程: 下载列表 -> 解析去重 -> 并发 TCP 延迟 -> 串行下载测速 -> 写 txt/csv -> 上传 GitHub Release

整个流程包在一个 try 里, 只有出错时才推送通知(成功不推)。
需要与青龙的 notify.py 放在同一目录(默认 /ql/data/scripts/)。

环境变量:
    GITHUB_REPO   owner/repo, 例 4evergr8/CFAutoTest
    GITHUB_TOKEN  有 repo 权限的 PAT
    RELEASE_TAG   Release 标签, 默认 latest(固定, 每次覆盖附件)
    RELEASE_NAME  Release 标题, 可选
    PROXY         下载/上传用的代理, 例 192.168.123.100:7890 (先走代理, 失败再直连)

用法:
    python node_speedtest.py            # 全量跑
    python node_speedtest.py --limit 20 # 只跑前 20 个(用于试跑)
"""
import argparse
import asyncio
import csv
import json
import os
import re
import socket
import ssl
import sys
import time
import traceback
import urllib.error
import urllib.request
from urllib.parse import urlparse
from pathlib import Path

# ============================================================
#                      可配置参数
# ============================================================

SOURCE_URL = "https://zip.cm.edu.kg/all.txt"
COUNTRIES = ["JP", "HK", "SG", "TW"]
PORT = 443

LATENCY_MAX_MS = 800          # TLS 握手耗时上限(注意: 含 TLS, 比纯 TCP RTT 大 3-5 倍)
PING_TIMEOUT_MS = 2000        # 单次 TLS 握手超时
PING_ATTEMPTS = 3             # 每个 IP 尝试次数, 取最小值
PING_CONCURRENCY = 50         # 延迟阶段并发数(TLS 握手吃 CPU, 太高会虚高)

TEST_URL = "https://4evergr8.ccwu.cc/00000.zip"
SPEED_MIN_MBPS = 7.0          # 主阈值: 达到即算合格
LOW_SPEED_MIN_MBPS = 5.0      # 低速阈值: 该国凑不满时用它兜底补齐
MAX_PER_COUNTRY = 7           # 单个国家码凑够 N 个后, 立即跳到下一个国家码
SPEED_MAX_BYTES = 25 * 1024 * 1024
VERIFY_TLS = True             # 是否校验证书

# 提前终止时间由阈值推导: 25MB 若要达到 8 MB/s 必须在 3.125s 内下完,
# 超过该时间仍未下完即不可能达标, 直接放弃 (留 5% 余量避免边界误杀)
EARLY_STOP_SEC = SPEED_MAX_BYTES / (SPEED_MIN_MBPS * 1024 * 1024) * 1.05

OUT_DIR = "."                 # 输出目录(相对脚本所在目录), "." 表示与脚本同目录
OUT_TXT = "result.txt"
OUT_CSV = "result.csv"
LIST_FILE = "all.txt"

GITHUB_REPO = os.environ.get("GITHUB_REPO", "")        # 例: 4evergr8/CFAutoTest
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")      # 需要 repo 权限的 PAT
RELEASE_TAG = os.environ.get("RELEASE_TAG", "latest")  # 固定 tag, 每次覆盖里面的附件
RELEASE_NAME = os.environ.get("RELEASE_NAME", "SpeedTest Results")

PROXY = os.environ.get("PROXY", "").strip()            # 例: 192.168.123.100:7890
PROXY_URL = f"http://{PROXY}" if PROXY else ""
NET_TIMEOUT = 5.0             # 下载列表的单次超时(秒)
API_TIMEOUT = 15.0            # 调用 GitHub API 的超时(秒), 上传附件留些余量

# ============================================================

BASE = Path(__file__).resolve().parent
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

HOST = urlparse(TEST_URL).hostname
PAT = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)#(.*)$")

# 延迟阶段就做完整 TLS 握手(带 SNI), 提前筛掉「TCP 通但不认这个域名」的节点
TLS_CTX = ssl.create_default_context()
if not VERIFY_TLS:
    TLS_CTX.check_hostname = False
    TLS_CTX.verify_mode = ssl.CERT_NONE


def fmt_dur(sec):
    if sec < 60:
        return f"{sec:.0f}s"
    if sec < 3600:
        return f"{sec / 60:.1f}min"
    return f"{sec / 3600:.1f}h"


def fetch(req, timeout=NET_TIMEOUT):
    """先走代理, 失败再直连, 各尝试一次。返回 (status, body, err)"""
    plans = []
    if PROXY_URL:
        plans.append(({"http": PROXY_URL, "https": PROXY_URL}, "代理"))
    plans.append(({}, "直连"))

    def clone():
        # 每次尝试都用全新的 Request, 复用同一对象会残留上一次的代理状态
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
            # 能拿到 HTTP 响应说明链路是通的, 不再换路径
            return e.code, e.read(), None
        except Exception as e:
            last = e
            print(f"[网络] {name}失败: {type(e).__name__}: {e}")
    return None, b"", last


# ---------------- 并发 TLS 握手延迟 ----------------
async def tls_rtt(ip, port, sem):
    async with sem:
        best = None
        for _ in range(PING_ATTEMPTS):
            t0 = time.perf_counter()
            try:
                _, w = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=TLS_CTX, server_hostname=HOST),
                    PING_TIMEOUT_MS / 1000
                )
                dt = (time.perf_counter() - t0) * 1000
                w.close()
                try:
                    await w.wait_closed()
                except Exception:
                    pass
                best = dt if best is None else min(best, dt)
            except Exception:
                pass
        return best


# ---------------- 串行下载测速 ----------------
def speed_test(ip, port):
    res = {"speed": None, "bytes": 0, "ttfb": None, "status": ""}
    sock = ss = None
    try:
        # 所有 socket 操作都以提前终止时间为上限, 不再单独设总超时
        sock = socket.create_connection((ip, port), timeout=EARLY_STOP_SEC)
        sock.settimeout(EARLY_STOP_SEC)

        ctx = ssl.create_default_context()
        if not VERIFY_TLS:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(sock, server_hostname=HOST)
        ss.settimeout(EARLY_STOP_SEC)

        req = (
            f"GET {urlparse(TEST_URL).path} HTTP/1.1\r\n"
            f"Host: {HOST}\r\n"
            f"User-Agent: {UA}\r\n"
            f"Accept: */*\r\n"
            f"Range: bytes=0-{SPEED_MAX_BYTES - 1}\r\n"
            f"Connection: close\r\n\r\n"
        )
        ss.sendall(req.encode())

        buf = b""
        try:
            while b"\r\n\r\n" not in buf:
                d = ss.recv(4096)
                if not d:
                    break
                buf += d
        except socket.timeout:
            res["status"] = "ttfb_timeout"
            return res
        head, _, rest = buf.partition(b"\r\n\r\n")
        code = head.split(b"\r\n")[0].decode(errors="ignore") if head else ""
        if " 2" not in code:
            res["status"] = code[:30] or "no_response"
            return res

        n = len(rest)
        t_start = time.perf_counter()
        aborted = False
        while n < SPEED_MAX_BYTES:
            if time.perf_counter() - t_start > EARLY_STOP_SEC:
                aborted = True
                break
            try:
                d = ss.recv(65536)
            except socket.timeout:
                break
            if not d:
                break
            n += len(d)

        el = time.perf_counter() - t_start
        res["bytes"] = n
        if n > 0 and el > 0.02:
            res["speed"] = n / el / 1024 / 1024
        res["status"] = "early_stop" if aborted else ("partial" if n < SPEED_MAX_BYTES else "ok")
    except Exception as e:
        res["status"] = f"{type(e).__name__}"
    finally:
        for s in (ss, sock):
            try:
                if s:
                    s.close()
            except Exception:
                pass
    return res


# ---------------- 主流程 ----------------
def main():
    try:
        # ---- 0. 参数与横幅 ----
        stage = "启动"
        ap = argparse.ArgumentParser()
        ap.add_argument("--limit", type=int, default=0, help="只测前 N 个节点, 0=全量")
        args = ap.parse_args()

        est_one = EARLY_STOP_SEC + 1.5
        t0 = time.perf_counter()

        print("=" * 68)
        print("节点批量测速")
        print(f"  测速目标  : {TEST_URL}")
        print(f"  国家/地区 : {', '.join(COUNTRIES)}")
        print(f"  端口      : {PORT}")
        print(f"  延迟筛选  : <= {LATENCY_MAX_MS} ms "
              f"(TLS 握手 {PING_ATTEMPTS} 次取最小, 单次超时 {PING_TIMEOUT_MS} ms, "
              f"并发 {PING_CONCURRENCY})")
        print(f"  速度阈值  : >= {SPEED_MIN_MBPS} MB/s (凑不满时用 >= {LOW_SPEED_MIN_MBPS} MB/s 补齐)")
        print(f"  单次样本  : {SPEED_MAX_BYTES // 1024 // 1024} MB")
        print(f"  提前终止  : {EARLY_STOP_SEC:.1f} s (样本未下完即不可能达标, 兼作 socket 超时)")
        print(f"  每国配额  : {MAX_PER_COUNTRY} 个")
        print(f"  输出目录  : {BASE / OUT_DIR} ({OUT_TXT} / {OUT_CSV})")
        if GITHUB_REPO and GITHUB_TOKEN:
            print(f"  Release   : {GITHUB_REPO} @ {RELEASE_TAG}")
        else:
            print(f"  Release   : 未配置 (需 GITHUB_REPO / GITHUB_TOKEN)")
        print(f"  网络代理  : {PROXY_URL or '未配置 (直连)'}")
        print("=" * 68 + "\n")

        qualified = []

        # ---- 1. 下载列表(先代理, 失败再直连, 各一次) ----
        stage = "下载列表"
        list_path = BASE / LIST_FILE
        req = urllib.request.Request(
            SOURCE_URL, headers={"User-Agent": UA, "Accept": "*/*"})
        st, data, err = fetch(req, timeout=NET_TIMEOUT)
        if st != 200 or not data:
            raise RuntimeError(f"列表下载失败: {err or f'HTTP {st}'}")
        list_path.write_bytes(data)
        print(f"[下载] 成功, {len(data)} 字节\n")

        # ---- 2. 解析去重 ----
        stage = "解析列表"
        seen, rows = set(), []
        with list_path.open(encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = PAT.match(line.strip())
                if not m:
                    continue
                ip, port, tag = m.group(1), int(m.group(2)), m.group(3).strip().upper()
                if port != PORT or tag not in COUNTRIES:
                    continue
                if (ip, port) in seen:
                    continue
                seen.add((ip, port))
                rows.append({"ip": ip, "port": port, "tag": tag})
        if not rows:
            raise RuntimeError("没有匹配到任何节点")
        if args.limit:
            rows = rows[: args.limit]
        print(f"[解析] 待测 {len(rows)} 个节点 (已按 ip:port 去重)\n")

        # ---- 3. 并发 TLS 握手延迟 ----
        stage = "延迟测试"
        async def _ping():
            sem = asyncio.Semaphore(PING_CONCURRENCY)
            results = await asyncio.gather(
                *(tls_rtt(r["ip"], r["port"], sem) for r in rows))
            for r, rtt in zip(rows, results):
                r["ping_ms"] = rtt

        t_ping = time.perf_counter()
        asyncio.run(_ping())
        lat = sorted(r["ping_ms"] for r in rows if r["ping_ms"] is not None)
        reachable = len(lat)
        print(f"[延迟] 完成 {len(rows)} 个 | TLS 握手成功 {reachable} 个 "
              f"({reachable / len(rows) * 100:.1f}%) | 失败 {len(rows) - reachable} 个 "
              f"| 耗时 {time.perf_counter() - t_ping:.1f}s")
        if lat:
            print(f"[延迟] 分布 min {lat[0]:.1f} / 中位 {lat[len(lat) // 2]:.1f} / "
                  f"p90 {lat[int(len(lat) * 0.9) - 1]:.1f} ms")

        # ---- 4. 按延迟筛选 ----
        stage = "延迟筛选"
        targets = [r for r in rows
                   if r["ping_ms"] is not None and r["ping_ms"] <= LATENCY_MAX_MS]
        print(f"[筛选] 延迟 <= {LATENCY_MAX_MS}ms: {len(targets)} 个 "
              f"(占可达节点 {len(targets) / max(1, reachable) * 100:.1f}%)")
        for tag in COUNTRIES:
            n_all = sum(1 for r in rows if r["tag"] == tag)
            n_ok = sum(1 for r in targets if r["tag"] == tag)
            print(f"         {tag}: 候选 {n_all} 个 -> 通过 {n_ok} 个")
        print()

        # ---- 5. 逐国测速 ----
        stage = "测速"
        out_dir = BASE / OUT_DIR
        out_dir.mkdir(parents=True, exist_ok=True)
        csv_path = out_dir / OUT_CSV
        txt_path = out_dir / OUT_TXT
        csv_f = csv_path.open("w", encoding="utf-8-sig", newline="")
        writer = csv.writer(csv_f)
        writer.writerow(["ip", "port", "tag", "ping_ms", "speed_MBps",
                         "bytes_MB", "status", "qualified"])

        for ci, tag in enumerate(COUNTRIES, 1):
            group = [r for r in targets if r["tag"] == tag]
            if not group:
                print(f"[{ci}/{len(COUNTRIES)}] {tag}: 无符合条件的候选, 跳过\n", flush=True)
                continue

            print(f"{'-' * 68}")
            print(f"[{ci}/{len(COUNTRIES)}] {tag} | 候选 {len(group)} 个 "
                  f"| 目标 {MAX_PER_COUNTRY} 个 | 最坏耗时约 {fmt_dur(len(group) * est_one)}")
            print(f"{'-' * 68}", flush=True)

            hit = 0
            speeds_here = []
            c_start = time.perf_counter()

            for i, r in enumerate(group, 1):
                if hit >= MAX_PER_COUNTRY:
                    rest = len(group) - i + 1
                    print(f"  >> {tag} 已凑够 {hit} 个, 跳过剩余 {rest} 个, 进入下一个国家 "
                          f"(本段用时 {fmt_dur(time.perf_counter() - c_start)})", flush=True)
                    for rr in group[i - 1:]:
                        rr["skipped"] = "country_quota"
                    break

                res = speed_test(r["ip"], r["port"])
                r.update(res)
                q = res["speed"] is not None and res["speed"] >= SPEED_MIN_MBPS
                r["qualified"] = q
                if q:
                    qualified.append(r)
                    hit += 1
                if res["speed"] is not None:
                    speeds_here.append(res["speed"])

                sp = f"{res['speed']:.2f} MB/s" if res["speed"] is not None else "-"
                mark = " *" if q else "  "
                print(f"[{tag} {i:>3}/{len(group)}] {r['ip']:<16} "
                      f"延迟{r['ping_ms']:>6.1f}ms {sp:>11}{mark} "
                      f"命中 {hit}/{MAX_PER_COUNTRY} [{res['status']}] "
                      f"累计 {fmt_dur(time.perf_counter() - t0)}", flush=True)

                writer.writerow([r["ip"], r["port"], r["tag"],
                                 f"{r['ping_ms']:.1f}",
                                 f"{res['speed']:.2f}" if res["speed"] is not None else "",
                                 f"{res['bytes'] / 1024 / 1024:.2f}",
                                 res["status"], "Y" if q else "N"])
                csv_f.flush()

                if i % 20 == 0 and hit < MAX_PER_COUNTRY:
                    used = time.perf_counter() - c_start
                    avg = sum(speeds_here) / len(speeds_here) if speeds_here else 0.0
                    print(f"    ── {tag} {i}/{len(group)} | 命中 {hit}/{MAX_PER_COUNTRY} "
                          f"| 命中率 {hit / i * 100:.1f}% | 本段均值 {avg:.2f} MB/s "
                          f"| 已用 {fmt_dur(used)} "
                          f"| 预计还需 {fmt_dur(used / i * (len(group) - i))}", flush=True)

            # 该国全部测完仍未凑够, 用低速阈值从高到低补齐
            if hit < MAX_PER_COUNTRY:
                main_hit = hit
                cand = [r for r in group
                        if r.get("speed") is not None
                        and LOW_SPEED_MIN_MBPS <= r["speed"] < SPEED_MIN_MBPS]
                cand.sort(key=lambda x: -x["speed"])
                picked = cand[: MAX_PER_COUNTRY - hit]
                for r in picked:
                    r["fallback"] = True
                    qualified.append(r)
                hit += len(picked)
                print(f"  >> {tag} 全部 {len(group)} 个测完, 主阈值达标 {main_hit} 个, "
                      f"低速阈值补 {len(picked)} 个, 共 {hit}/{MAX_PER_COUNTRY}"
                      + ("" if hit >= MAX_PER_COUNTRY else " (仍不足)"), flush=True)

        # ---- 6. 重写 csv(补上低速补齐标记) 并写 txt ----
        stage = "写文件"
        csv_f.close()
        with csv_path.open("w", encoding="utf-8-sig", newline="") as f2:
            w2 = csv.writer(f2)
            w2.writerow(["ip", "port", "tag", "ping_ms", "speed_MBps",
                         "bytes_MB", "status", "qualified"])
            for r in rows:
                if "speed" not in r:
                    if r.get("skipped"):
                        status = r["skipped"]
                    elif r["ping_ms"] is None:
                        status = "ping_fail"
                    else:
                        status = "latency_skip"
                    w2.writerow([r["ip"], r["port"], r["tag"],
                                 f"{r['ping_ms']:.1f}" if r["ping_ms"] is not None else "",
                                 "", "", status, "N"])
                    continue
                mark = "Y" if r.get("qualified") else ("L" if r.get("fallback") else "N")
                w2.writerow([r["ip"], r["port"], r["tag"],
                             f"{r['ping_ms']:.1f}",
                             f"{r['speed']:.2f}" if r["speed"] is not None else "",
                             f"{r['bytes'] / 1024 / 1024:.2f}",
                             r["status"], mark])

        qualified.sort(key=lambda x: -x["speed"])
        with txt_path.open("w", encoding="utf-8") as f:
            for r in qualified:
                f.write(f"{r['ip']}:{r['port']}#{r['tag']} {r['ip']} {r['speed']:.2f}\n")

        # ---- 7. 汇总 ----
        total_mb = sum(r.get("bytes", 0) for r in rows) / 1024 / 1024
        size_str = f"{total_mb:.0f} MB" if total_mb < 1024 else f"{total_mb / 1024:.2f} GB"
        n_low = sum(1 for r in qualified if r.get("fallback"))
        print(f"\n{'=' * 68}")
        print(f"完成 | 总耗时 {fmt_dur(time.perf_counter() - t0)} | 总下载 {size_str}")
        print(f"入选节点: {len(qualified)} 个 "
              f"(主阈值 >= {SPEED_MIN_MBPS}: {len(qualified) - n_low} 个, "
              f"低速补齐 >= {LOW_SPEED_MIN_MBPS}: {n_low} 个)")
        print(f"{'国家':<8}{'入选':>6}{'其中低速':>10}{'最快':>10}{'已测':>8}")
        for tag in COUNTRIES:
            qs = [r for r in qualified if r["tag"] == tag]
            tested = sum(1 for r in rows if r["tag"] == tag and "speed" in r)
            low = sum(1 for r in qs if r.get("fallback"))
            if not qs:
                print(f"{tag:<8}{0:>6}{0:>10}{'-':>10}{tested:>8}")
                continue
            print(f"{tag:<8}{len(qs):>6}{low:>10}{max(r['speed'] for r in qs):>10.2f}{tested:>8}")
        print("=" * 68)
        print(f"txt: {txt_path}")
        print(f"csv: {csv_path}")

        # ---- 8. 上传到 GitHub Release ----
        stage = "上传 Release"
        if not (GITHUB_REPO and GITHUB_TOKEN):
            print("\n[release] 未配置 GITHUB_REPO / GITHUB_TOKEN, 跳过上传")
        else:
            tested_all = sum(1 for r in rows if "speed" in r)
            lines = [
                f"耗时 {fmt_dur(time.perf_counter() - t0)} | 已测 {tested_all} 个 "
                f"| 下载 {size_str}",
                f"入选节点 {len(qualified)} 个 "
                f"(主阈值 >= {SPEED_MIN_MBPS}: {len(qualified) - n_low} 个, "
                f"低速补齐 >= {LOW_SPEED_MIN_MBPS}: {n_low} 个)",
                "",
            ]
            for tag in COUNTRIES:
                qs = [r for r in qualified if r["tag"] == tag]
                low = sum(1 for r in qs if r.get("fallback"))
                lines.append(f"- {tag}: {len(qs)} 个" + (f" (含低速 {low} 个)" if low else ""))
            if qualified:
                lines.append("")
                for r in qualified[:30]:
                    flag = " (低速)" if r.get("fallback") else ""
                    lines.append(f"`{r['ip']}:{r['port']}` {r['speed']:.2f} MB/s "
                                 f"[{r['tag']}]{flag}")
                if len(qualified) > 30:
                    lines.append(f"... 其余 {len(qualified) - 30} 个见附件 result.txt")
            else:
                lines.append("")
                lines.append("本轮无节点达到速度阈值")
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

        print(f"\n全部完成, 用时 {fmt_dur(time.perf_counter() - t0)}")

    except Exception as e:
        # ---- 唯一的通知: 只在出错时推送 ----
        stage = locals().get("stage", "启动")
        qual = locals().get("qualified") or []
        rows = locals().get("rows") or []
        tested = sum(1 for r in rows if isinstance(r, dict) and "speed" in r)

        title = f"节点测速失败 [{stage}]"
        body = (
            f"{type(e).__name__}: {e}\n"
            f"阶段: {stage} | 已测: {tested} 个 | 已产出: {len(qual)} 个\n\n"
            f"{traceback.format_exc()[-800:]}"
        )
        print(f"\n[异常] {title}")
        print(body)

        from notify import send
        send(title, body)
        print("[通知] 已推送")
        sys.exit(1)


if __name__ == "__main__":
    main()
