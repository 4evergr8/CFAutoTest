# -*- coding: utf-8 -*-
"""
cron: 0 4,9,14,19,0 * * *
new Env('CF 延迟优选')

两阶段延迟优选（不测下载速度）

流程: 全段抽样 -> 选出通率最高的网段 -> 该段随机 200 个
      -> 每个 IP 测 3 次取平均 -> 延迟小于阈值的按升序取前 15
      -> 写 txt/csv -> 上传 GitHub Release

入选不足 MIN_TOTAL 个时视为本轮失败: 不上传 Release, 直接报错退出。

环境变量:
    GITHUB_REPO   owner/repo
    GITHUB_TOKEN  有 repo 权限的 PAT
    RELEASE_TAG   Release 标签, 默认 latest(与 node_speedtest.py 同一个 release)
    RELEASE_NAME  Release 标题, 可选
    PROXY         拉取网段列表用的代理, 例 192.168.123.100:7890 (先代理, 失败再直连)
"""
import asyncio
import csv
import ipaddress
import json
import os
import random
import ssl
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

CF_IPV4_URL = "https://www.cloudflare.com/ips-v4"
PORT = 443
TEST_URL = "https://4evergr8.ccwu.cc/00000.zip"   # 决定 TLS 握手的 SNI

RANGE_SAMPLE = 20             # 第一阶段: 每个网段抽几个 IP 用于比较通率
SAMPLE_TOTAL = 200            # 第二阶段: 最优网段里随机抽几个 IP
PING_ATTEMPTS = 3             # 每个 IP 测几次(取平均), 任一次失败即判定不可靠
PING_TIMEOUT_MS = 1000        # 单次 TLS 握手超时
PING_CONCURRENCY = 50         # 并发数

LATENCY_MAX_MS = 800          # 延迟上限, 超过的不入选
TOP_N = 15                    # 最终取前几个
MIN_TOTAL = 7                 # 入选少于该值则不上传 Release

VERIFY_TLS = True

OUT_DIR = "."
OUT_TXT = "cf_latency.txt"
OUT_CSV = "cf_latency.csv"

GITHUB_REPO = os.environ.get("GITHUB_REPO", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
RELEASE_TAG = os.environ.get("RELEASE_TAG", "latest")
RELEASE_NAME = os.environ.get("RELEASE_NAME", "CF Latency Top")

PROXY = os.environ.get("PROXY", "").strip()
PROXY_URL = f"http://{PROXY}" if PROXY else ""
NET_TIMEOUT = 8.0
API_TIMEOUT = 15.0

# ============================================================

BASE = Path(__file__).resolve().parent
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

HOST = urlparse(TEST_URL).hostname

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
    """先走代理, 失败再直连, 各尝试一次"""
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


# ---------------- 单次 TLS 握手 ----------------
async def tls_once(ip, sem):
    async with sem:
        t0 = time.perf_counter()
        try:
            _, w = await asyncio.wait_for(
                asyncio.open_connection(ip, PORT, ssl=TLS_CTX, server_hostname=HOST),
                PING_TIMEOUT_MS / 1000
            )
            dt = (time.perf_counter() - t0) * 1000
            w.close()
            try:
                await asyncio.wait_for(w.wait_closed(), 0.3)
            except Exception:
                pass
            return dt
        except Exception:
            return None


async def measure(ip, sem, times):
    """测 times 次取平均; 任一次失败即返回 None"""
    vals = []
    for _ in range(times):
        v = await tls_once(ip, sem)
        if v is None:
            return None
        vals.append(v)
    return sum(vals) / len(vals)


def run_batch(items, times, label):
    """对 items 里的每个 dict 计算 ping_ms(平均), 失败为 None"""
    async def _run():
        sem = asyncio.Semaphore(PING_CONCURRENCY)
        res = await asyncio.gather(*(measure(r["ip"], sem, times) for r in items))
        for r, v in zip(items, res):
            r["ping_ms"] = v

    t0 = time.perf_counter()
    asyncio.run(_run())
    ok = sum(1 for r in items if r["ping_ms"] is not None)
    print(f"[{label}] {ok}/{len(items)} 个可达 | 耗时 {time.perf_counter() - t0:.1f}s")
    return ok


def main():
    try:
        stage = "启动"
        t0 = time.perf_counter()
        rnd = random.SystemRandom()

        print("=" * 68)
        print("CF 延迟优选 (不测下载速度)")
        print(f"  目标域名  : {HOST}")
        print(f"  网段来源  : {CF_IPV4_URL}")
        print(f"  第一阶段  : 每段抽 {RANGE_SAMPLE} 个, 选出通率最高的网段")
        print(f"  第二阶段  : 该段随机 {SAMPLE_TOTAL} 个, 每个测 {PING_ATTEMPTS} 次取平均")
        print(f"  入选条件  : 平均延迟 < {LATENCY_MAX_MS} ms, 取前 {TOP_N} 个")
        print(f"  下限      : 少于 {MIN_TOTAL} 个则不上传 Release")
        print(f"  并发      : {PING_CONCURRENCY} | 单次超时 {PING_TIMEOUT_MS} ms")
        if GITHUB_REPO and GITHUB_TOKEN:
            print(f"  Release   : {GITHUB_REPO} @ {RELEASE_TAG}")
        else:
            print(f"  Release   : 未配置 (需 GITHUB_REPO / GITHUB_TOKEN)")
        print("=" * 68 + "\n")

        # ---- 1. 拉取官方网段 ----
        stage = "拉取网段"
        req = urllib.request.Request(CF_IPV4_URL,
                                     headers={"User-Agent": UA, "Accept": "*/*"})
        st, data, err = fetch(req)
        if st != 200 or not data:
            raise RuntimeError(f"网段列表拉取失败: {err or f'HTTP {st}'}")
        nets = []
        for line in data.decode(errors="ignore").splitlines():
            line = line.strip()
            if not line or "/" not in line:
                continue
            try:
                net = ipaddress.ip_network(line, strict=False)
            except ValueError:
                continue
            if net.version == 4:
                nets.append(net)
        if not nets:
            raise RuntimeError("没有解析到任何 IPv4 网段")
        print(f"[网段] {len(nets)} 个\n")

        # ---- 2. 第一阶段: 全段抽样, 比较通率 ----
        stage = "全段抽样"
        probe = []
        for net in nets:
            lo, hi = int(net.network_address) + 1, int(net.broadcast_address) - 1
            for v in rnd.sample(range(lo, hi + 1), min(RANGE_SAMPLE, hi - lo + 1)):
                probe.append({"ip": str(ipaddress.IPv4Address(v)), "cidr": str(net)})
        run_batch(probe, 1, "抽样")

        ranges = []
        for net in nets:
            g = [r for r in probe if r["cidr"] == str(net)]
            ok = [r["ping_ms"] for r in g if r["ping_ms"] is not None]
            ok.sort()
            ranges.append({
                "cidr": str(net), "n": len(g), "ok": len(ok),
                "rate": len(ok) / len(g) if g else 0,
                "med": ok[len(ok) // 2] if ok else None,
            })
        # 先比通率, 通率相同再比中位延迟
        ranges.sort(key=lambda x: (-x["rate"], x["med"] if x["med"] else 1e9))

        print(f"\n{'CIDR':<19}{'样本':>6}{'可达':>6}{'通率':>8}{'中位':>9}")
        for r in ranges:
            med = f"{r['med']:.0f}" if r["med"] else "-"
            print(f"{r['cidr']:<19}{r['n']:>6}{r['ok']:>6}{r['rate'] * 100:>7.0f}%{med:>9}")

        best = ranges[0]
        if best["ok"] == 0:
            raise RuntimeError("第一阶段没有任何网段可达")
        print(f"\n[选择] 最优网段 {best['cidr']} "
              f"(通率 {best['rate'] * 100:.0f}%, 中位 {best['med']:.0f} ms)\n")

        # ---- 3. 第二阶段: 该段随机抽样, 每个测 N 次取平均 ----
        stage = "精细测速"
        net = ipaddress.ip_network(best["cidr"], strict=False)
        lo, hi = int(net.network_address) + 1, int(net.broadcast_address) - 1
        ips = rnd.sample(range(lo, hi + 1), min(SAMPLE_TOTAL, hi - lo + 1))
        rows = [{"ip": str(ipaddress.IPv4Address(v)), "cidr": best["cidr"]} for v in ips]
        print(f"[抽样] {best['cidr']} 内随机 {len(rows)} 个, 每个测 {PING_ATTEMPTS} 次")
        run_batch(rows, PING_ATTEMPTS, "测速")

        lat = sorted(r["ping_ms"] for r in rows if r["ping_ms"] is not None)
        if lat:
            print(f"[延迟] min {lat[0]:.1f} / 中位 {lat[len(lat) // 2]:.1f} / "
                  f"p90 {lat[int(len(lat) * 0.9) - 1]:.1f} ms")

        # ---- 4. 排序取前 N ----
        stage = "筛选"
        cand = [r for r in rows
                if r["ping_ms"] is not None and r["ping_ms"] < LATENCY_MAX_MS]
        cand.sort(key=lambda x: x["ping_ms"])
        picked = cand[:TOP_N]
        for r in picked:
            r["selected"] = True
        print(f"[筛选] 平均延迟 < {LATENCY_MAX_MS}ms 的有 {len(cand)} 个, 取前 {len(picked)} 个\n")

        for i, r in enumerate(picked, 1):
            print(f"  {i:>2}. {r['ip']:<16} {r['ping_ms']:>7.1f} ms")

        # ---- 5. 写文件 ----
        stage = "写文件"
        out_dir = BASE / OUT_DIR
        out_dir.mkdir(parents=True, exist_ok=True)
        txt_path = out_dir / OUT_TXT
        csv_path = out_dir / OUT_CSV

        with txt_path.open("w", encoding="utf-8") as f:
            for r in picked:
                f.write(f"{r['ip']}:{PORT}#{best['cidr']} {r['ip']} {r['ping_ms']:.1f}\n")

        with csv_path.open("w", encoding="utf-8-sig", newline="") as f:
            w = csv.writer(f)
            w.writerow(["ip", "port", "cidr", "ping_ms", "status", "selected"])
            for r in rows:
                if r["ping_ms"] is None:
                    w.writerow([r["ip"], PORT, r["cidr"], "", "ping_fail", "N"])
                    continue
                ok = r["ping_ms"] < LATENCY_MAX_MS
                w.writerow([r["ip"], PORT, r["cidr"], f"{r['ping_ms']:.1f}",
                            "ok" if ok else "latency_skip",
                            "Y" if r.get("selected") else "N"])

        print(f"\n{'=' * 68}")
        print(f"完成 | 耗时 {fmt_dur(time.perf_counter() - t0)} | 网段 {best['cidr']} "
              f"| 抽样 {len(rows)} | 可达 {len(lat)} | 入选 {len(picked)}")
        print(f"txt: {txt_path}")
        print(f"csv: {csv_path}")

        # ---- 6. 数量校验: 不够就不更新 Release ----
        stage = "结果校验"
        if len(picked) < MIN_TOTAL:
            raise RuntimeError(
                f"本轮仅入选 {len(picked)} 个 (< {MIN_TOTAL}), 放弃更新 Release")

        # ---- 7. 上传 Release ----
        stage = "上传 Release"
        if not (GITHUB_REPO and GITHUB_TOKEN):
            print("\n[release] 未配置 GITHUB_REPO / GITHUB_TOKEN, 跳过上传")
            print(f"\n全部完成, 用时 {fmt_dur(time.perf_counter() - t0)}")
            return

        lines = [
            f"网段 {best['cidr']} (通率 {best['rate'] * 100:.0f}%) | "
            f"抽样 {len(rows)} 个 | 可达 {len(lat)} 个 | "
            f"入选 {len(picked)} 个 (平均延迟 < {LATENCY_MAX_MS}ms)",
            f"耗时 {fmt_dur(time.perf_counter() - t0)} | 每个 IP 测 {PING_ATTEMPTS} 次取平均",
            "",
        ]
        for r in picked:
            lines.append(f"`{r['ip']}:{PORT}` {r['ping_ms']:.1f} ms")
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
            data_ = raw if raw is not None else (
                json.dumps(payload).encode() if payload is not None else None)
            rq = urllib.request.Request(url, data=data_, method=method)
            for k, v in hdr.items():
                rq.add_header(k, v)
            if ctype:
                rq.add_header("Content-Type", ctype)
            st_, body, err = fetch(rq, timeout=API_TIMEOUT)
            if st_ is None:
                raise RuntimeError(f"请求 {path} 失败: {err}")
            return st_, body

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

        st, rb = gh(f"/releases/{rel_id}/assets")
        if st == 200:
            for a in json.loads(rb):
                if a["name"] in (OUT_TXT, OUT_CSV):
                    gh(f"/releases/assets/{a['id']}", "DELETE")
                    print(f"[release] 删除旧附件 {a['name']}")

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
        stage = locals().get("stage", "启动")
        picked = locals().get("picked") or []
        rows = locals().get("rows") or []
        title = f"CF 延迟优选失败 [{stage}]"
        body = (
            f"{type(e).__name__}: {e}\n"
            f"阶段: {stage} | 已测: {len(rows)} 个 | 已入选: {len(picked)} 个\n\n"
            f"{traceback.format_exc()[-800:]}"
        )
        print(f"\n[异常] {title}")
        print(body)
        try:
            from notify import send
            send(title, body)
            print("[通知] 已推送")
        except ImportError:
            print("[通知] 未找到 notify.py, 跳过推送")
        sys.exit(1)


if __name__ == "__main__":
    main()
