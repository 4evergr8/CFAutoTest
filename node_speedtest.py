# -*- coding: utf-8 -*-
"""
节点延迟 + 下载速度批量筛选

流程: 下载列表 -> 解析去重 -> 并发 TCP 延迟 -> 串行下载测速 -> 写 txt/csv -> git 提交推送

整个流程包在一个 try 里, 只有出错时才推送通知(成功不推)。
非青龙环境(没有 notify 模块)会静默跳过通知。

用法:
    python node_speedtest.py            # 全量跑
    python node_speedtest.py --limit 20 # 只跑前 20 个(用于试跑)
"""
import argparse
import asyncio
import csv
import re
import socket
import ssl
import subprocess
import sys
import time
import traceback
import urllib.request
from urllib.parse import urlparse
from pathlib import Path

# ============================================================
#                      可配置参数
# ============================================================

SOURCE_URL = "https://zip.cm.edu.kg/all.txt"
COUNTRIES = ["JP", "HK", "SG"]
PORT = 443

LATENCY_MAX_MS = 200          # 只对延迟 <= 该值的节点测速
PING_TIMEOUT_MS = 2000        # 单次 TCP 握手超时
PING_ATTEMPTS = 3             # 每个 IP 尝试次数, 取最小值
PING_CONCURRENCY = 100        # ping 阶段并发数

TEST_URL = "https://4evergr8.ccwu.cc/00000.zip"
SPEED_MIN_MBPS = 8.0          # txt 只输出速度 >= 该值的节点
MAX_PER_COUNTRY = 5           # 单个国家码找到 N 个达标节点后, 立即跳到下一个国家码
SPEED_MAX_BYTES = 25 * 1024 * 1024
SPEED_TIMEOUT = 10.0          # 单个节点测速总时长上限(秒)
VERIFY_TLS = True             # 是否校验证书

# 提前终止时间由阈值推导: 25MB 若要达到 8 MB/s 必须在 3.125s 内下完,
# 超过该时间仍未下完即不可能达标, 直接放弃 (留 5% 余量避免边界误杀)
EARLY_STOP_SEC = SPEED_MAX_BYTES / (SPEED_MIN_MBPS * 1024 * 1024) * 1.05

OUT_DIR = "."                 # 输出目录(相对脚本所在目录), "." 表示与脚本同目录
OUT_TXT = "result.txt"
OUT_CSV = "result.csv"
LIST_FILE = "all.txt"

GIT_PUSH = True               # 跑完是否自动提交并推送
GIT_BRANCH = "main"
GIT_USER = "4evergr8"
GIT_EMAIL = "137018415+4evergr8@users.noreply.github.com"

# ============================================================

BASE = Path(__file__).resolve().parent
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

HOST = urlparse(TEST_URL).hostname
PAT = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)#(.*)$")


def fmt_dur(sec):
    if sec < 60:
        return f"{sec:.0f}s"
    if sec < 3600:
        return f"{sec / 60:.1f}min"
    return f"{sec / 3600:.1f}h"


def sh(cmd):
    """在脚本所在目录执行 shell 命令"""
    return subprocess.run(cmd, cwd=str(BASE), shell=True,
                          capture_output=True, text=True, timeout=180)


# ---------------- 并发 TCP 延迟 ----------------
async def tcp_rtt(ip, port, sem):
    async with sem:
        best = None
        for _ in range(PING_ATTEMPTS):
            t0 = time.perf_counter()
            try:
                _, w = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), PING_TIMEOUT_MS / 1000
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
    deadline = time.perf_counter() + SPEED_TIMEOUT
    try:
        sock = socket.create_connection((ip, port), timeout=SPEED_TIMEOUT)
        sock.settimeout(max(0.5, deadline - time.perf_counter()))

        ctx = ssl.create_default_context()
        if not VERIFY_TLS:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(sock, server_hostname=HOST)

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
        while b"\r\n\r\n" not in buf:
            if time.perf_counter() > deadline:
                res["status"] = "ttfb_timeout"
                return res
            ss.settimeout(max(0.5, deadline - time.perf_counter()))
            d = ss.recv(4096)
            if not d:
                break
            buf += d
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
            remain = deadline - time.perf_counter()
            if remain <= 0:
                break
            ss.settimeout(min(remain, 3.0))
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
              f"(TCP {PING_ATTEMPTS} 次取最小, 单次超时 {PING_TIMEOUT_MS} ms, 并发 {PING_CONCURRENCY})")
        print(f"  速度阈值  : >= {SPEED_MIN_MBPS} MB/s")
        print(f"  单次样本  : {SPEED_MAX_BYTES // 1024 // 1024} MB")
        print(f"  单次超时  : {SPEED_TIMEOUT:.0f} s")
        print(f"  提前终止  : {EARLY_STOP_SEC:.1f} s (样本未下完即不可能达标)")
        print(f"  每国配额  : {MAX_PER_COUNTRY} 个达标后切换国家")
        print(f"  输出目录  : {BASE / OUT_DIR} ({OUT_TXT} / {OUT_CSV})")
        print(f"  自动推送  : {'开' if GIT_PUSH else '关'} (分支 {GIT_BRANCH})")
        print("=" * 68 + "\n")

        qualified = []

        # ---- 1. 下载列表(强制直连, 忽略系统代理) ----
        stage = "下载列表"
        list_path = BASE / LIST_FILE
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        data = None
        for i in range(3):
            try:
                req = urllib.request.Request(
                    SOURCE_URL, headers={"User-Agent": UA, "Accept": "*/*"})
                with opener.open(req, timeout=40) as r:
                    data = r.read()
                if not data:
                    raise RuntimeError("返回内容为空")
                break
            except Exception as e:
                print(f"[下载] 第 {i + 1} 次失败: {type(e).__name__}: {e}")
                if i < 2:
                    time.sleep(2)
        else:
            raise RuntimeError("列表下载失败, 3 次重试均未成功")
        list_path.write_bytes(data)
        print(f"[下载] 成功, {len(data)} 字节 (直连)\n")

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

        # ---- 3. 并发 TCP 延迟 ----
        stage = "延迟测试"
        async def _ping():
            sem = asyncio.Semaphore(PING_CONCURRENCY)
            results = await asyncio.gather(
                *(tcp_rtt(r["ip"], r["port"], sem) for r in rows))
            for r, rtt in zip(rows, results):
                r["ping_ms"] = rtt

        t_ping = time.perf_counter()
        asyncio.run(_ping())
        lat = sorted(r["ping_ms"] for r in rows if r["ping_ms"] is not None)
        reachable = len(lat)
        print(f"[延迟] 完成 {len(rows)} 个 | 可达 {reachable} 个 "
              f"({reachable / len(rows) * 100:.1f}%) | 不可达 {len(rows) - reachable} 个 "
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
                    print(f"  >> {tag} 已达标 {hit} 个, 跳过剩余 {rest} 个, 进入下一个国家 "
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

        # ---- 6. 补全未测节点并写 txt ----
        stage = "写文件"
        for r in rows:
            if "speed" not in r:
                if r.get("skipped"):
                    status = r["skipped"]
                elif r["ping_ms"] is None:
                    status = "ping_fail"
                else:
                    status = "latency_skip"
                writer.writerow([r["ip"], r["port"], r["tag"],
                                 f"{r['ping_ms']:.1f}" if r["ping_ms"] is not None else "",
                                 "", "", status, "N"])
        csv_f.close()

        qualified.sort(key=lambda x: -x["speed"])
        with txt_path.open("w", encoding="utf-8") as f:
            for r in qualified:
                f.write(f"{r['ip']}:{r['port']}#{r['tag']} {r['ip']} {r['speed']:.2f}\n")

        # ---- 7. 汇总 ----
        total_mb = sum(r.get("bytes", 0) for r in rows) / 1024 / 1024
        size_str = f"{total_mb:.0f} MB" if total_mb < 1024 else f"{total_mb / 1024:.2f} GB"
        print(f"\n{'=' * 68}")
        print(f"完成 | 总耗时 {fmt_dur(time.perf_counter() - t0)} | 总下载 {size_str}")
        print(f"合格节点 (>= {SPEED_MIN_MBPS} MB/s): {len(qualified)} 个")
        print(f"{'国家':<8}{'达标':>6}{'最快':>10}{'均值':>10}{'已测':>8}")
        for tag in COUNTRIES:
            qs = [r for r in qualified if r["tag"] == tag]
            tested = sum(1 for r in rows if r["tag"] == tag and "speed" in r)
            if not qs:
                print(f"{tag:<8}{0:>6}{'-':>10}{'-':>10}{tested:>8}")
                continue
            sp = [r["speed"] for r in qs]
            print(f"{tag:<8}{len(qs):>6}{max(sp):>10.2f}{sum(sp) / len(sp):>10.2f}{tested:>8}")
        print("=" * 68)
        print(f"txt: {txt_path}")
        print(f"csv: {csv_path}")

        # ---- 8. 提交并推送 ----
        stage = "git 推送"
        if GIT_PUSH:
            print("\n[git] 检查变更")
            sh(f"git add -A -- {OUT_TXT} {OUT_CSV}")
            if sh("git diff --cached --quiet").returncode == 0:
                print("[git] 结果无变化, 跳过提交")
            else:
                msg = f"update: {time.strftime('%Y-%m-%d %H:%M:%S')}"
                r = sh(f'git -c user.name="{GIT_USER}" -c user.email="{GIT_EMAIL}" '
                       f'commit -q -m "{msg}"')
                if r.returncode != 0:
                    raise RuntimeError(f"git commit 失败: {r.stderr.strip()}")
                r = sh(f"git push origin {GIT_BRANCH}")
                if r.returncode != 0:
                    raise RuntimeError(f"git push 失败: {r.stderr.strip()[:200]}")
                print(f"[git] 已推送 {GIT_BRANCH}")

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

        try:
            for p in ("/ql/data/scripts", "/ql/scripts"):
                if p not in sys.path:
                    sys.path.append(p)
            from notify import send
            send(title, body)
            print("[通知] 已推送")
        except Exception as ne:
            print(f"[通知] 跳过 ({type(ne).__name__}: {ne})")

        sys.exit(1)


if __name__ == "__main__":
    main()
