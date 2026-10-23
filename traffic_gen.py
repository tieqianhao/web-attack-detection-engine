# -*- coding: utf-8 -*-
"""
流量发生器 —— 对本地靶场产生"正常 + 攻击"混合访问流量

设计要点（这决定你的指标是否可信）：
1. 攻击占比控制在 20%-25%，贴近真实日志比例
2. 正常流量要足够多，否则误报率测出来没有意义
3. 攻击流量会自动打标签写入 ground_truth.jsonl
   → 这样你才能算出真实的检出率与误报率，而不是拍脑袋

用法：
    python vuln_app.py          # 另开一个终端先跑靶场
    python traffic_gen.py       # 再跑这个
"""

import os
import io
import json
import time
import random
import argparse
import urllib.parse
import requests

HERE = os.path.dirname(os.path.abspath(__file__))
TRUTH_PATH = os.path.join(HERE, "ground_truth.jsonl")
BASE = "http://127.0.0.1:8080"

random.seed(20261023)

NORMAL_UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
]

ATTACK_UA = [
    "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "Mozilla/5.0 (compatible; Nuclei - Open-source project (v3))",
    "python-requests/2.31.0",
]

# 正常请求
NORMAL_REQS = [
    ("/", {}),
    ("/search", {"q": "admin"}),
    ("/search", {"q": "alice"}),
    ("/search", {"q": "news"}),
    ("/user", {"id": "1"}),
    ("/user", {"id": "2"}),
    ("/comment", {"content": "这个视频做得不错"}),
    ("/download", {"file": "readme.txt"}),
    ("/login", {"username": "alice", "password": "alice123"}),
]

# 攻击请求（含编码变形，用于检验规范化是否生效）
ATTACK_REQS = [
    ("/search", {"q": "admin' union select 1,2,3--"}, "sqli"),
    ("/search", {"q": "admin' OR 1=1--"}, "sqli"),
    ("/search", {"q": "x' and sleep(3)--"}, "sqli"),
    ("/search", {"q": urllib.parse.quote("admin' union select 1,2,3--")}, "sqli_encoded"),
    ("/user", {"id": "1 union select 1,2,3"}, "sqli"),
    ("/user", {"id": "1 OR 1=1"}, "sqli"),
    ("/user", {"id": urllib.parse.quote("1' union select username,password from users--")}, "sqli_encoded"),
    ("/download", {"file": "../../../../etc/passwd"}, "traversal"),
    ("/download", {"file": urllib.parse.quote("../../../windows/win.ini")}, "traversal_encoded"),
    ("/comment", {"content": "<script>alert(1)</script>"}, "xss"),
    ("/comment", {"content": "<img src=x onerror=alert(1)>"}, "xss"),
    ("/comment", {"content": urllib.parse.quote("<script>alert(document.cookie)</script>")}, "xss_encoded"),
    ("/.git/config", {}, "sensitive"),
    ("/.env", {}, "sensitive"),
    ("/admin/console", {}, "sensitive"),
    ("/actuator/env", {}, "sensitive"),
    ("/backup.sql", {}, "sensitive"),
]


def send(path, params, ua, label):
    try:
        r = requests.get(BASE + path, params=params, headers={"User-Agent": ua}, timeout=5)
        status = r.status_code
    except Exception:
        status = 0
    rec = {
        "ts": time.time(),
        "path": path,
        "params": params,
        "ua": ua,
        "label": "attack" if label != "normal" else "normal",
        "attack_type": label,
        "status": status,
        "url": path + ("?" + urllib.parse.urlencode(params) if params else ""),
    }
    with io.open(TRUTH_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return status


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--normal", type=int, default=300, help="正常请求数")
    ap.add_argument("--attack", type=int, default=90, help="攻击请求数")
    ap.add_argument("--burst", action="store_true", help="模拟一次高频突发（触发 R7）")
    ap.add_argument("--brute", action="store_true", help="模拟一次登录爆破（触发 R8）")
    args = ap.parse_args()

    if os.path.exists(TRUTH_PATH):
        os.remove(TRUTH_PATH)

    print("开始产生流量 → %s" % BASE)
    ok = 0
    for i in range(args.normal):
        path, params = random.choice(NORMAL_REQS)
        ua = random.choice(NORMAL_UA)
        st = send(path, params, ua, "normal")
        ok += (st > 0)
        time.sleep(random.uniform(0.005, 0.03))
    print("  正常流量 %d 条（成功 %d）" % (args.normal, ok))

    ok = 0
    for i in range(args.attack):
        path, params, kind = random.choice(ATTACK_REQS)
        ua = random.choice(ATTACK_UA) if random.random() < 0.4 else random.choice(NORMAL_UA)
        st = send(path, params, ua, kind)
        ok += (st > 0)
        time.sleep(random.uniform(0.005, 0.03))
    print("  攻击流量 %d 条（成功 %d）" % (args.attack, ok))

    if args.burst:
        print("  模拟高频突发：单 IP 快速请求 80 次")
        # 突发扫描的请求本身是正常的，异常在于"频率"
        # 因此标注为 normal，由行为规则在【事件级】单独检测（见报告第七节）
        for _ in range(80):
            send("/", {}, NORMAL_UA[0], "normal")
            time.sleep(0.005)
        print("  → 用于触发行为规则 R7（请求频率突增）")

    if args.brute:
        print("  模拟登录爆破：连续 8 次失败登录")
        for i in range(8):
            send("/login", {"username": "admin", "password": "wrong%d" % i}, NORMAL_UA[0], "attack")
            time.sleep(0.05)
        print("  → 用于触发行为规则 R8（疑似认证爆破）")

    n_a = sum(1 for _ in io.open(TRUTH_PATH, encoding="utf-8"))
    print("\n完成，共 %d 条，标签已写入 %s" % (n_a, TRUTH_PATH))
    print("下一步：python run_pipeline.py")


if __name__ == "__main__":
    main()
