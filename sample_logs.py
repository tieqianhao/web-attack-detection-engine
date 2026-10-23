# -*- coding: utf-8 -*-
"""
攻击/正常混合样本生成器 —— 用于验证检测规则的效果

为什么需要它：
  没有带标签的数据集，你就无法证明自己的规则有效。
  面试官问"你怎么证明规则有用"，答案就是这个：攻击回放 + 指标。

用法：
  python sample_logs.py            # 打印数据集统计
  python detect.py --evaluate      # 用它做评估
"""

import random

random.seed(42)

ATTACK_URLS = [
    "/api/user?id=1' union select 1,2,3--",
    "/api/user?id=1' and sleep(3)--",
    "/search?q=1' or 1=1--",
    "/api/order?sort=(select%20*%20from%20information_schema.tables)",
    "/product?id=1%27%20and%20extractvalue(1,concat(0x7e,version()))--",
    "/api/exec?cmd=;cat%20/etc/passwd",
    "/api/exec?cmd=`whoami`",
    "/api/exec?cmd=$(id)",
    "/download?file=../../../../etc/passwd",
    "/download?file=..%2f..%2f..%2fetc%2fshadow",
    "/comment?content=<script>alert(1)</script>",
    "/profile?name=<img src=x onerror=alert(1)>",
    "/.git/config",
    "/.env",
    "/backup.sql",
    "/admin/console",
    "/actuator/env",
    "/swagger-ui.html",
]

NORMAL_URLS = [
    "/", "/index.html", "/static/css/main.css", "/static/js/app.js",
    "/api/user/profile", "/api/product/list?page=1", "/api/cart",
    "/login", "/logout", "/about", "/contact",
    "/images/logo.png", "/favicon.ico", "/api/news?page=2",
    "/search?q=python", "/api/comment?post=12",
]

ATTACK_UAS = [
    "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "Mozilla/5.0 (compatible; Nuclei - Open-source project)",
    "AwvsScanner/1.0",
    "Mozilla/5.0 zgrab/0.x",
]

NORMAL_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
]


def build_dataset(n_attack=120, n_normal=380):
    """生成带 label 的混合样本。默认攻击占比约 24%，接近真实日志的比例。"""
    data = []
    for i in range(n_attack):
        data.append({
            "ip": "203.0.113.%d" % random.randint(2, 60),
            "ts": 1700000000 + i * 3,
            "method": random.choice(["GET", "GET", "POST"]),
            "url": random.choice(ATTACK_URLS),
            "ua": random.choice(ATTACK_UAS) if random.random() < 0.5 else random.choice(NORMAL_UAS),
            "status": random.choice(["200", "403", "500", "404"]),
            "referer": "-",
            "body": "",
            "label": "attack",
        })
    for i in range(n_normal):
        data.append({
            "ip": "198.51.100.%d" % random.randint(2, 80),
            "ts": 1700000000 + i * 11,
            "method": random.choice(["GET", "GET", "GET", "POST"]),
            "url": random.choice(NORMAL_URLS),
            "ua": random.choice(NORMAL_UAS),
            "status": random.choice(["200", "200", "200", "304", "404"]),
            "referer": "-",
            "body": "",
            "label": "normal",
        })
    random.shuffle(data)
    return data


if __name__ == "__main__":
    ds = build_dataset()
    a = sum(1 for r in ds if r["label"] == "attack")
    print("样本总数 %d ｜ 攻击 %d ｜ 正常 %d" % (len(ds), a, len(ds) - a))
    print("运行 python detect.py --evaluate 查看检出率与误报率")
