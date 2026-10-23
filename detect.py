# -*- coding: utf-8 -*-
"""
Web 攻击检测引擎 —— ELK 检测平台的核心部分

两种运行方式：
  1) 离线评估（推荐先跑这个，不需要 ES）：
       python detect.py --evaluate
     → 用 sample_logs.py 生成的带标签样本，输出检出率与误报率

  2) 实时检测（读日志文件）：
       python detect.py --log /path/to/access.log
     → 命中规则的事件写入 alerts.jsonl

  3) 从 Elasticsearch 拉取（可选）：
       python detect.py --es http://localhost:9200 --index filebeat-*

规则设计原则：
  - 特征规则（R1/R2/R4）：命中快、易绕过 → 负责高置信告警
  - 行为规则（R3/R5/R6）：难绕过、有滞后 → 负责兜底
  两者结合才是可用的检测体系。
"""

import re
import urllib.parse
import os
import io
import sys
import json
import time
import argparse
import collections
import datetime
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
ALERT_PATH = os.path.join(HERE, "alerts.jsonl")

# ---------- 规则定义 ----------

SQLI_PAT = re.compile(
    r"(?i)(union\s+select|select\s+.*\s+from\s+information_schema|"
    r"sleep\s*\(|benchmark\s*\(|extractvalue\s*\(|updatexml\s*\(|"
    r"or\s+1\s*=\s*1|'\s*or\s*'|xp_cmdshell|load_file\s*\(|"
    r"information_schema\.|pg_sleep|waitfor\s+delay)"
)

SCANNER_UA_PAT = re.compile(
    r"(?i)(sqlmap|nuclei|awvs|acunetix|nessus|nmap|wpscan|"
    r"dirbuster|gobuster|burp|masscan|zgrab|hydra)"
)

SENSITIVE_PATH_PAT = re.compile(
    r"(?i)(\.git/|\.env|\.svn/|\.DS_Store|web\.config|"
    r"backup|\.bak|\.sql|\.swp|phpinfo|adminer|"
    r"/admin|/manager|/console|\.xmlrpc|actuator|swagger|druid)"
)

CMD_INJECT_PAT = re.compile(
    r"(?i)([;&|`]\s*(cat|ls|whoami|id|wget|curl|nc|bash|sh|chmod|python|perl)\b"
    r"|`[^`]+`|\$\(.*?\))"
)

TRAVERSAL_PAT = re.compile(r"(?i)(\.\./|\.\.\\|%2e%2e%2f|%252e%252e)")

XSS_PAT = re.compile(r"(?i)(<script|onerror\s*=|onload\s*=|javascript:|alert\s*\()")

RULES = [
    ("R1", "SQL 注入特征", "high", SQLI_PAT),
    ("R2", "扫描器指纹", "medium", SCANNER_UA_PAT),
    ("R3", "命令注入特征", "high", CMD_INJECT_PAT),
    ("R4", "路径遍历特征", "high", TRAVERSAL_PAT),
    ("R5", "XSS 特征", "medium", XSS_PAT),
    ("R6", "敏感路径探测", "low", SENSITIVE_PATH_PAT),
]

# 行为规则参数
BURST_WINDOW = 60          # 秒
BURST_THRESHOLD = 60       # 窗口内单 IP 请求数
FAIL_WINDOW = 120          # 秒
FAIL_THRESHOLD = 5         # 登录失败次数


# 同形字（长得像 ASCII，但 NFKC 归一化不会折叠它们）
HOMOGLYPHS = [
    ("ı", "i"), ("İ", "i"), ("ı", "i"), ("ſ", "s"), ("ᛁ", "i"),
    ("а", "a"), ("е", "e"), ("о", "o"), ("р", "p"), ("с", "c"),
]


def _decode_char(match):
    """CHAR(117,110,105,111,110) → union"""
    try:
        return "".join(chr(int(x)) for x in re.findall(r"\d+", match.group(1))
                       if int(x) < 128)
    except Exception:
        return match.group(0)


def _try_utf7(s):
    """UTF-7 还原：+ADw- 解码后是 < 。仅当串里出现 UTF-7 特征片段才尝试"""
    if "+AD" not in s.upper() and "+AF" not in s.upper():
        return s
    try:
        out = s.encode("ascii", "ignore").decode("utf-7")
        return out if out else s
    except Exception:
        return s


def now_str():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def emit(alert):
    line = json.dumps(alert, ensure_ascii=False)
    print("[ALERT] %s | %s | %s | %s" % (
        alert.get("rule_id"), alert.get("rule_name"),
        alert.get("src_ip", "-"), str(alert.get("evidence", ""))[:80]))
    with io.open(ALERT_PATH, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def make_alert(rule_id, rule_name, level, rec, evidence):
    return {
        "ts": now_str(),
        "rule_id": rule_id,
        "rule_name": rule_name,
        "level": level,
        "src_ip": rec.get("ip", "-"),
        "method": rec.get("method", "-"),
        "url": rec.get("url", "-"),
        "ua": rec.get("ua", "-"),
        "status": rec.get("status", "-"),
        "evidence": evidence[:200],
    }


# ---------- 特征检测 ----------

def normalize(text):
    """
    规范化：多次 URL 解码后再匹配。

    为什么要先解码：
      ;cat%20/etc/passwd 和 ;cat /etc/passwd 是同一个攻击，
      不做规范化就只能检出前者——这就是"检测层与执行层语义不一致"的翻版：
      后端会解码后执行，检测却只看原始字符串，必然漏报。
    """
    s = text
    for _ in range(3):
        new = urllib.parse.unquote_plus(s)
        if new == s:
            break
        s = new
    return s


# ---------- 深度规范化：对抗变形的核心层 ----------
#
# 设计原则（这是本项目第二版的关键改动）：
#   第一版我用的是"一条正则对应一种攻击写法"，结果被对抗测试打穿：
#   大小写、注释断词、超长编码、反斜杠……每一种都要加一条正则，无穷无尽。
#
#   正确做法是把"语义等价的多种写法"折叠成同一个规范形式，再交给正则。
#   规则数量不变，覆盖面却指数上升。**归一化层比规则库更值得投入。**

# 严格按 2 字节一组从左到右扫描。
# 踩过的坑：曾经写成 {2,3}，结果 %c0%af%c0%af 被贪婪切成 3 字节再解码，
# 得到的是乱码而不是两个斜杠——归一化反而把载荷改坏了。
_OVERLONG_RE = re.compile(r"(?:%[89a-fA-F][0-9a-fA-F]){2}")


def _decode_overlong(match):
    """UTF-8 超长编码还原：%c0%af 在宽松解析器里等于 '/'"""
    try:
        bs = bytes(int(match.group(0)[i + 1:i + 3], 16)
                   for i in range(0, len(match.group(0)), 3))
    except Exception:
        return match.group(0)
    try:
        if len(bs) == 2:
            return chr(((bs[0] & 0x1F) << 6) | (bs[1] & 0x3F))
        if len(bs) == 3:
            return chr(((bs[0] & 0x0F) << 12) | ((bs[1] & 0x3F) << 6) | (bs[2] & 0x3F))
    except Exception:
        pass
    return match.group(0)


def deep_normalize(text, comment_to_space=False):
    """
    深度规范化：把各种"语义等价但字面不同"的写法折叠成同一形态。

    comment_to_space 参数的由来（第二个踩坑）：
      注释在不同位置扮演不同角色——
        un/**/ion    里的注释纯粹是"断词"，应当删除  → un ion → union
        1/**/union   里的注释是"代替空格"，应当换成空格
      最初我一律删成空串，结果第二种变成 1union，正则里的 \s+ 匹配不到。
      正确做法是产出两个候选形态都去匹配，而不是猜哪一种对。

    按依赖顺序分七步：
      1-2. 【超长编码还原 → URL 解码】循环多轮（顺序绝对不能反，见下方踩坑）
      3. 剥离 SQL/HTML 注释（/**/、/*!...*/、<!-- -->）
      4. Shell 空白变量还原（${IFS}、$IFS → 空格）
      5. 各类空白符统一（%09 %0a %0b %0c %a0 全角空格 → 普通空格）
      6. 路径分隔符统一（反斜杠 → 正斜杠，Windows/IIS 与 Unix 语义相同）
      7. 多重空白压缩（防止用多空格打断正则里的单空格）

    踩过的坑（顺序问题）：
      最初我把 URL 解码放在超长编码还原前面，结果 %c0%af 被 unquote 当成
      普通百分号编码去解，0xc0 0xaf 不是合法 UTF-8，Python 直接替换成两个
      U+FFFD——载荷被我自己改坏了，后面的还原规则再也匹配不到。
      正确顺序：先还原超长编码（此时它还是字面上的 %c0%af），再 URL 解码。
      两者还要循环，因为双重编码下第一轮解码才会露出第二轮的超长编码。
    """
    s = text or ""
    # 0) JSON / JS 里的 \uXXXX 转义还原（服务端 json.loads 后会还原，检测也必须还原）
    s = re.sub(r"\\u([0-9a-fA-F]{4})",
               lambda m: chr(int(m.group(1), 16)), s)
    # 0.5) CHAR(117,110,...) 还原：MySQL 里这等于 'union'。
    #      这是"编码"而非"语义等价"——它有明确的语法特征，所以可以在归一化层折叠，
    #      不需要新增规则，也不需要真的懂 SQL。
    s = re.sub(r"(?i)\bchar\s*\(\s*([\d\s,]+)\)", _decode_char, s)
    s = _try_utf7(s)
    # 1-2) 超长编码还原 + URL 解码，循环到稳定
    for _ in range(5):
        before = s
        s = _OVERLONG_RE.sub(_decode_overlong, s)
        s = urllib.parse.unquote_plus(s)
        if s == before:
            break
    # 3) 剥离注释：MySQL 内联注释与 HTML 注释在服务端会被吃掉
    repl = " " if comment_to_space else ""
    s = re.sub(r"/\*+[!0-9]*\*+/", repl, s)   # /**/  /*!*/  /*!50000*/
    s = re.sub(r"/\*+!?\d*", " ", s)           # /*!50000 → 空格，保留其后关键字
    s = s.replace("*/", " ")
    s = re.sub(r"<!--|-->", " ", s)
    # 4) Shell 空白变量
    s = re.sub(r"\$\{IFS\}|\$IFS\d*|\{IFS\}", " ", s, flags=re.I)
    # 5) 空白符统一
    s = re.sub(r"(%09|%0a|%0b|%0c|%0d|%a0|&nbsp;| |\t|\n|\r|\v|\f)+",
               " ", s, flags=re.I)
    # 6) 路径分隔符统一
    s = s.replace("\\", "/")
    # 6.5) 路径段分号剔除：Spring 等框架把 ; 当参数分隔符，..;/ 等价于 ../
    s = re.sub(r";(?=/)", "", s)
    # 7) 多重空白压缩
    s = re.sub(r" {2,}", " ", s)
    # 8) Unicode 兼容归一化：全角字符、全角空格折叠成半角
    s = unicodedata.normalize("NFKC", s)
    # 9) 同形字映射：ı/İ 之类长得像 ASCII 但 NFKC 不会折叠的字符
    for a, b in HOMOGLYPHS:
        s = s.replace(a, b)
    return s


def collect_blob(rec):
    """
    全字段收集：把一条日志里所有字符串值拼成一个检测面。

    为什么不能用字段白名单（这是第二轮对抗测试暴露的架构问题）：
      第一版我写的是 ("url", "ua", "body", "referer") 四个字段，
      结果把载荷放进 Cookie / X-Forwarded-For / Accept-Language / 任意自定义头，
      检测引擎连看都看不见 —— 8 个协议层用例里 4 个直接隐身。

      攻击载荷会出现在哪里，不由我决定，由攻击者决定。
      所以正确做法是遍历所有字段，而不是枚举"我认为重要的字段"。
    """
    parts = []
    for k, v in rec.items():
        if str(k).startswith("_"):
            continue
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, dict):
            for kk, vv in v.items():
                parts.append(str(kk))
                parts.append(str(vv))
        elif isinstance(v, (list, tuple)):
            parts.extend(str(x) for x in v)
    return " ".join(parts)


def signature_detect(rec):
    """对单条日志做特征匹配，返回命中的告警列表"""
    blob = collect_blob(rec)
    # 同时匹配三个形态：
    #   原始串      —— 看得见的写法
    #   候选一      —— 注释当"断词"删掉
    #   候选二      —— 注释当"空格"替换
    # 语义上三者等价，检测就不该只认其中一种。
    blob = (blob + " " + deep_normalize(blob)
            + " " + deep_normalize(blob, comment_to_space=True))
    hits = []
    for rid, name, level, pat in RULES:
        m = pat.search(blob)
        if m:
            hits.append(make_alert(rid, name, level, rec, m.group(0)))
    return hits


# ---------- 行为检测 ----------

class BehaviorEngine(object):
    """基于时间窗口的行为检测：突发流量、登录爆破"""

    def __init__(self):
        self.req_window = collections.defaultdict(list)   # ip -> [ts]
        self.fail_window = collections.defaultdict(list)  # ip -> [ts]
        self.fired = set()

    def feed(self, rec):
        alerts = []
        ip = rec.get("ip", "-")
        ts = rec.get("ts") or time.time()
        if isinstance(ts, str):
            try:
                ts = time.mktime(time.strptime(ts, "%Y-%m-%d %H:%M:%S"))
            except Exception:
                ts = time.time()

        # R7 突发流量
        q = self.req_window[ip]
        q.append(ts)
        self.req_window[ip] = [t for t in q if ts - t <= BURST_WINDOW]
        if len(self.req_window[ip]) >= BURST_THRESHOLD:
            key = ("R7", ip, int(ts // BURST_WINDOW))
            if key not in self.fired:
                self.fired.add(key)
                alerts.append(make_alert("R7", "请求频率突增", "medium", rec,
                                         "%ds 内 %d 次请求" % (BURST_WINDOW, len(self.req_window[ip]))))

        # R8 认证爆破
        url = str(rec.get("url", "")).lower()
        status = str(rec.get("status", ""))
        if any(k in url for k in ("login", "signin", "auth", "session")) and status.startswith(("4", "5")):
            f = self.fail_window[ip]
            f.append(ts)
            self.fail_window[ip] = [t for t in f if ts - t <= FAIL_WINDOW]
            if len(self.fail_window[ip]) >= FAIL_THRESHOLD:
                key = ("R8", ip, int(ts // FAIL_WINDOW))
                if key not in self.fired:
                    self.fired.add(key)
                    alerts.append(make_alert("R8", "疑似认证爆破", "high", rec,
                                             "%ds 内登录失败 %d 次" % (FAIL_WINDOW, len(self.fail_window[ip]))))
        return alerts


# ---------- 解析 ----------

NGINX_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+) [^"]*" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)


def parse_nginx_line(line):
    m = NGINX_RE.search(line)
    if not m:
        return None
    d = m.groupdict()
    try:
        ts = time.mktime(time.strptime(d["time"].split()[0], "%d/%b/%Y:%H:%M:%S"))
    except Exception:
        ts = time.time()
    return {"ip": d["ip"], "ts": ts, "method": d["method"], "url": d["url"],
            "status": d["status"], "referer": d["referer"], "ua": d["ua"]}


# ---------- 评估 ----------

def evaluate(records):
    """records: 带 label 字段（attack / normal）的样本"""
    beh = BehaviorEngine()
    tp = fp = tn = fn = 0
    miss = []
    for rec in records:
        is_attack = rec.get("label") == "attack"
        hits = signature_detect(rec) + beh.feed(rec)
        detected = len(hits) > 0
        if is_attack and detected:
            tp += 1
        elif is_attack and not detected:
            fn += 1
            miss.append(rec)
        elif not is_attack and detected:
            fp += 1
        else:
            tn += 1
    total_a, total_n = tp + fn, fp + tn
    rec_rate = (tp / total_a * 100) if total_a else 0
    fp_rate = (fp / total_n * 100) if total_n else 0
    print("\n" + "=" * 46)
    print("检测效果评估")
    print("=" * 46)
    print("攻击样本 %d 条 ｜ 正常样本 %d 条" % (total_a, total_n))
    print("命中 %d ｜ 漏报 %d ｜ 误报 %d ｜ 正确排除 %d" % (tp, fn, fp, tn))
    print("检出率：%.1f%%" % rec_rate)
    print("误报率：%.1f%%" % fp_rate)
    print("=" * 46)
    if miss:
        print("\n漏报样例（这些就是你下一轮要补的规则）：")
        for r in miss[:5]:
            print("  -", str(r.get("url", ""))[:90])
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "recall": rec_rate, "fpr": fp_rate}


def main():
    ap = argparse.ArgumentParser(description="Web 攻击检测引擎")
    ap.add_argument("--evaluate", action="store_true", help="用样本评估规则效果")
    ap.add_argument("--log", help="Nginx/Apache 访问日志路径")
    ap.add_argument("--json", help="JSONL 格式的日志（每行一个 record）")
    args = ap.parse_args()

    if args.evaluate:
        sys.path.insert(0, HERE)
        import sample_logs
        records = sample_logs.build_dataset()
        evaluate(records)
        return

    records = []
    if args.log and os.path.exists(args.log):
        with io.open(args.log, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                r = parse_nginx_line(line)
                if r:
                    records.append(r)
    elif args.json and os.path.exists(args.json):
        with io.open(args.json, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    records.append(json.loads(line))
                except Exception:
                    pass
    else:
        print("请指定 --evaluate / --log / --json")
        return

    beh = BehaviorEngine()
    n = 0
    for rec in records:
        for a in signature_detect(rec) + beh.feed(rec):
            emit(a)
            n += 1
    print("\n共处理 %d 条日志，产生 %d 条告警 → %s" % (len(records), n, ALERT_PATH))


if __name__ == "__main__":
    main()
