# -*- coding: utf-8 -*-
"""
自我对抗引擎：用真实绕过手法攻击自己的检测规则

为什么要有这个东西：
    上一篇博客里我拿到了"检出率 100%"，但那个 100% 的潜台词是——
    **攻击流量是我自己按课本写法造的**。真实攻击者不会那么乖。

    本脚本做的就是 WAF 绕过测试（bypass testing）的最小实现：
    对同一组攻击载荷施加 N 种真实变形手法，看哪些变形能让检测规则瞎掉。
    能被绕过的手法 = 我这套规则的盲区 = 我下一步要补的东西。

运行：
    python mutate.py                # 跑全量对抗，输出按手法/按载荷类型的绕过统计
    python mutate.py --show-miss    # 列出所有绕过成功的手法（不含载荷原文）
"""

import sys
import os
import io
import re
import json
import urllib.parse
import collections
import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import detect

HERE = os.path.dirname(os.path.abspath(__file__))
RESULT_PATH = os.path.join(HERE, "对抗测试结果.json")

# ---------- 基础载荷：按攻击类型分组 ----------
# 说明：这里的字符串全部用拼接方式构造，避免脚本本身被当成攻击样本误伤。
# 每一项 = (载荷类别, 注入位置, 载荷原文)

def _p(*parts):
    return "".join(parts)

PAYLOADS = [
    ("SQL注入-联合查询", "q",
     _p("1 ", "un", "ion ", "sel", "ect ", "null,version()--")),
    ("SQL注入-布尔盲注", "q",
     _p("admin' o", "r 1=1--")),
    ("SQL注入-时间盲注", "q",
     _p("1' a", "nd sl", "eep(5)--")),
    ("SQL注入-报错注入", "q",
     _p("1' a", "nd upd", "atexml(1,concat(0x7e,version()),1)--")),
    ("SQL注入-读文件", "q",
     _p("1' un", "ion sel", "ect lo", "ad_file('/etc/passwd')--")),
    ("命令注入-分号", "cmd",
     _p("127.0.0.1; ca", "t /etc/passwd")),
    ("命令注入-反引号", "cmd",
     _p("$(who", "ami)")),
    ("命令注入-空格绕过", "cmd",
     _p("127.0.0.1;cat${IFS}/etc/passwd")),
    ("路径遍历-相对路径", "file",
     _p("../../../etc/passwd")),
    ("路径遍历-双重编码", "file",
     _p("..%252f..%252fetc/passwd")),
    ("XSS-脚本标签", "q",
     _p("<scr", "ipt>al", "ert(1)</scr", "ipt>")),
    ("XSS-事件属性", "q",
     _p("<img src=x onerr", "or=al", "ert(1)>")),
    ("XSS-协议", "q",
     _p("java", "script:al", "ert(1)")),
    ("敏感路径-git", "path", "/.git/config"),
    ("敏感路径-env", "path", "/.env"),
    ("敏感路径-后台", "path", "/admin/login"),
]

# ---------- 变形手法：全部取自真实 WAF 绕过技巧 ----------
# 每项 = (手法ID, 手法名称, 变形函数, 所属大类)

def m_upper(s):
    return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s))

def m_comment(s):
    """MySQL 内联注释：把关键字打断，MySQL 会忽略 /**/"""
    return s.replace(" ", "/**/")

def m_tab(s):
    return s.replace(" ", "\t")

def m_newline(s):
    return s.replace(" ", "%0a")

def m_urlenc(s):
    return urllib.parse.quote(s, safe="")

def m_double_urlenc(s):
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")

def m_nullbyte(s):
    return s + "%00"

def m_case_keyword(s):
    """只把 SQL/XSS 关键字做大小写交替，空格保留"""
    out = []
    up = True
    for c in s:
        if c.isalpha():
            out.append(c.upper() if up else c.lower())
            up = not up
        else:
            out.append(c)
    return "".join(out)

def m_space_plus(s):
    """空格换成 +，部分容器会还原成空格"""
    return s.replace(" ", "+")

def m_space_double(s):
    """双空格：部分正则用单空格做分隔，会被打断"""
    return s.replace(" ", "  ")

def m_unicode_ws(s):
    """用全角/不间断空格替换普通空格"""
    return s.replace(" ", "%c2%a0")

def m_hex(s):
    """把路径分隔符做十六进制编码（IIS/旧容器的经典绕过）"""
    return s.replace("/", "%2f").replace("\\", "%5c")

def m_overlong(s):
    """UTF-8 超长编码：%c0%af 解码后是 /"""
    return s.replace("/", "%c0%af").replace("..", "..%c0%af")

def m_dot_variation(s):
    """....// 变形：剥离后仍是 ../"""
    return s.replace("../", "....//")

def m_semicolon_pad(s):
    """路径后加分号——旧版容器会截断分号后内容"""
    return s + ";"

def m_concat_split(s):
    """MySQL 注释拼接：关键字被拆开但服务端会拼回来"""
    return s.replace("select", "sel/**/ect").replace("union", "un/**/ion")

def m_equiv_op(s):
    """等价操作符替换：or 1=1 → or 2>1"""
    return s.replace("1=1", "2>1").replace("or", "||")

def m_backslash(s):
    """反斜杠：部分解析器把 \\ 当转义"""
    return s.replace("/", "\\")

def m_param_pollution(s):
    """HTTP 参数污染：把载荷拆到两个同名参数，后端可能拼接"""
    return s + "&q=1"

def m_ua_spoof(s):
    """扫描器 UA 伪装成正常浏览器（针对 R2 指纹规则）"""
    return s

MUTATIONS = [
    ("M01", "大小写交替（整体）", m_upper, "编码/大小写"),
    ("M02", "SQL内联注释 /**/ 断词", m_comment, "注释混淆"),
    ("M03", "空格→Tab", m_tab, "空白符替换"),
    ("M04", "空格→换行 %0a", m_newline, "空白符替换"),
    ("M05", "URL 单次编码", m_urlenc, "编码/大小写"),
    ("M06", "URL 双重编码", m_double_urlenc, "编码/大小写"),
    ("M07", "空字节截断 %00", m_nullbyte, "截断"),
    ("M08", "关键字大小写交替", m_case_keyword, "编码/大小写"),
    ("M09", "空格→加号", m_space_plus, "空白符替换"),
    ("M10", "双空格打断", m_space_double, "空白符替换"),
    ("M11", "空格→不间断空格", m_unicode_ws, "空白符替换"),
    ("M12", "分隔符十六进制编码", m_hex, "编码/大小写"),
    ("M13", "UTF-8 超长编码 %c0%af", m_overlong, "编码/大小写"),
    ("M14", "....// 变形", m_dot_variation, "路径变形"),
    ("M15", "分号截断", m_semicolon_pad, "截断"),
    ("M16", "关键字注释拼接", m_concat_split, "注释混淆"),
    ("M17", "等价操作符替换", m_equiv_op, "语义等价"),
    ("M18", "斜杠→反斜杠", m_backslash, "路径变形"),
    ("M19", "参数污染拆分", m_param_pollution, "协议层"),
]

# 扫描器 UA 单独测（R2 是唯一一条只看 UA 的规则）
UA_CASES = [
    ("sqlmap 原版", "sqlmap/1.7.2#stable"),
    ("sqlmap 大小写", "SQLMap/1.7"),
    ("sqlmap 伪装", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) sqlmap"),
    ("nuclei 伪装", "Mozilla/5.0 (compatible; nuclei)"),
    ("正常浏览器", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"),
]


# ---------- 第二轮补充手法 ----------
# 这些是真实世界里更"进阶"的绕过，也是我第一轮故意没测的。

def m_widebyte(s):
    """
    宽字节注入：GBK 下 %df%5c 会合成一个汉字，把反斜杠"吃掉"，
    于是后面的单引号逃逸出转义 —— 这是能把转义符变成注入点的经典手法。
    """
    return "%df%5c" + s

def m_utf7(s):
    """UTF-7 编码：+ADw- 解码后是 < ，部分服务端/浏览器会还原"""
    return "+ADw-" + s.replace("<", "").replace(">", "+AD4-")

def m_fullwidth(s):
    """全角字符：＜ ＞ ／ 在部分归一化流程里会被折叠成半角"""
    table = {"<": "＜", ">": "＞", "/": "／", "'": "＇", "\"": "＂"}
    return "".join(table.get(c, c) for c in s)

def m_mysql_version_comment(s):
    """MySQL 版本注释：/*!50000...*/ 里的关键字仍会被 MySQL 执行"""
    return "/*!50000" + s + "*/"

def m_char_func(s):
    """
    CHAR() 部分编码：只把载荷里的一个关键字用 CHAR() 编码，其余原样保留。

    踩过的坑（第三轮对抗测试最值钱的发现）：
      第一版我写的是 head = s[:12]，只编码前 12 个字符，**剩余载荷直接丢掉**。
      还原出来的字符串是 "1' union sel" 这种被截断的残片——它确实绕过了检测，
      但它根本不是一个能执行的攻击。8 条"盲区"全是这么来的。
      那是测试工具的 bug，不是检测引擎的能力边界。
      修正后：编码一个完整关键字，载荷一字不丢。
    """
    low = s.lower()
    for kw in ("union", "select", "script", "alert", "sleep",
               "extractvalue", "information_schema", "load_file"):
        i = low.find(kw)
        if i >= 0:
            seg = s[i:i + len(kw)]
            codes = ",".join(str(ord(c)) for c in seg if ord(c) < 128)
            if codes:
                return s[:i] + "char(%s)" % codes + s[i + len(kw):]
    head = s[:6]
    codes = ",".join(str(ord(c)) for c in head if ord(c) < 128)
    return ("char(%s)" % codes + s[6:]) if codes else s


# ---------- 变形有效性校验 ----------
#
# mutate.py 自己也必须有测试。否则"绕过率"里混进的不是绕过，而是脚本的 bug。
# 判据独立于检测规则库（只看信息保留，不看正则是否命中），所以不会循环论证。

_WORD_RE = re.compile(r"[a-z]{3,}")
_STOP = {"and", "not", "for", "the", "null", "true", "false"}


def variant_effectiveness(base, variant):
    """
    这个变形还算不算"同一个攻击"？返回 (是否有效, 原因)

    两条判据：
      1. 长度不能大幅缩水（截断会直接丢信息）
      2. 原始载荷里的实词，归一化后至少要保留一半
         注意这里比较的是"词表"而不是"检测正则"，所以不是在自证清白。
    """
    norm = (detect.deep_normalize(variant) + " " +
            detect.deep_normalize(variant, comment_to_space=True)).lower()
    if len(variant) < len(base) * 0.6:
        return False, "载荷被截断（%d → %d 字符）" % (len(base), len(variant))
    words = [w for w in _WORD_RE.findall(base.lower()) if w not in _STOP]
    if words:
        kept = [w for w in words if w in norm]
        if len(kept) < len(words) * 0.5:
            return False, "实词丢失 %d/%d（变形后已不是同一攻击）" % (
                len(words) - len(kept), len(words))
    return True, ""

def m_semicolon_path(s):
    """Spring WebFlux 经典：..;/ 里的分号被当作参数分隔符剔除后仍是 ../"""
    return s.replace("../", "..;/")

def m_double_write(s):
    """
    双写关键词：ununionion
    专门对付"把关键字替换成空串"的过滤逻辑——删一次还剩一个。
    """
    for kw in ("union", "select", "script", "alert"):
        if kw in s.lower():
            return s.replace(kw, kw + kw).replace(kw, kw[:len(kw) // 2] + kw + kw[len(kw) // 2:])
    return s + s

def m_sql_comment_newline(s):
    """SQL 注释 + 换行：--%0a 之后的换行让后续语句另起一行执行"""
    return s + "--%0a"

def m_combo(s):
    """组合技：大小写 + 双重 URL 编码（单看一种都能防，组合就未必）"""
    mixed = "".join(c.upper() if i % 3 == 0 else c.lower() for i, c in enumerate(s))
    return urllib.parse.quote(urllib.parse.quote(mixed, safe=""), safe="")

def m_padding(s):
    """超长填充：塞大量无害字符，赌检测有长度截断或回溯超时"""
    return "A" * 500 + s

def m_turkish_i(s):
    """Unicode 近似字符：把 i 换成无点 ı / İ，绕过大小写无关匹配"""
    return s.replace("i", "%c4%b1")

MUTATIONS_V2 = [
    ("M20", "宽字节注入 %df%5c", m_widebyte, "编码/大小写"),
    ("M21", "UTF-7 编码", m_utf7, "编码/大小写"),
    ("M22", "全角字符替换", m_fullwidth, "编码/大小写"),
    ("M23", "MySQL 版本注释", m_mysql_version_comment, "注释混淆"),
    ("M24", "CHAR() 十进制编码", m_char_func, "语义等价"),
    ("M25", "分号路径 ..;/", m_semicolon_path, "路径变形"),
    ("M26", "双写关键词", m_double_write, "过滤绕过"),
    ("M27", "SQL注释+换行", m_sql_comment_newline, "注释混淆"),
    ("M28", "大小写+双重编码组合", m_combo, "编码/大小写"),
    ("M29", "超长填充绕过", m_padding, "协议层"),
    ("M30", "Unicode 近似字符", m_turkish_i, "编码/大小写"),
]

# ---------- 协议层用例：换字段，而不是换写法 ----------
# 这一类不看载荷怎么变形，而是问：
#   "同样的载荷，放在请求的其他位置，检测引擎还看得见吗？"

PROTOCOL_CASES = [
    ("P1", "载荷放进 Cookie", "cookie", "q",
     _p("1' un", "ion sel", "ect null--")),
    ("P2", "载荷放进 X-Forwarded-For", "xff", "q",
     _p("<scr", "ipt>al", "ert(1)</scr", "ipt>")),
    ("P3", "载荷放进 Referer", "referer", "q",
     _p("../../etc/passwd")),
    ("P4", "载荷放进 User-Agent", "ua", "q",
     _p("1' o", "r 1=1--")),
    ("P5", "载荷放进 Accept-Language", "accept_language", "q",
     _p("; ca", "t /etc/passwd")),
    ("P6", "载荷放进自定义 Header", "x_custom", "q",
     _p("1' un", "ion sel", "ect null--")),
    ("P7", "JSON body 内 Unicode 转义", "json_body", "q",
     _p("un", "ion sel", "ect")),
    ("P8", "载荷放进 POST body（明文）", "body", "q",
     _p("1' o", "r 1=1--")),
]


def build_record(payload, inject_pos):
    """把载荷放进一条模拟日志的合适字段里"""
    rec = {"ip": "10.0.0.99", "method": "GET", "status": "200",
           "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
           "referer": "-", "body": "", "url": "/index",
           "cookie": "-", "headers": {}}
    if inject_pos == "q":
        rec["url"] = "/search?q=" + payload
    elif inject_pos == "cmd":
        rec["url"] = "/ping?host=" + payload
    elif inject_pos == "file":
        rec["url"] = "/download?file=" + payload
    elif inject_pos == "path":
        rec["url"] = payload
    return rec


def build_protocol_record(field, payload):
    """把载荷放进指定的协议字段"""
    rec = build_record("x", "q")
    if field == "cookie":
        rec["cookie"] = "session=abc; q=" + payload
    elif field == "xff":
        rec["headers"]["X-Forwarded-For"] = payload
    elif field == "referer":
        rec["referer"] = "http://x/?r=" + payload
    elif field == "ua":
        rec["ua"] = payload
    elif field == "accept_language":
        rec["headers"]["Accept-Language"] = payload
    elif field == "x_custom":
        rec["headers"]["X-Api-Token"] = payload
    elif field == "json_body":
        # JSON 里的 Unicode 转义：\u0075nion —— 服务端 json.loads 后会还原
        esc = "".join("\\u%04x" % ord(c) if ord(c) < 128 else c for c in payload)
        rec["body"] = '{"keyword":"%s"}' % esc
    elif field == "body":
        rec["body"] = "q=" + payload
    return rec


# ---------- 采集层盲区：日志里根本没有的东西 ----------
#
# 这一组不是"绕过"，而是检测层的先天边界。
# 日志驱动的检测，输入就是日志——日志里没有的字段，规则写得再完美也看不见。
# 把它们单列出来，是为了防止把"采集层问题"当成"检测规则问题"去修：
# 后者改代码能解决，前者只能改采集配置。混在一起会让人在错误的方向上使劲。

COLLECT_CASES = [
    ("C1", "URL 被采集层截断，载荷落在截断线之后", "truncate_url"),
    ("C2", "POST body 未采集（配置只记 URL）", "no_body"),
    ("C3", "分块传输：body 分片，日志只落首片", "chunked"),
    ("C4", "请求走私：外层请求合法，内层载荷不可见", "smuggling"),
    ("C5", "HTTPS 加密链路：中间设备只看到 SNI", "tls"),
]


def build_collect_case(kind):
    """构造一条"日志里缺少关键信息"的记录"""
    payload = _p("1' un", "ion sel", "ect null--")
    rec = build_record("x", "q")
    if kind == "truncate_url":
        rec["url"] = "/search?q=" + "A" * 200 + payload
        rec["_truncate_at"] = 200
    elif kind == "no_body":
        rec["url"] = "/search"
        rec["body"] = ""
    elif kind == "chunked":
        rec["url"] = "/upload"
        rec["body"] = ""
    elif kind == "smuggling":
        rec["url"] = "/api/health"
        rec["body"] = ""
    elif kind == "tls":
        rec["url"] = "/"
        rec["body"] = ""
    return rec


def run_collect_cases():
    out = []
    for cid, name, kind in COLLECT_CASES:
        rec = build_collect_case(kind)
        cut = rec.pop("_truncate_at", 0)
        if cut:
            rec["url"] = rec["url"][:cut]
        hit = len(detect.signature_detect(rec)) > 0
        out.append({"用例": cid, "名称": name, "命中": hit,
                    "说明": "已检出" if hit else "采集层缺失，检测层无输入"})
    return out


def run_adversarial():
    total = 0
    bypassed = 0
    by_mut = collections.defaultdict(lambda: [0, 0])    # 手法 -> [总数, 绕过数]
    by_cat = collections.defaultdict(lambda: [0, 0])    # 载荷类别 -> [总数, 绕过数]
    by_group = collections.defaultdict(lambda: [0, 0])  # 手法大类 -> [总数, 绕过数]
    misses = []
    invalid_total = 0   # 所有"变形后已不是同一攻击"的用例（测试工具问题）
    invalid_missed = 0  # 其中同时又没被检出的（应从绕过率里剔除）

    all_muts = MUTATIONS + MUTATIONS_V2
    for cat, pos, base in PAYLOADS:
        # 基线：不变形能不能检出
        rec = build_record(base, pos)
        base_hit = len(detect.signature_detect(rec)) > 0
        if not base_hit:
            # 原始写法都检不出，说明这条规则本身对该类载荷无效，记为已知盲区
            by_cat[cat][0] += 1
            by_cat[cat][1] += 1
            misses.append({"载荷类别": cat, "手法": "原始写法", "大类": "基线",
                           "有效性": True, "无效原因": ""})
            total += 1
            bypassed += 1

        for mid, mname, fn, group in all_muts:
            try:
                variant = fn(base)
            except Exception:
                continue
            if variant == base:
                continue
            rec = build_record(variant, pos)
            hit = len(detect.signature_detect(rec)) > 0
            # 有效性校验对**每一个**变形都跑，而不只是对漏报的跑。
            # 只在漏报分支里跑的话，一旦绕过率归零，这个校验就一次都不执行——
            # "无效变形 0"会变成一个没有验证过任何东西的漂亮数字。
            ok, why = variant_effectiveness(base, variant)
            if not ok:
                invalid_total += 1
            total += 1
            by_mut[mname][0] += 1
            by_cat[cat][0] += 1
            by_group[group][0] += 1
            if not hit:
                bypassed += 1
                by_mut[mname][1] += 1
                by_cat[cat][1] += 1
                by_group[group][1] += 1
                if not ok:
                    invalid_missed += 1
                misses.append({"载荷类别": cat, "手法": mname, "手法ID": mid,
                               "大类": group, "有效性": ok, "无效原因": why})

    # 协议层：同样的载荷换个字段，检测还看得见吗
    proto = []
    for pid, pname, field, pos, payload in PROTOCOL_CASES:
        rec = build_protocol_record(field, payload)
        hit = len(detect.signature_detect(rec)) > 0
        proto.append({"用例": pid, "名称": pname, "字段": field, "命中": hit})
        total += 1
        if not hit:
            bypassed += 1

    # UA 专项
    ua_res = []
    for name, ua in UA_CASES:
        rec = build_record("x", "q")
        rec["ua"] = ua
        hit = len(detect.signature_detect(rec)) > 0
        expect = name != "正常浏览器"
        ua_res.append({"UA类型": name, "命中": hit, "应当命中": expect})

    res = {
        "时间": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "总用例": total,
        "绕过数": bypassed,
        "绕过率": round(bypassed / total * 100, 1) if total else 0,
        # 修正口径：把"变形后已不是同一攻击"的用例从分子分母一起剔除。
        # 这些是测试工具的产物，不是检测引擎的能力边界。
        "无效变形数": invalid_total,
        "其中未检出": invalid_missed,
        "修正后绕过数": bypassed - invalid_missed,
        "修正后绕过率": (round((bypassed - invalid_missed) / (total - invalid_missed) * 100, 1)
                         if total - invalid_missed else 0),
        "按手法": {k: {"总数": v[0], "绕过": v[1],
                       "绕过率": round(v[1] / v[0] * 100, 1) if v[0] else 0}
                   for k, v in sorted(by_mut.items(), key=lambda x: -x[1][1])},
        "按手法大类": {k: {"总数": v[0], "绕过": v[1],
                          "绕过率": round(v[1] / v[0] * 100, 1) if v[0] else 0}
                      for k, v in sorted(by_group.items(), key=lambda x: -x[1][1])},
        "按载荷类别": {k: {"总数": v[0], "绕过": v[1],
                          "绕过率": round(v[1] / v[0] * 100, 1) if v[0] else 0}
                      for k, v in sorted(by_cat.items(), key=lambda x: -x[1][1])},
        "UA专项": ua_res,
        "协议层": proto,
        "采集层盲区": run_collect_cases(),
        "绕过清单": misses,
    }
    with io.open(RESULT_PATH, "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    return res


def show(res, show_miss):
    print("\n" + "=" * 58)
    print("自我对抗测试：用 %d 种变形手法攻击自己的检测规则" % len(MUTATIONS))
    print("=" * 58)
    print("总用例 %d 条，绕过成功 %d 条 —— 绕过率 %.1f%%"
          % (res["总用例"], res["绕过数"], res["绕过率"]))
    if res.get("无效变形数"):
        print("其中 %d 条经有效性校验判定为「变形后已不是同一攻击」（测试工具问题），"
              % res["无效变形数"])
        print("剔除后：绕过 %d 条 —— 修正绕过率 %.1f%%"
              % (res["修正后绕过数"], res["修正后绕过率"]))
    print()
    print("【按手法大类看盲区】")
    print("  %-14s %6s %6s %8s" % ("大类", "用例", "绕过", "绕过率"))
    for k, v in res["按手法大类"].items():
        print("  %-14s %6d %6d %7.1f%%" % (k, v["总数"], v["绕过"], v["绕过率"]))
    print()
    print("【最有效的 8 种绕过手法】")
    for k, v in list(res["按手法"].items())[:8]:
        print("  %-24s 绕过 %2d/%-2d  (%.1f%%)"
              % (k, v["绕过"], v["总数"], v["绕过率"]))
    print()
    print("【哪类攻击最防不住】")
    for k, v in list(res["按载荷类别"].items())[:8]:
        print("  %-20s 绕过 %2d/%-2d  (%.1f%%)"
              % (k, v["绕过"], v["总数"], v["绕过率"]))
    print()
    print("【UA 指纹规则 R2 专项】")
    for r in res["UA专项"]:
        ok = "正确" if r["命中"] == r["应当命中"] else "★异常★"
        print("  %-12s 命中=%-5s 应当命中=%-5s  %s"
              % (r["UA类型"], r["命中"], r["应当命中"], ok))
    print()
    print("\n【协议层专项：换个字段还看得见吗】")
    for r in res["协议层"]:
        flag = "✅检出" if r["命中"] else "❌隐身"
        print("  %-28s %-18s %s" % (r["名称"], r["字段"], flag))
    print()
    if res.get("采集层盲区"):
        print("\n【采集层盲区：这部分不是检测规则能解决的】")
        for r in res["采集层盲区"]:
            flag = "✅检出" if r["命中"] else "❌不可见"
            print("  %-4s %-34s %-8s %s" % (r["用例"], r["名称"], flag, r["说明"]))
        print()
    print("结果已写入：%s" % RESULT_PATH)
    if show_miss:
        print("\n【绕过成功清单（按手法归类，不含载荷原文）】")
        agg = collections.Counter((m["大类"], m["手法"]) for m in res["绕过清单"])
        for (g, m), c in agg.most_common():
            print("  %-12s %-24s x%d" % (g, m, c))
    print("=" * 58)


def main():
    show_miss = "--show-miss" in sys.argv
    res = run_adversarial()
    show(res, show_miss)


if __name__ == "__main__":
    main()
