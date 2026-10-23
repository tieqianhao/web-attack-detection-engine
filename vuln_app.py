# -*- coding: utf-8 -*-
"""
靶场 Web 应用（故意留有漏洞，仅用于本地检测实验）

用途：为检测平台提供【真实】的访问日志，而不是编造的样本。
安全声明：只监听 127.0.0.1，仅供本机实验，请勿部署到任何公网/生产环境。

启动：
    python vuln_app.py
访问：
    http://127.0.0.1:8080

它会把所有请求以 Nginx combined 格式写入 access.log
"""

import os
import time
import datetime
import sqlite3
from flask import Flask, request, jsonify, make_response

HERE = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(HERE, "access.log")
DB_PATH = os.path.join(HERE, "lab.db")

app = Flask(__name__)


# ---------- 日志：Nginx combined 格式 ----------

def log_request(status=200, size="-"):
    ts = datetime.datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0800")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")
    line = '%s - - [%s] "%s %s %s" %s %s "%s" "%s"\n' % (
        ip, ts, request.method, request.full_path.rstrip("?"),
        request.environ.get("SERVER_PROTOCOL", "HTTP/1.1"),
        status, size,
        request.headers.get("Referer", "-"),
        request.headers.get("User-Agent", "-"),
    )
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line)


# ---------- 数据库初始化 ----------

def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
    cur.execute("DELETE FROM users")
    cur.execute("INSERT INTO users VALUES (1,'admin','S3cr3t-P@ss','admin')")
    cur.execute("INSERT INTO users VALUES (2,'alice','alice123','user')")
    con.commit()
    con.close()


# ---------- 路由 ----------

@app.route("/")
def index():
    log_request(200, 512)
    return jsonify({"msg": "lab app", "endpoints": ["/search", "/user", "/login", "/download", "/comment"]})


@app.route("/search")
def search():
    """故意存在 SQL 注入：字符串拼接进 SQL"""
    q = request.args.get("q", "")
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    dangerous = False
    try:
        sql = "SELECT id, username, role FROM users WHERE username LIKE '%%%s%%'" % q
        cur.execute(sql)
        rows = cur.fetchall()
        dangerous = any(k in q.lower() for k in ("union", "or 1=1", "sleep", "--", "'"))
    except Exception as e:
        rows = []
        dangerous = True
    con.close()
    log_request(200 if not dangerous else 500, 256)
    return jsonify({"q": q, "rows": rows, "sql": sql})


@app.route("/user")
def user():
    id_ = request.args.get("id", "1")
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    try:
        cur.execute("SELECT id, username, role FROM users WHERE id = " + id_)
        rows = cur.fetchall()
    except Exception:
        rows = []
    con.close()
    log_request(200, 128)
    return jsonify({"rows": rows})


@app.route("/login", methods=["GET", "POST"])
def login():
    """登录接口，用于产生爆破与失败日志"""
    u = request.args.get("username") or (request.json or {}).get("username", "")
    p = request.args.get("password") or (request.json or {}).get("password", "")
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT username, role FROM users WHERE username=? AND password=?", (u, p))
    row = cur.fetchone()
    con.close()
    if row:
        log_request(200, 128)
        return jsonify({"ok": True, "user": row[0], "role": row[1]})
    log_request(401, 64)
    return jsonify({"ok": False}), 401


@app.route("/download")
def download():
    """故意存在路径遍历"""
    f = request.args.get("file", "readme.txt")
    dangerous = ".." in f or f.startswith("/")
    log_request(403 if dangerous else 200, 128)
    if dangerous:
        return jsonify({"error": "blocked", "file": f}), 403
    return jsonify({"content": "hello lab"})


@app.route("/comment", methods=["GET", "POST"])
def comment():
    """故意反射 XSS"""
    c = request.args.get("content", "")
    log_request(200, 256)
    resp = make_response("<html><body><div>%s</div></body></html>" % c)
    resp.headers["Content-Type"] = "text/html"
    return resp


if __name__ == "__main__":
    init_db()
    if not os.path.exists(LOG_PATH):
        open(LOG_PATH, "w", encoding="utf-8").close()
    print("=" * 52)
    print("靶场已启动：http://127.0.0.1:8080")
    print("日志文件：%s" % LOG_PATH)
    print("仅监听本机，仅供实验。Ctrl+C 停止")
    print("=" * 52)
    app.run(host="127.0.0.1", port=8080, debug=False)
