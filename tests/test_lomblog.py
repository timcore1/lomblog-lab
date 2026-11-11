# -*- coding: utf-8 -*-
"""Тесты ЛомБлога: JWT-контур (таск 8) и живучесть старых векторов.

Запуск: python -m unittest discover -s tests -v
"""
import base64
import json
import os
import sys
import threading
import unittest

# Чтобы `python -m unittest discover -s tests` видел app.py из корня проекта
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import jwt  # noqa: E402
from werkzeug.serving import make_server  # noqa: E402

import app as lab  # noqa: E402


def b64url(raw):
    """base64url без padding — как в JWT."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def make_alg_none_token(payload):
    """Собираем неподписанный токен руками: header.payload. (подпись пустая)."""
    header = {"alg": "none", "typ": "JWT"}
    return (b64url(json.dumps(header, separators=(",", ":")).encode())
            + "." + b64url(json.dumps(payload, separators=(",", ":")).encode())
            + ".")


class JwtApiTest(unittest.TestCase):
    def setUp(self):
        lab.app.config["TESTING"] = True
        self.client = lab.app.test_client()

    def login(self, username, password):
        r = self.client.post("/api/login",
                             json={"username": username, "password": password})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        return r.get_json()

    def get_flag(self, token):
        return self.client.get(
            "/api/admin/flag",
            headers={"Authorization": "Bearer " + token})

    def test_admin_login_returns_valid_token_and_flag(self):
        data = self.login("admin", "admin2026!")
        self.assertEqual(data["role"], "admin")
        self.assertEqual(data["token_type"], "Bearer")
        payload = jwt.decode(data["token"], "secret", algorithms=["HS256"])
        self.assertEqual(payload, {"user": "admin", "role": "admin"})
        r = self.get_flag(data["token"])
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json(), {"ok": True, "flag": lab.FLAG_JWT})

    def test_alg_none_token_grants_admin(self):
        token = make_alg_none_token({"user": "student", "role": "admin"})
        self.assertTrue(token.endswith("."))  # подписи нет вообще
        r = self.get_flag(token)
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertEqual(r.get_json()["flag"], lab.FLAG_JWT)

    def test_weak_secret_forged_token_grants_admin(self):
        # Секрет "secret" подбирается словарём — форжим токен без логина
        forged = jwt.encode({"user": "anonymous", "role": "admin"},
                            "secret", algorithm="HS256")
        r = self.get_flag(forged)
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertEqual(r.get_json()["flag"], lab.FLAG_JWT)

    def test_regular_user_is_not_admin(self):
        data = self.login("alice", "qwerty123")
        self.assertEqual(data["role"], "user")
        r = self.get_flag(data["token"])
        self.assertEqual(r.status_code, 403)

    def test_bad_or_missing_token_rejected(self):
        self.assertEqual(self.client.get("/api/admin/flag").status_code, 401)
        r = self.get_flag("not.a.jwt")
        self.assertEqual(r.status_code, 401)
        # Правильная структура, но подпись чужим ключом
        wrong = jwt.encode({"user": "x", "role": "admin"},
                           "wrong-secret", algorithm="HS256")
        self.assertEqual(self.get_flag(wrong).status_code, 401)


class OldVectorsTest(unittest.TestCase):
    """Старые уязвимости должны остаться на месте — стенд не «починили»."""

    def setUp(self):
        lab.app.config["TESTING"] = True
        self.client = lab.app.test_client()

    def test_idor_profile(self):
        r = self.client.get("/profile/1")
        self.assertEqual(r.status_code, 200)
        self.assertIn(lab.FLAG_IDOR, r.get_data(as_text=True))

    def test_stored_xss_flag_in_post_source(self):
        r = self.client.get("/post/1")
        self.assertEqual(r.status_code, 200)
        self.assertIn(lab.FLAG_XSS, r.get_data(as_text=True))

    def test_weak_session_key_admin(self):
        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "admin"
            sess["is_admin"] = 1
        r = self.client.get("/admin")
        self.assertEqual(r.status_code, 200)
        self.assertIn(lab.FLAG_KEY, r.get_data(as_text=True))

    def test_backup_disclosure(self):
        r = self.client.get("/backup/db.sql")
        self.assertEqual(r.status_code, 200)
        self.assertIn(lab.FLAG_BACKUP, r.get_data(as_text=True))

    def test_sqli_union(self):
        r = self.client.get("/search",
                            query_string={"q": "' UNION SELECT id,flag FROM secrets--"})
        self.assertEqual(r.status_code, 200)
        self.assertIn(lab.FLAG_SQLI, r.get_data(as_text=True))

    def test_ssti(self):
        r = self.client.get("/hello", query_string={"name": "{{config.FLAG_SSTI}}"})
        self.assertEqual(r.status_code, 200)
        self.assertIn(lab.FLAG_SSTI, r.get_data(as_text=True))

    def test_path_traversal(self):
        r = self.client.get("/download", query_string={"file": "../flag.txt"})
        self.assertEqual(r.status_code, 200)
        self.assertIn(lab.FLAG_TRAVERSAL, r.get_data(as_text=True))

    def test_jwt_flag_is_registered_in_game(self):
        # Таск 8 виден на главной и в рейтинге — как остальные задания
        with lab.app.app_context():
            row = lab.get_db().execute(
                "SELECT value, points FROM flags WHERE name='JWT'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["value"], lab.FLAG_JWT)
        self.assertGreater(row["points"], 0)


class SsrfTest(unittest.TestCase):
    """Таск 9: превью ссылок ходит куда угодно — в том числе в свой же сервер.

    /preview реально дергает urllib.request, поэтому для проверки поднимаем
    живой сервер на localhost (как в настоящей лабе).
    """

    @classmethod
    def setUpClass(cls):
        import socket

        def port_free(p):
            with socket.socket() as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    s.bind(("127.0.0.1", p))
                    return True
                except OSError:
                    return False

        # По умолчанию — «как в лабе» 5001; если он занят, берём свободный порт
        port = 5001 if port_free(5001) else 0
        try:
            cls.server = make_server("127.0.0.1", port, lab.app, threaded=True)
        except (OSError, SystemExit):
            cls.server = make_server("127.0.0.1", 0, lab.app, threaded=True)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=5)

    def setUp(self):
        lab.app.config["TESTING"] = True
        self.client = lab.app.test_client()

    def preview(self, url):
        return self.client.get("/preview", query_string={"url": url})

    def test_preview_fetches_index_html(self):
        r = self.preview(self.base + "/")
        self.assertEqual(r.status_code, 200)
        html = r.get_data(as_text=True)
        # главная (для гостя — /welcome) отдалась целиком через SSRF
        self.assertIn("ЛомБлог", html)
        self.assertIn("<pre class='preview'>", html)

    def test_preview_reads_internal_metadata(self):
        r = self.preview(self.base + "/internal/metadata")
        self.assertEqual(r.status_code, 200)
        self.assertIn(lab.FLAG_SSRF, r.get_data(as_text=True))

    def test_internal_metadata_is_not_linked_in_ui(self):
        # Защита через сокрытие: роут работает, но ссылки на него нет
        for path in ("/", "/welcome", "/post/1"):
            html = self.client.get(path).get_data(as_text=True)
            self.assertNotIn("/internal/metadata", html)

    def test_preview_shows_connection_error_as_text(self):
        # Порт 1 на localhost закрыт: ошибка должна быть текстом, а не 500
        r = self.preview("http://127.0.0.1:1/nope")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Не удалось получить", r.get_data(as_text=True))

    def test_preview_form_on_post_page(self):
        html = self.client.get("/post/1").get_data(as_text=True)
        self.assertIn("action='/preview'", html)
        self.assertIn("name='url'", html)

    def test_ssrf_flag_is_registered_in_game(self):
        with lab.app.app_context():
            row = lab.get_db().execute(
                "SELECT value, points FROM flags WHERE name='SSRF'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["value"], lab.FLAG_SSRF)
        self.assertGreater(row["points"], 0)


class LikeTest(unittest.TestCase):
    """Таск 10: одиночный лайк и UI (сам race condition живёт в test_race.py)."""

    POST_ID = 2

    def setUp(self):
        lab.app.config["TESTING"] = True
        self.client = lab.app.test_client()
        with lab.app.app_context():
            db = lab.get_db()
            db.execute("UPDATE posts SET likes=0 WHERE id=?", (self.POST_ID,))
            db.commit()

    def likes(self):
        with lab.app.app_context():
            return lab.get_db().execute(
                "SELECT likes FROM posts WHERE id=?", (self.POST_ID,)).fetchone()["likes"]

    def test_single_like_increments_by_one(self):
        with self.client.session_transaction() as sess:
            sess["user_id"] = 2
            sess["username"] = "alice"
        before = self.likes()
        r = self.client.post(f"/like/{self.POST_ID}")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.likes(), before + 1)

    def test_second_like_in_same_session_is_blocked(self):
        with self.client.session_transaction() as sess:
            sess["user_id"] = 2
            sess["username"] = "alice"
        self.client.post(f"/like/{self.POST_ID}")
        after_first = self.likes()
        self.client.post(f"/like/{self.POST_ID}")
        self.assertEqual(self.likes(), after_first)

    def test_like_button_is_on_index_and_post_page(self):
        with self.client.session_transaction() as sess:
            sess["user_id"] = 2
            sess["username"] = "alice"
        index_html = self.client.get("/").get_data(as_text=True)
        post_html = self.client.get(f"/post/{self.POST_ID}").get_data(as_text=True)
        for html in (index_html, post_html):
            self.assertIn(f"action='/like/{self.POST_ID}'", html)
            self.assertIn("like-btn", html)

    def test_race_flag_page_hints_until_threshold(self):
        with lab.app.app_context():
            db = lab.get_db()
            db.execute("UPDATE posts SET likes=0")
            db.commit()
        data = self.client.get("/flag/race").get_json()
        self.assertFalse(data["ok"])
        self.assertEqual(data["need"], lab.RACE_TARGET)
        self.assertIn("не хватает", data["hint"])

    def test_race_flag_is_registered_in_game(self):
        with lab.app.app_context():
            row = lab.get_db().execute(
                "SELECT value, points FROM flags WHERE name='Race'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["value"], lab.FLAG_RACE)
        self.assertGreater(row["points"], 0)

    def test_likes_column_exists_in_schema(self):
        # Миграция должна работать и на базе, созданной до таска 10
        with lab.app.app_context():
            cols = [r[1] for r in lab.get_db().execute("PRAGMA table_info(posts)")]
        self.assertIn("likes", cols)


if __name__ == "__main__":
    unittest.main()
