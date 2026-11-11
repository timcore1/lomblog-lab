# -*- coding: utf-8 -*-
"""Таск 10: race condition (TOCTOU) в лайках.

50 потоков бьют POST /like/<id> с одной и той же сессионной кукой.
Сервер не хранит «кто лайкал» — проверка живёт только в cookie, поэтому
все параллельные запросы проходят её и накручивают счётчик.

Запуск: python -m unittest discover -s tests -v
"""
import concurrent.futures
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as lab  # noqa: E402

POST_ID = 1
THREADS = 50          # столько одновременных запросов в одной сессии
ROUNDS = 4            # каждый поток повторяет удар, чтобы перекрыть порог 100
EXPECTED_AT_LEAST = THREADS + 1


class RaceConditionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        lab.app.config["TESTING"] = True
        # Обнуляем счётчики у всех постов: тест сам накрутит нужное количество
        with lab.app.app_context():
            db = lab.get_db()
            db.execute("UPDATE posts SET likes=0")
            db.commit()
        # Одна сессия с кукой — как у реального пользователя
        client = lab.app.test_client()
        with client.session_transaction() as sess:
            sess["user_id"] = 2
            sess["username"] = "alice"
        cls.cookie = client.get_cookie("session")

    def make_client(self):
        """Новый test_client с той же сессионной кукой."""
        c = lab.app.test_client()
        c.set_cookie("session", self.cookie.value)
        return c

    def hammer(self, _):
        client = self.make_client()
        codes = []
        self.barrier.wait(timeout=10)  # все 50 стартуют одновременно
        for _ in range(ROUNDS):
            # Клиент контролирует cookie: возвращаем исходную — «чистую» сессию
            client.set_cookie("session", self.cookie.value)
            codes.append(client.post(f"/like/{POST_ID}").status_code)
        return codes

    def test_race_nukes_likes_and_flag_drops(self):
        self.barrier = threading.Barrier(THREADS)
        with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as pool:
            batches = list(pool.map(self.hammer, range(THREADS)))

        codes = [code for batch in batches for code in batch]
        # Все лайки приняты (302 на /post/<id>)
        self.assertTrue(all(code == 302 for code in codes),
                        f"неожиданные коды: {sorted(set(codes))}")

        with lab.app.app_context():
            likes = lab.get_db().execute(
                "SELECT likes FROM posts WHERE id=?", (POST_ID,)).fetchone()["likes"]

        # Главное: «один лайк на сессию» не сработало — счётчик выше числа потоков
        print(f"\nлайков после гонки: {likes} (потоков: {THREADS}, попыток: "
              f"{THREADS * ROUNDS})")
        self.assertGreater(likes, EXPECTED_AT_LEAST,
                           f"лайков {likes}, ожидали > {EXPECTED_AT_LEAST}")

        # Порог пройден → ручка отдаёт флаг
        data = lab.app.test_client().get("/flag/race").get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["flag"], lab.FLAG_RACE)


if __name__ == "__main__":
    unittest.main()
