# Тесты стенда: python -m unittest discover -s tests -v
import os

# Тесты не должны поднимать живой бот-модератор при импорте app.py:
# цепочку таска 11 гоняем вручную (tests/test_boss.py).
os.environ.setdefault("LOMBLOG_BOT", "0")
