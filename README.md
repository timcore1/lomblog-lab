&lt;p align="center"&gt;
  &lt;img src=".github/banner.png" alt="ЛомБлог — учебный уязвимый стенд" width="100%"&gt;
&lt;/p&gt;

&lt;h1 align="center"&gt;🥷 ЛомБлог&lt;/h1&gt;

&lt;p align="center"&gt;
  Намеренно уязвимый веб-блог для обучения пентесту.&lt;br&gt;
  4 таска · флаги · Docker за 30 секунд · ноль зависимостей кроме Flask
&lt;/p&gt;

&lt;p align="center"&gt;
  &lt;a href="LICENSE"&gt;&lt;img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"&gt;&lt;/a&gt;
  &lt;img src="https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white" alt="Python"&gt;
  &lt;img src="https://img.shields.io/badge/flask-3.x-000000?logo=flask&logoColor=white" alt="Flask"&gt;
  &lt;img src="https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white" alt="Docker"&gt;
  &lt;img src="https://img.shields.io/badge/CTF-4%20flags-6d28d9" alt="CTF"&gt;
&lt;/p&gt;

---

&gt; ⚠️ **ВНИМАНИЕ:** намеренно уязвимое учебное приложение. Запускать **только
&gt; в изолированной среде** (VM / Docker / localhost). Никогда не выкатывать
&gt; в открытую сеть и не тащить этот код в прод. Никогда.

## 🎯 Что это

Учебный стенд для курса по этичному хакингу. Минималистичный блог на Flask,
в котором «случайно» забыли про безопасность. Твоя задача — найти все
уязвимости и собрать флаги формата `TIMCORE{...}`.

Подходит для:
- 📚 лабораторных работ по веб-безопасности
- 🚩 тренировки перед CTF
- 🎓 демонстрации OWASP Top 10 на пальцах

## 🗺️ Задания

| # | Таск | Категория | Сложность |
|---|------|-----------|-----------|
| 1 | Прочитай чужой профиль | Broken Access Control (IDOR) | ⭐ |
| 2 | Заставь блог выполнить твой JS | Stored XSS | ⭐⭐ |
| 3 | Войди в админку без пароля | Слабая криптография сессий | ⭐⭐⭐ |
| 4 | Найди «забытый» бэкап | Information Disclosure | ⭐ |

Дыр больше, чем заданий — бонусы тем, кто смотрит шире списка. 😉

## 🚀 Quickstart

### Docker (рекомендуется)

```bash
git clone https://github.com/TIMCORE/lomblog-lab.git
cd lomblog-lab
docker build -t lomblog .
docker run --rm -p 5001:5001 lomblog
```

### Локально

```bash
pip install -r requirements.txt
python app.py
```

Открывай http://127.0.0.1:5001 — и в бой. Прокси на Burp Suite / ZAP
настраивается по вкусу. 😎

## 📸 Скриншоты

&lt;p align="center"&gt;
  &lt;img src=".github/screenshot-main.png" width="45%" alt="Главная"&gt;
  &lt;img src=".github/screenshot-post.png" width="45%" alt="Комментарии"&gt;
&lt;/p&gt;

## 📁 Структура

```
lomblog-lab/
├── app.py              # весь стенд — один файл (~250 строк)
├── requirements.txt    # flask, и всё
├── Dockerfile          # python:3.12-slim, multi-arch
└── README.md
```

Один файл — не баг, а фича: код читается за 10 минут, каждая уязвимость
помечена комментарием. Идеально для разбора на паре.

## 🎓 Для преподавателей

Стенд используется в живом курсе. Если берёте для своих занятий — звёздочка
репозиторию согреет автору душу, а issue с идеями тасков — ещё сильнее.
Решения не публикуются: не портите игру студентам. 🤫

## 🗺️ Roadmap

- [ ] Игровой режим: автопроверка флагов, очки, scoreboard
- [ ] Достижения и подсказки за очки
- [ ] Новые таски: SSTI, JWT, SSRF
- [ ] Attack-Defense режим для командных зачётов

## 🤝 Contributing

PR приветствуются — новые уязвимости, улучшения фронта, переводы.
Правило одно: каждая дыра должна быть реалистичной и помеченной
комментарием.

## ⚖️ Дисклеймер

Проект создан исключительно в образовательных целях. Автор не несёт
ответственности за использование вне учебной лаборатории. Взлом систем
без разрешения владельца — уголовно наказуем. Ломайте только то, что вам
принадлежит. Stay legal. 💣

## 📄 License

MIT © Timcore
