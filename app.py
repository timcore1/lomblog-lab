# -*- coding: utf-8 -*-
"""
ЛомБлог — намеренно уязвимое учебное приложение.
ЗАПУСКАТЬ ТОЛЬКО В ИЗОЛИРОВАННОЙ ЛАБЕ. Educational purposes only.
"""
import sqlite3
import os
from datetime import datetime
from urllib.parse import quote
from flask import Flask, request, session, redirect, render_template_string, g, abort
from markupsafe import escape
# ТАСК 8: PyJWT для мини-API (Flask-сессии живут отдельно).
# На Kali/Parrot pip «из коробки» ругается externally-managed-environment:
# тогда либо venv, либо pip install --user --break-system-packages (см. README).
try:
    import jwt
except ModuleNotFoundError:
    raise SystemExit(
        "Не хватает PyJWT.\n"
        "  python -m pip install -r requirements.txt\n"
        "  если pip ругается externally-managed-environment:\n"
        "  python -m pip install --user --break-system-packages 'PyJWT>=2.8'\n"
        "  или создай venv: python -m venv .venv && source .venv/bin/activate\n"
    )

app = Flask(__name__)

# ТАСК 3: секретный ключ захардкожен и слабый. Так делать НЕЛЬЗЯ. Но все делают...
app.secret_key = "supersecret123"

# Чтобы кириллица и эмодзи в JSON-ответах движка были читаемыми, а не \uXXXX
app.json.ensure_ascii = False

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE_DIR, "lomblog.db")
UPLOADS = os.path.join(BASE_DIR, "uploads")  # «материалы курса» для таска 7

FLAG_IDOR = "TIMCORE{id0r_1s_n0t_4_f34tur3}"
FLAG_XSS = "TIMCORE{st0r3d_xss_n0_s4n1t1z3r_b4by}"
FLAG_KEY = "TIMCORE{w34k_s3cr3t_k3y_c00k13_f0rg3d}"
FLAG_BACKUP = "TIMCORE{b4ckup_f1l3s_4r3_publ1c_l0l}"
FLAG_SQLI = "TIMCORE{un10n_s3l3ct_b4by}"
FLAG_SSTI = "TIMCORE{jinja_rce_7x7_49}"
FLAG_TRAVERSAL = "TIMCORE{dot_dot_slash_p4th_tr4v3rs4l}"
FLAG_JWT = "TIMCORE{jwt_n0n3_4lg_w0w}"

# ТАСК 8: секрет подписи JWT намеренно слабый — брутится по словарю
# (jwt_tool / hashcat -m 16500) за пару секунд. Так делать НЕЛЬЗЯ.
JWT_SECRET = "secret"

# ТАСК 6: флаг таска SSTI лежит прямо в конфиге Flask. В UI его нет —
# достаётся только из шаблона: {{config.FLAG_SSTI}} (а {{config}} светит и SECRET_KEY)
app.config["FLAG_SSTI"] = FLAG_SSTI

# --- Геймификация ---
HINT_PENALTY = 20  # столько очков списывается за подсказку к таску
ACHIEVEMENTS = {
    "first_blood": ("Первая кровь", "Сдан первый флаг"),
    "full_clear": ("Полный клир", "Сданы все флаги стенда"),
    "speedrun": ("Скорострел", "Два флага за 10 минут"),
}


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,          -- пароли в открытом виде, классика жанра
        bio TEXT,
        is_admin INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS posts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        body TEXT
    );
    CREATE TABLE IF NOT EXISTS comments(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER,
        author TEXT,
        body TEXT
    );
    -- ТАСК 5: отдельная таблица с флагом. В UI её нет вообще —
    -- достаётся только SQL-инъекцией в поиске (UNION-based).
    CREATE TABLE IF NOT EXISTS secrets(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        flag TEXT
    );
    CREATE TABLE IF NOT EXISTS flags(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE,        -- короткое имя таска: IDOR, XSS, Ключ, Бэкап, SQLi, SSTI, Path
        value TEXT UNIQUE,       -- сам флаг
        points INTEGER NOT NULL,
        hint TEXT
    );
    CREATE TABLE IF NOT EXISTS submissions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        flag_id INTEGER NOT NULL,
        submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, flag_id) -- один и тот же флаг засчитывается один раз
    );
    CREATE TABLE IF NOT EXISTS hints(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        flag_id INTEGER NOT NULL,
        penalty INTEGER NOT NULL DEFAULT 20,
        taken_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, flag_id) -- одна подсказка на таск, штраф берём один раз
    );
    CREATE TABLE IF NOT EXISTS achievements(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        code TEXT NOT NULL,      -- first_blood / full_clear / speedrun
        name TEXT NOT NULL,      -- «Первая кровь» и т.п.
        awarded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, code)
    );
    """)
    if not db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        db.executemany(
            "INSERT INTO users(username,password,bio,is_admin) VALUES(?,?,?,?)",
            [
                ("admin", "admin2026!", FLAG_IDOR, 1),
                ("alice", "qwerty123", "Люблю котиков и SQL", 0),
                ("bob", "bob12345", "CTF-игрок со стажем", 0),
            ],
        )
        db.executemany(
            "INSERT INTO posts(title,body) VALUES(?,?)",
            [
                ("Добро пожаловать в ЛомБлог",
                 "Это учебный стенд. Здесь всё сломано намеренно. Найди флаги!"),
                ("Как я настраивал сервер",
                 "Поставил Flask, открыл порт наружу, бэкапы положил рядом. Что могло пойти не так?"),
            ],
        )
        db.execute(
            "INSERT INTO comments(post_id,author,body) VALUES(?,?,?)",
            (1, "alice", "Первый комментарий! А тут вообще фильтрация есть?"),
        )
    # ТАСК 5: единственная строка с флагом. INSERT OR IGNORE + явный id —
    # чтобы на существующей базе сид не дублировался при каждом старте.
    db.execute("INSERT OR IGNORE INTO secrets(id, flag) VALUES(1, ?)", (FLAG_SQLI,))
    # Флаги сеем ВСЕГДА и идемпотентно: INSERT OR IGNORE + UNIQUE(name),
    # поэтому существующая база доживает без потерь и добивает недостающие таски
    db.executemany(
        "INSERT OR IGNORE INTO flags(name,value,points,hint) VALUES(?,?,?,?)",
        [
            ("IDOR", FLAG_IDOR, 100,
             "Подставь чужой id в URL профиля. Какой id обычно у первого пользователя в БД?"),
            ("XSS", FLAG_XSS, 150,
             "Оставь комментарий с <script>alert(1)</script>. А потом посмотри исходник страницы (Ctrl+U)."),
            ("Ключ", FLAG_KEY, 200,
             "Из чего сделана кука сессии Flask? Чем она подписана и насколько секретен ключ? Погугли flask-unsign."),
            ("Бэкап", FLAG_BACKUP, 100,
             "Стандартные пути: /backup, /dump, /db.sql... или почитай второй пост блога."),
            ("SQLi", FLAG_SQLI, 150,
             "Поле поиска подставляется в SQL как есть. Посмотри, сколько колонок возвращает поиск, "
             "и подгони UNION под это число: таблица secrets(id, flag)."),
            ("SSTI", FLAG_SSTI, 250,
             "Страница /hello?name= клеит имя в шаблон Jinja до рендера. Попробуй {{7*7}}, "
             "а потом {{config}} — там и флаг, и секретный ключ для таска с кукой."),
            ("Path", FLAG_TRAVERSAL, 150,
             "Скачивание в /download клеит путь к имени файла без нормализации. "
             "Попробуй ?file=../flag.txt, а потом почитай соседний app.py."),
            ("JWT", FLAG_JWT, 200,
             "Мини-API: POST /api/login выдаёт JWT, GET /api/admin/flag его проверяет. "
             "Секрет подписи — из словаря (jwt_tool с rockyou.txt), а ещё можно "
             "подменить alg на none и выкинуть подпись."),
        ],
    )
    db.commit()
    db.close()


# ТАСК 7: «материалы курса» в uploads/. Файлы декоративные — реального смысла
# не несут, нужны только чтобы страница /files и скачивание выглядели живыми.
UPLOAD_FILES = {
    "report.txt": (
        "Отчёт по безопасности «ЛомБлога» (черновик)\n"
        "\n"
        "Проверено:\n"
        "  - вход в админку по паролю — ок\n"
        "  - комментарии — ок\n"
        "  - поиск по постам — ок\n"
        "\n"
        "Вывод: серьёзных проблем не обнаружено, можно катить в прод.\n"
        "Подпись: отдел безопасности (шутка за 3000 руб.)\n"
    ),
    "cheatsheet.txt": (
        "Шпаргалка по веб-безопасности (материалы курса)\n"
        "\n"
        "1. Никогда не доверяй пользовательскому вводу.\n"
        "2. Параметризованные запросы — база, а не конкатенация строк.\n"
        "3. Экранируй вывод, а не только вход.\n"
        "4. Файлы, которые отдаёт веб-сервер, держи в отдельной папке.\n"
        "5. Секреты — вне webroot и никогда в git.\n"
        "6. Нормализуй путь перед открытием файла (os.path.realpath + проверка префикса).\n"
        "\n"
        "Курс «Этичный хакинг», модуль 4.\n"
    ),
    "notes.txt": (
        "Заметки к семинару\n"
        "\n"
        "  - Разбирали path traversal: ../ в имени файла — классика жанра.\n"
        "  - Домашка: найти в этом стенде все таски и сдать флаги.\n"
        "  - Не забыть: flask-unsign и подпись куки сессии.\n"
    ),
}


def ensure_lab_files():
    """Идемпотентно создаёт uploads/ с материалами и flag.txt с флагом таска 7."""
    os.makedirs(UPLOADS, exist_ok=True)
    for name, text in UPLOAD_FILES.items():
        path = os.path.join(UPLOADS, name)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
    # ТАСК 7: в нормальном проде такие файлы лежат ВНЕ webroot (или вообще в vault),
    # и уж точно не в корне проекта рядом с кодом. Здесь флаг намеренно положен
    # в каталог приложения, чтобы ../flag.txt из uploads/ вёл прямо к нему.
    # Файл в .gitignore: стенд создаёт его сам при старте, в репозиторий он не едет.
    flag_path = os.path.join(BASE_DIR, "flag.txt")
    if not os.path.exists(flag_path):
        with open(flag_path, "w", encoding="utf-8") as fh:
            fh.write(FLAG_TRAVERSAL + "\n")


BASE = """
<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ЛомБлог</title>
<style>
*{box-sizing:border-box}
body{margin:0;font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#eef1f8;color:#24292f}
header{background:linear-gradient(135deg,#6d28d9,#2563eb);color:#fff;padding:24px 0;box-shadow:0 2px 12px rgba(15,23,42,.25)}
header .wrap{max-width:820px;margin:0 auto;padding:0 20px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}
header h1{margin:0;font-size:1.55rem;letter-spacing:.5px}
header nav{font-size:.92rem}
header a{color:#dbeafe;text-decoration:none}
header a:hover{color:#fff;text-decoration:underline}
header h1 a{color:#fff}
header h1 a:hover{text-decoration:underline}
header b{color:#fff}
main{max-width:820px;margin:28px auto;padding:0 20px}
h2{color:#1e293b}
a{color:#4f46e5}
.post,.comment{background:#fff;border-radius:12px;padding:16px 20px;margin:14px 0;box-shadow:0 1px 4px rgba(15,23,42,.08);border:1px solid #e2e8f0;transition:transform .15s,box-shadow .15s}
.post:hover{transform:translateY(-2px);box-shadow:0 6px 16px rgba(15,23,42,.12)}
.post a{text-decoration:none;font-size:1.05rem}
.comment b{color:#6d28d9}
input,textarea{background:#fff;border:1px solid #cbd5e1;border-radius:8px;padding:10px;width:100%%;margin:6px 0;font-size:.95rem}
input:focus,textarea:focus{outline:2px solid #818cf8;border-color:transparent}
button{background:linear-gradient(135deg,#6d28d9,#2563eb);color:#fff;border:0;border-radius:8px;padding:10px 22px;font-size:.95rem;cursor:pointer;transition:opacity .15s}
button:hover{opacity:.85}
.warn{background:#fef2f2;color:#b91c1c;border:1px solid #fecaca;border-radius:8px;padding:10px 14px}
.muted{color:#64748b;font-size:.85rem}
.pbar{max-width:820px;margin:14px auto 0;padding:0 20px;display:flex;align-items:center;gap:12px;font-size:.82rem;color:#e0e7ff}
.pbar .track{flex:1;height:8px;background:rgba(255,255,255,.25);border-radius:99px;overflow:hidden}
.pbar .fill{height:100%%;border-radius:99px;background:linear-gradient(90deg,#fbbf24,#34d399);transition:width .45s ease}
.pbar .plabel{white-space:nowrap;font-weight:600}
table{width:100%%;border-collapse:collapse;background:#fff;border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;box-shadow:0 1px 4px rgba(15,23,42,.08)}
th,td{padding:10px 14px;text-align:left;border-bottom:1px solid #e2e8f0}
th{background:#f8fafc;color:#1e293b;font-size:.85rem;text-transform:uppercase;letter-spacing:.4px}
tr:last-child td{border-bottom:0}
.board tr.top{background:rgba(251,191,36,.07)}
.board tr.me{background:linear-gradient(90deg,rgba(109,40,217,.14),rgba(37,99,235,.10))}
.board tr.me td:first-child{box-shadow:inset 3px 0 0 #6d28d9}
.board td.place{font-weight:700;color:#475569;font-size:1.05rem;width:78px}
.board td.pts{font-weight:700;color:#4f46e5}
.you{font-size:.72rem;background:linear-gradient(135deg,#6d28d9,#2563eb);color:#fff;border-radius:99px;padding:1px 8px;margin-left:6px}
.task{display:flex;align-items:center;justify-content:space-between;gap:12px;background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:12px 16px;margin:10px 0;box-shadow:0 1px 4px rgba(15,23,42,.06)}
.task.done{background:#f8fffb;border-color:#bbf7d0}
.task .tname{font-weight:600}
.task .tpoints{color:#4f46e5;font-weight:700;font-size:.88rem;white-space:nowrap}
.hint-text{color:#475569;font-size:.85rem;margin-top:8px;background:#fffbeb;border:1px dashed #fcd34d;border-radius:8px;padding:8px 10px;max-width:560px}
.hint-btn{background:linear-gradient(135deg,#f59e0b,#fbbf24);padding:8px 14px;font-size:.85rem;white-space:nowrap}
.ach{background:#fff;border:1px solid #e2e8f0;border-left:4px solid #6d28d9;border-radius:12px;padding:12px 16px;margin:10px 0;box-shadow:0 1px 4px rgba(15,23,42,.08)}
.stats{display:flex;gap:12px;flex-wrap:wrap;margin:14px 0}
.stat{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:12px 18px;min-width:150px;box-shadow:0 1px 4px rgba(15,23,42,.06)}
.stat b{display:block;font-size:1.25rem;color:#1e293b}
.stat span{color:#64748b;font-size:.78rem}
.hero{background:linear-gradient(135deg,#6d28d9,#2563eb);color:#fff;border-radius:16px;padding:26px;box-shadow:0 10px 30px rgba(37,99,235,.25)}
.hero h2{color:#fff;margin:0 0 10px}
.hero p{margin:8px 0;color:#e0e7ff}
.hero .muted{color:#c7d2fe}
.hero-link{color:#e0e7ff;margin-left:12px;font-size:.9rem}
.cta{display:inline-block;margin-top:14px;background:#fff;color:#4c1d95;font-weight:700;text-decoration:none;border-radius:10px;padding:12px 26px;transition:transform .15s}
.cta:hover{transform:translateY(-2px)}
#toasts{position:fixed;top:18px;right:18px;z-index:10000;display:flex;flex-direction:column;gap:10px;max-width:340px}
.toast{padding:12px 16px;border-radius:10px;color:#fff;font-size:.92rem;font-weight:600;box-shadow:0 10px 28px rgba(15,23,42,.28);transition:opacity .3s,transform .3s;animation:pop .22s ease-out}
.toast.good{background:linear-gradient(135deg,#059669,#10b981)}
.toast.bad{background:linear-gradient(135deg,#b91c1c,#ef4444)}
.toast.ach{background:linear-gradient(135deg,#7c3aed,#f59e0b)}
.toast.pen{background:linear-gradient(135deg,#b45309,#f59e0b)}
.toast.hide{opacity:0;transform:translateX(24px)}
@keyframes pop{from{opacity:0;transform:translateY(-10px)}to{opacity:1;transform:none}}
footer{max-width:820px;margin:40px auto;padding:20px;color:#94a3b8;font-size:.85rem;text-align:center}
</style></head><body>
<header><div class="wrap"><h1><a href="/" title="На главную">🥷 ЛомБлог</a></h1><nav>%s</nav></div>%s</header>
<main>%s</main>
<footer>Учебный стенд · только для лаборатории · happy hacking 💣</footer>
<div id="toasts" aria-live="polite"></div>
<script>
(function () {
  var box = document.getElementById('toasts');

  // Тост: 4 секунды на экране, потом плавно уезжает.
  // kind: good (успех) / bad (ошибка) / ach (достижение) / pen (штраф)
  function toast(text, kind) {
    var el = document.createElement('div');
    el.className = 'toast ' + (kind || 'good');
    el.textContent = text;
    box.appendChild(el);
    setTimeout(function () {
      el.classList.add('hide');
      setTimeout(function () { el.remove(); }, 320);
    }, 4000);
  }

  // Конфетти на canvas: без библиотек, живёт ~2.6 c и удаляет себя
  function confetti() {
    var c = document.createElement('canvas');
    c.width = window.innerWidth;
    c.height = window.innerHeight;
    c.style.cssText = 'position:fixed;left:0;top:0;pointer-events:none;z-index:9999';
    document.body.appendChild(c);
    var g = c.getContext('2d');
    var cols = ['#6d28d9', '#2563eb', '#fbbf24', '#10b981', '#ef4444', '#ec4899'];
    var parts = [];
    for (var i = 0; i < 140; i++) {
      parts.push({
        x: c.width / 2 + (Math.random() - .5) * 240,
        y: c.height * .35,
        vx: (Math.random() - .5) * 10,
        vy: -Math.random() * 11 - 3,
        s: 4 + Math.random() * 7,
        r: Math.random() * 6,
        vr: (Math.random() - .5) * .35,
        col: cols[Math.random() * cols.length | 0]
      });
    }
    var t0 = performance.now();
    (function frame(t) {
      g.clearRect(0, 0, c.width, c.height);
      for (var i = 0; i < parts.length; i++) {
        var p = parts[i];
        p.vy += .25; p.x += p.vx; p.y += p.vy; p.r += p.vr;
        g.save();
        g.translate(p.x, p.y);
        g.rotate(p.r);
        g.fillStyle = p.col;
        g.fillRect(-p.s / 2, -p.s / 2, p.s, p.s * .6);
        g.restore();
      }
      if (t - t0 < 2600) { requestAnimationFrame(frame); } else { c.remove(); }
    })(t0);
  }

  // Очки в шапке: сервер присылает точное значение (с учётом штрафов)
  function setPoints(pts) {
    var np = document.getElementById('nav-points');
    if (np) { np.textContent = '⭐ Очки: ' + pts; }
    var pr = document.getElementById('progress');
    if (pr) { pr.dataset.points = pts; }
  }

  // Обновляем шапку без перезагрузки: очки и прогресс «Флаги: N/4»
  function bump(add, total) {
    var pr = document.getElementById('progress');
    var pts = (pr ? (+pr.dataset.points || 0) : 0) + add;
    if (typeof total === 'number') { pts = total; }
    if (pr) {
      var all = +pr.dataset.total || 0;
      var done = (+pr.dataset.done || 0) + 1;
      if (all && done > all) { done = all; }
      pr.dataset.done = done;
      var pct = all ? Math.round(done * 100 / all) : 0;
      pr.querySelector('.fill').style.width = pct + '%%';
      pr.querySelector('.plabel').textContent = 'Флаги: ' + done + '/' + all + ' · ' + pct + '%%';
    }
    setPoints(pts);
  }

  // Сдача флага: форма живёт на главной, обработчик — здесь
  document.addEventListener('submit', async function (ev) {
    var f = ev.target;
    if (!f || f.id !== 'flag-form') { return; }
    ev.preventDefault();
    var btn = f.querySelector('button');
    btn.disabled = true;
    try {
      var r = await fetch('/submit', {method: 'POST', body: new FormData(f)});
      var d = await r.json();
      if (d.ok) {
        toast('+' + d.points + ' очков: ' + d.name, 'good');
        confetti();
        f.reset();
        bump(d.points, d.total);
        if (d.achievements && d.achievements.length) {
          d.achievements.forEach(function (a, i) {
            setTimeout(function () { toast('🏆 Достижение: ' + a.name, 'ach'); }, 250 + i * 450);
          });
        }
      } else {
        toast(d.msg || 'Флаг не принят', 'bad');
      }
    } catch (e) {
      toast('Не удалось отправить флаг, попробуй ещё раз', 'bad');
    } finally {
      btn.disabled = false;
    }
  });

  // Подсказка к таску: показываем текст, списываем очки, кнопку убираем
  document.addEventListener('click', async function (ev) {
    var b = ev.target && ev.target.closest ? ev.target.closest('.hint-btn') : null;
    if (!b) { return; }
    ev.preventDefault();
    b.disabled = true;
    var fd = new FormData();
    fd.append('flag_id', b.dataset.flag);
    try {
      var r = await fetch('/hint', {method: 'POST', body: fd});
      var d = await r.json();
      if (d.ok) {
        var el = document.getElementById('hint-' + b.dataset.flag);
        if (el) { el.textContent = d.hint; el.style.display = 'block'; }
        if (d.charged) {
          toast('💡 Подсказка: −' + d.penalty + ' очков', 'pen');
          setPoints(d.total);
        }
        b.remove();
      } else {
        toast(d.msg || 'Подсказка недоступна', 'bad');
        b.disabled = false;
      }
    } catch (e) {
      toast('Не удалось получить подсказку', 'bad');
      b.disabled = false;
    }
  });
})();
</script>
</body></html>
"""


def total_flags():
    return get_db().execute("SELECT COUNT(*) AS n FROM flags").fetchone()["n"]


def user_stats(user_id):
    """Очки (минус штрафы за подсказки), число сданных флагов и сумма штрафов."""
    db = get_db()
    row = db.execute(
        "SELECT COALESCE(SUM(f.points), 0) AS pts, COUNT(s.id) AS cnt "
        "FROM submissions s JOIN flags f ON f.id = s.flag_id "
        "WHERE s.user_id = ?",
        (user_id,),
    ).fetchone()
    pen = db.execute(
        "SELECT COALESCE(SUM(penalty), 0) AS p FROM hints WHERE user_id = ?",
        (user_id,),
    ).fetchone()["p"]
    return {"points": row["pts"] - pen, "gross": row["pts"],
            "solved": row["cnt"], "penalty": pen}


def fmt_span(seconds):
    """Секунды → «2 мин 07 с» / «1 ч 05 мин»."""
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h} ч {m:02d} мин"
    if m:
        return f"{m} мин {s:02d} с"
    return f"{s} с"


def award_achievements(user_id):
    """Выдаёт недостающие достижения и возвращает список новых (для тостов)."""
    db = get_db()
    subs = db.execute(
        "SELECT flag_id, submitted_at FROM submissions WHERE user_id=? "
        "ORDER BY submitted_at, id", (user_id,)).fetchall()
    have = {r["code"] for r in db.execute(
        "SELECT code FROM achievements WHERE user_id=?", (user_id,))}
    got = []
    if subs and "first_blood" not in have:
        got.append("first_blood")
    total = total_flags()
    if total and len({s["flag_id"] for s in subs}) >= total and "full_clear" not in have:
        got.append("full_clear")
    if len(subs) >= 2 and "speedrun" not in have:
        times = []
        for s in subs:
            try:
                times.append(datetime.strptime(s["submitted_at"], "%Y-%m-%d %H:%M:%S"))
            except (TypeError, ValueError):
                pass
        # «Скорострел»: любые две сдачи подряд с разницей не больше 10 минут
        if any((b - a).total_seconds() <= 600 for a, b in zip(times, times[1:])):
            got.append("speedrun")
    for code in got:
        db.execute(
            "INSERT OR IGNORE INTO achievements(user_id,code,name) VALUES(?,?,?)",
            (user_id, code, ACHIEVEMENTS[code][0]))
    if got:
        db.commit()
    return [{"code": c, "name": ACHIEVEMENTS[c][0], "desc": ACHIEVEMENTS[c][1]}
            for c in got]


def nav():
    if session.get("user_id"):
        st = user_stats(session["user_id"])
        return (f"Залогинен как <b>{session['username']}</b> "
                f"(id={session['user_id']}) | "
                f"<a href='/welcome'>🎯 Миссия</a> | "
                f"<a href='/scoreboard'>🏆 Рейтинг</a> | "
                f"<a href='/hello'>👋 Скажи привет</a> | "
                f"<a href='/files'>📁 Материалы</a> | "
                f"<span id='nav-points' title='твои очки'>⭐ Очки: {st['points']}</span> | "
                f"<a href='/profile/{session['user_id']}'>Мой профиль</a> | "
                f"<a href='/logout'>Выйти</a>")
    return ("<a href='/welcome'>🎯 Миссия</a> | "
            "<a href='/scoreboard'>🏆 Рейтинг</a> | "
            "<a href='/hello'>👋 Скажи привет</a> | "
            "<a href='/files'>📁 Материалы</a> | "
            "<a href='/login'>Войти</a> | <a href='/register'>Регистрация</a>")


def progress():
    """Прогресс-бар в шапке: «Флаги: 2/4 · 50%». Гостю не показываем."""
    if not session.get("user_id"):
        return ""
    st = user_stats(session["user_id"])
    total = total_flags()
    done = st["solved"]
    pct = int(round(done * 100.0 / total)) if total else 0
    return (f"<div class='pbar' id='progress' data-done='{done}' "
            f"data-total='{total}' data-points='{st['points']}'>"
            f"<span class='plabel'>Флаги: {done}/{total} · {pct}%</span>"
            f"<div class='track'><div class='fill' style='width:{pct}%'></div></div>"
            f"</div>")


def page(body):
    # Обычные страницы НЕ прогоняем через Jinja: иначе любой {{...}} из БД
    # (подсказки, посты, комменты) исполнится и сольёт флаг/секретный ключ.
    # Шаблонный движок включается только в таске 6 (/hello) — там это и есть дырка.
    return BASE % (nav(), progress(), body)


def search_form(value=""):
    """Форма поиска по постам. Общая для главной и страницы выдачи."""
    # value экранируем: тут нам интересна только SQLi, лишний reflected XSS не нужен
    return (f"<div class='post'>"
            f"<form method='get' action='/search'>"
            f"<input name='q' value='{escape(value)}' autocomplete='off' "
            f"placeholder='Поиск по постам: заголовок или текст...'>"
            f"<button>🔍 Найти</button></form>"
            f"<p class='muted'>Ищем по названию и тексту поста. LIKE всё прощает.</p></div>")


@app.route("/")
def index():
    uid = session.get("user_id")
    if not uid:
        return redirect("/welcome")  # стартовая страница-приветствие
    db = get_db()
    solved = {r["flag_id"] for r in db.execute(
        "SELECT flag_id FROM submissions WHERE user_id=?", (uid,))}
    taken = {r["flag_id"] for r in db.execute(
        "SELECT flag_id FROM hints WHERE user_id=?", (uid,))}
    body = "<h2>Задания</h2>"
    for f in db.execute("SELECT * FROM flags ORDER BY id").fetchall():
        if f["id"] in solved:
            mark = "<span class='tpoints'>✅ сдан</span>"
            hint_html = ""
        elif f["id"] in taken:
            mark = "<span class='tpoints'>💡 подсказка куплена</span>"
            # hint — текст из БД, экранируем: там бывают теги вроде <script>
            hint_html = f"<div class='hint-text'>{escape(f['hint'])}</div>"
        else:
            mark = (f"<button class='hint-btn' data-flag='{f['id']}'>"
                    f"💡 Подсказка −{HINT_PENALTY}</button>")
            hint_html = f"<div class='hint-text' id='hint-{f['id']}' style='display:none'></div>"
        body += (f"<div class='task{' done' if f['id'] in solved else ''}'>"
                 f"<div><div class='tname'>{f['name']}"
                 f" <span class='tpoints'>· {f['points']} очков</span></div>"
                 f"{hint_html}</div>{mark}</div>")
    posts = db.execute("SELECT * FROM posts ORDER BY id").fetchall()
    body += "<h2>Поиск</h2>" + search_form()
    body += "<h2>Посты</h2>" + "".join(
        f"<div class='post'><a href='/post/{p['id']}'><b>{p['title']}</b></a></div>"
        for p in posts)
    # Форма сдачи флага: fetch-обработчик живёт в общем JS в BASE
    body += """
    <h2>Сдать флаг</h2>
    <div class='post'>
      <form id='flag-form'>
        <input name='flag' placeholder='TIMCORE{...}' autocomplete='off' required>
        <button>Проверить</button>
      </form>
      <p class='muted'>Флаг засчитывается один раз. Очки сразу обновятся в шапке и в рейтинге.</p>
    </div>"""
    return page(body)


# ТАСК 5: SQL-инъекция в поиске. Ввод склеивается с запросом через f-строку,
# поэтому через UNION можно вытащить любую таблицу (например, secrets.flag).
@app.route("/search")
def search():
    q = request.args.get("q", "")
    # Колонок в выборке ровно две (id, title) — те же, что рисуем в выдаче.
    # Так UNION-инъекция подходит по числу столбцов: ' UNION SELECT id,flag FROM secrets--
    sql = f"SELECT id, title FROM posts WHERE title LIKE '%{q}%' OR body LIKE '%{q}%'"
    rows = []
    error = ""
    try:
        rows = get_db().execute(sql).fetchall()
    except sqlite3.Error as e:
        # ТАСК 5: текст ошибки БД показываем пользователю как есть —
        # так новичку проще разбирать синтаксис собственного payload'а
        error = str(e)
    if error:
        result = f"<p class='warn'>SQL error: {escape(error)}</p>"
    elif not rows:
        result = "<p class='muted'>Ничего не нашлось.</p>"
    else:
        # без экранирования, как и везде в этом стенде
        result = "".join(
            f"<div class='post'><a href='/post/{r[0]}'><b>{r[1]}</b></a></div>"
            for r in rows)
    return page(f"<h2>Поиск</h2>{search_form(q)}"
                f"<p class='muted'>Запрос: <code>{escape(q)}</code> · найдено: {len(rows)}</p>"
                f"{result}")


# ТАСК 6: SSTI. Имя попадает в текст шаблона f-строкой ДО рендера,
# поэтому Jinja честно исполняет всё, что ввёл пользователь: {{7*7}}, {{config}}...
@app.route("/hello")
def hello():
    name = request.args.get("name", "гость")
    # тело страницы собираем сразу в шаблоне — не экранируем и не проверяем
    return render_template_string(
        BASE % (nav(), progress(), f"<h2>Привет, {name}!</h2>"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        try:
            db = get_db()
            cur = db.execute(
                "INSERT INTO users(username,password,bio) VALUES(?,?,?)",
                (request.form["username"], request.form["password"], ""))
            db.commit()
            session["user_id"] = cur.lastrowid
            session["username"] = request.form["username"]
            session["is_admin"] = 0
            return redirect("/")
        except sqlite3.IntegrityError:
            return page("<p class='warn'>Такой юзер уже есть.</p>")
    return page("""
    <h2>Регистрация</h2>
    <form method=post>
      <input name=username placeholder=username required>
      <input name=password type=password placeholder=password required>
      <button>Создать</button>
    </form>""")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = get_db().execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (request.form["username"], request.form["password"])).fetchone()
        if u:
            session["user_id"] = u["id"]
            session["username"] = u["username"]
            session["is_admin"] = u["is_admin"]
            return redirect("/")
        return page("<p class='warn'>Неверный логин или пароль.</p>")
    return page("""
    <h2>Вход</h2>
    <form method=post>
      <input name=username placeholder=username required>
      <input name=password type=password placeholder=password required>
      <button>Войти</button>
    </form>""")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ===== Мини-API (таск 8): JWT =====
# Отдельный stateless-контур для «мобильного клиента»: Flask-сессии тут не участвуют.
# Обе дыры намеренные: слабый HS256-секрет и приём токенов с alg=none.
@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    u = get_db().execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (username, password)).fetchone()
    if not u:
        return {"ok": False, "error": "invalid credentials"}, 401
    role = "admin" if u["is_admin"] else "user"
    # ТАСК 8: секрет JWT_SECRET слабый, а роль едет в payload без дополнительных проверок
    token = jwt.encode({"user": u["username"], "role": role},
                       JWT_SECRET, algorithm="HS256")
    return {"ok": True, "token": token, "token_type": "Bearer", "role": role}


@app.route("/api/admin/flag")
def api_admin_flag():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return {"ok": False, "error": "Bearer token required"}, 401
    token = auth[len("Bearer "):].strip()
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") == "none":
            # ТАСК 8: доверяем alg из токена и принимаем пустую подпись.
            # Именно так делать НЕЛЬЗЯ: подпись не проверяется вообще.
            payload = jwt.decode(token, options={"verify_signature": False})
        else:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        return {"ok": False, "error": "invalid token"}, 401
    if payload.get("role") != "admin":
        return {"ok": False, "error": "admin only"}, 403
    return {"ok": True, "flag": FLAG_JWT}


@app.route("/post/<int:pid>", methods=["GET", "POST"])
def post(pid):
    db = get_db()
    p = db.execute("SELECT * FROM posts WHERE id=?", (pid,)).fetchone()
    if not p:
        abort(404)
    if request.method == "POST":
        if not session.get("user_id"):
            return redirect("/login")
        # ТАСК 2: комментарий сохраняется и отдаётся БЕЗ фильтрации (stored XSS)
        db.execute("INSERT INTO comments(post_id,author,body) VALUES(?,?,?)",
                   (pid, session["username"], request.form["body"]))
        db.commit()
        return redirect(f"/post/{pid}")
    comments = db.execute(
        "SELECT * FROM comments WHERE post_id=?", (pid,)).fetchall()
    # ТАСК 2 (пасхалка): флаг спрятан в HTML-комментарии
    body = f"""<!-- Никто не читает исходники страниц, правда? {FLAG_XSS} -->
    <h2>{p['title']}</h2><div class='post'>{p['body']}</div>
    <h3>Комментарии</h3>"""
    for c in comments:
        # вставляем сырое тело — никакого экранирования
        body += f"<div class='comment'><b>{c['author']}:</b> {c['body']}</div>"
    body += """
    <form method=post>
      <textarea name=body rows=3 placeholder='Твой комментарий...'></textarea>
      <button>Отправить</button>
    </form>"""
    return page(body)


# ТАСК 1: IDOR — никакой проверки, что профиль принадлежит юзеру
@app.route("/profile/<int:uid>")
def profile(uid):
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not u:
        abort(404)
    # достижения догоняем и по «старым» сдачам (без тостов — это GET)
    award_achievements(uid)
    st = user_stats(uid)
    total = total_flags()
    span = db.execute(
        "SELECT COUNT(*) AS n, MIN(submitted_at) AS a, MAX(submitted_at) AS b "
        "FROM submissions WHERE user_id=?", (uid,)).fetchone()
    duration = "—"
    if span["n"] >= 2:
        try:
            duration = fmt_span((datetime.strptime(span["b"], "%Y-%m-%d %H:%M:%S")
                                 - datetime.strptime(span["a"], "%Y-%m-%d %H:%M:%S")
                                 ).total_seconds())
        except (TypeError, ValueError):
            duration = "—"
    rows = db.execute(
        "SELECT code,name,awarded_at FROM achievements WHERE user_id=? "
        "ORDER BY awarded_at, id", (uid,)).fetchall()
    if rows:
        ach = "".join(
            f"<div class='ach'><b>🏆 {r['name']}</b> "
            f"<span class='muted'>· {r['awarded_at']}</span>"
            f"<div class='muted'>{ACHIEVEMENTS.get(r['code'], ('', ''))[1]}</div></div>"
            for r in rows)
    else:
        ach = "<p class='muted'>Пока пусто. Сдай первый флаг — получишь «Первую кровь».</p>"
    return page(f"""
    <h2>Профиль: {u['username']}</h2>
    <div class='post'>
      <p>ID: {u['id']}</p>
      <p>Bio: {u['bio']}</p>
    </div>
    <div class='stats'>
      <div class='stat'><b>{st['points']}</b><span>очков</span></div>
      <div class='stat'><b>{st['solved']} / {total}</b><span>флагов сдано</span></div>
      <div class='stat'><b>{duration}</b><span>сессия: первая → последняя сдача</span></div>
      <div class='stat'><b>−{st['penalty']}</b><span>штраф за подсказки</span></div>
    </div>
    <h3>Достижения</h3>
    {ach}""")


@app.route("/admin")
def admin():
    if not session.get("is_admin"):
        return page("<p class='warn'>403. Админам только. Попробуй стать админом 😉</p>")
    return page(f"""
    <h2>Админка</h2>
    <div class='post'><p>Поздравляю, ты внутри.</p>
    <p>Флаг: <b>{FLAG_KEY}</b></p></div>""")


# ТАСК 4: «забытый» бэкап базы, доступный всему интернету
@app.route("/backup")
def backup():
    return page("""
    <h2>Backup</h2>
    <p>Скачать дамп базы: <a href='/backup/db.sql'>db.sql</a>
    (админ обещал убрать это из публичного доступа... когда-нибудь)</p>""")


@app.route("/backup/db.sql")
def backup_sql():
    db = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    dump = "-- ЛомБлог backup dump\n-- " + FLAG_BACKUP + "\n"
    for u in users:
        dump += (f"INSERT INTO users VALUES({u['id']},'{u['username']}',"
                 f"'{u['password']}');\n")
    return dump, 200, {"Content-Type": "text/plain; charset=utf-8"}


# ТАСК 7: path traversal. Имя файла клеится к пути БЕЗ нормализации и проверок,
# поэтому ../flag.txt выходит из uploads/ и читает всё, что лежит рядом с app.py.
@app.route("/download")
def download():
    filename = request.args.get("file", "")
    if not filename:
        return redirect("/files")
    # уязвимая строка: os.path.join ничего не нормализует, ".." остаётся как есть
    path = os.path.join(UPLOADS, filename)
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as e:
        # ошибку показываем как есть — путь видно, новичку проще понять, куда он попал
        return page(f"<h2>Скачивание</h2>"
                    f"<p class='warn'>Не удалось открыть файл: {escape(str(e))}</p>"
                    f"<p class='muted'>Путь: <code>{escape(path)}</code></p>"
                    f"<p><a href='/files'>← К материалам курса</a></p>")
    resp = data.decode("utf-8", errors="replace")
    return resp, 200, {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": f"inline; filename=\"{os.path.basename(filename)}\"",
    }


@app.route("/files")
def files():
    """Список «материалов курса» — декоративные txt-файлы из uploads/."""
    try:
        names = sorted(os.listdir(UPLOADS))
    except OSError:
        names = []
    if names:
        items = "".join(
            f"<div class='post'><a href='/download?file={quote(n)}'><b>📄 {escape(n)}</b></a>"
            f" <span class='muted'>· {os.path.getsize(os.path.join(UPLOADS, n))} байт</span></div>"
            for n in names)
    else:
        items = "<p class='muted'>Пока пусто.</p>"
    return page(f"""
    <h2>📁 Материалы курса</h2>
    <p class='muted'>Полезные файлы для студентов. Качаем, читаем, конспектируем.</p>
    {items}""")


# ===== Игровой движок: сдача флагов и рейтинг =====
# Внимание: это НЕ уязвимые задания, а обычная логика проверки флагов.
@app.route("/submit", methods=["POST"])
def submit():
    if not session.get("user_id"):
        return {"ok": False, "msg": "Сначала войди в аккаунт."}, 401
    data = request.get_json(silent=True) or request.form
    value = (data.get("flag") or "").strip()
    db = get_db()
    fl = db.execute("SELECT * FROM flags WHERE value=?", (value,)).fetchone()
    if not fl:
        return {"ok": False, "msg": "Мимо. Флаг не из этого списка."}
    try:
        db.execute("INSERT INTO submissions(user_id,flag_id) VALUES(?,?)",
                   (session["user_id"], fl["id"]))
        db.commit()
    except sqlite3.IntegrityError:
        # сработал UNIQUE(user_id, flag_id) — повторную сдачу не засчитываем
        db.rollback()
        return {"ok": False, "msg": "Уже сдано, не жульничай 😉"}
    earned = award_achievements(session["user_id"])
    return {"ok": True, "points": fl["points"], "name": fl["name"],
            "total": user_stats(session["user_id"])["points"],
            "achievements": earned}


@app.route("/hint", methods=["POST"])
def hint():
    """Подсказка к несданному таску: показываем hint и списываем HINT_PENALTY очков."""
    if not session.get("user_id"):
        return {"ok": False, "msg": "Сначала войди в аккаунт."}, 401
    data = request.get_json(silent=True) or request.form
    try:
        flag_id = int(data.get("flag_id"))
    except (TypeError, ValueError):
        return {"ok": False, "msg": "Неизвестный таск."}, 400
    db = get_db()
    fl = db.execute("SELECT * FROM flags WHERE id=?", (flag_id,)).fetchone()
    if not fl:
        return {"ok": False, "msg": "Неизвестный таск."}, 404
    uid = session["user_id"]
    if db.execute("SELECT 1 FROM submissions WHERE user_id=? AND flag_id=?",
                  (uid, flag_id)).fetchone():
        return {"ok": False, "msg": "Таск уже сдан — подсказка не нужна."}
    # одна подсказка на таск: повторный запрос отдаём бесплатно
    charged = not db.execute("SELECT 1 FROM hints WHERE user_id=? AND flag_id=?",
                             (uid, flag_id)).fetchone()
    if charged:
        db.execute("INSERT INTO hints(user_id,flag_id,penalty) VALUES(?,?,?)",
                   (uid, flag_id, HINT_PENALTY))
        db.commit()
    return {"ok": True, "hint": fl["hint"], "penalty": HINT_PENALTY,
            "charged": charged, "total": user_stats(uid)["points"]}


@app.route("/scoreboard")
def scoreboard():
    # Только те, кто сдал хотя бы один флаг.
    # Очки — за вычетом штрафов за подсказки.
    # Сортировка: очки по убыванию, затем кто раньше сделал последнюю сдачу — выше.
    rows = get_db().execute("""
        SELECT u.id AS uid, u.username AS username,
               COALESCE((SELECT SUM(f.points) FROM submissions s
                         JOIN flags f ON f.id = s.flag_id
                         WHERE s.user_id = u.id), 0)
               - COALESCE((SELECT SUM(h.penalty) FROM hints h
                           WHERE h.user_id = u.id), 0) AS points,
               (SELECT COUNT(*) FROM submissions s WHERE s.user_id = u.id) AS flags_cnt,
               (SELECT MAX(s.submitted_at) FROM submissions s
                WHERE s.user_id = u.id) AS last_at
        FROM users u
        WHERE EXISTS (SELECT 1 FROM submissions s WHERE s.user_id = u.id)
        ORDER BY points DESC, last_at ASC, u.id ASC
    """).fetchall()
    total = total_flags()
    if not rows:
        table = "<p>Пока никто ничего не сдал. Будь первым 🚀</p>"
    else:
        me = session.get("user_id")
        medals = {1: "🥇", 2: "🥈", 3: "🥉"}
        trs = ""
        for i, r in enumerate(rows, 1):
            if r["uid"] == me:
                attrs = " class='me'"
            elif i <= 3:
                attrs = " class='top'"
            else:
                attrs = ""
            you = " <span class='you'>ты</span>" if r["uid"] == me else ""
            place = medals.get(i, str(i))
            trs += (f"<tr{attrs}><td class='place'>{place}</td>"
                    f"<td>{r['username']}{you}</td>"
                    f"<td class='pts'>{r['points']}</td>"
                    f"<td>{r['flags_cnt']} / {total}</td></tr>")
        table = ("<table class='board'><tr><th>Место</th><th>Юзер</th><th>Очки</th>"
                 "<th>Флагов</th></tr>" + trs + "</table>")
    return page(f"<h2>🏆 Рейтинг</h2>"
                f"<p class='muted'>Сортировка: очки, при равенстве — кто раньше "
                f"закрыл последний флаг.</p>{table}")


# ===== Стартовая страница-приветствие =====
@app.route("/welcome")
def welcome():
    flags = get_db().execute("SELECT name, points FROM flags ORDER BY id").fetchall()
    cards = "".join(
        f"<div class='task'><div><div class='tname'>{f['name']}</div></div>"
        f"<span class='tpoints'>{f['points']} очков</span></div>"
        for f in flags)
    logged = bool(session.get("user_id"))
    cta = "/" if logged else "/register"
    extra = "" if logged else " <a href='/login' class='hero-link'>Уже есть аккаунт? Войти</a>"
    return page(f"""
    <div class='hero'>
      <h2>🥷 Миссия «ЛомБлог»</h2>
      <p>Ты — пентестер, которого наняли проверить «ЛомБлог». Заказчик уверяет:
         «у нас современный стек, уязвимостей быть не может».</p>
      <p>Докажи обратное: найди и сдай {len(flags)} флага. Каждый флаг — это реальная
         дыра в этом приложении.</p>
      <p class='muted'>Флаг в формате TIMCORE{{...}} · повторная сдача не засчитывается ·
         подсказка стоит −{HINT_PENALTY} очков</p>
      <a class='cta' href='{cta}'>⚔️ В бой</a>{extra}
    </div>
    <h2>Задания</h2>
    {cards}
    <h2>Правила</h2>
    <div class='post'>
      <p>1. Флаги сдаются на главной странице, форма «Сдать флаг».</p>
      <p>2. Один флаг — одно зачисление, повторы не считаются.</p>
      <p>3. Подсказка к таску: −{HINT_PENALTY} очков, один раз на таск.</p>
      <p>4. Достижения: «Первая кровь», «Скорострел» (2 флага за 10 минут), «Полный клир».</p>
    </div>""")


# Инициализация при старте: идемпотентно создаёт недостающие таблицы и добивает
# флаги, поэтому работает и на уже существующей lomblog.db, и при любом раннере
# (python app.py, flask run, wsgi). ensure_lab_files() докладывает uploads/ и flag.txt.
init_db()
ensure_lab_files()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
