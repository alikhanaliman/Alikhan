"""PhysiX pilot platform: Flask + SQLite, session authentication and role-based access.
Run: pip install -r requirements.txt && python app.py
"""
import hmac
import json
import os
import re
import secrets
import sqlite3
from datetime import datetime, timezone, timedelta
from functools import wraps
from pathlib import Path
from uuid import uuid4

from flask import Flask, g, jsonify, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

BASE = Path(__file__).resolve().parent
INSTANCE = Path(os.environ.get('PHYSIX_DATA_DIR', BASE / 'instance')).resolve()
INSTANCE.mkdir(parents=True, exist_ok=True)
DB_PATH = INSTANCE / 'physix.db'

def load_secret():
    if os.environ.get('PHYSIX_SECRET_KEY'):
        return os.environ['PHYSIX_SECRET_KEY']
    path = INSTANCE / '.session_secret'
    if not path.exists():
        try:
            with path.open('x', encoding='utf-8') as fp:
                fp.write(secrets.token_hex(48))
            try: path.chmod(0o600)
            except OSError: pass
        except FileExistsError:
            pass
    return path.read_text(encoding='utf-8').strip()

app = Flask(__name__, static_folder=None)
app.config.update(
    SECRET_KEY=load_secret(),
    MAX_CONTENT_LENGTH=160 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('PHYSIX_COOKIE_SECURE') == '1',
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
)

SCHEMA = '''
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('student', 'curator')),
    curator_code TEXT UNIQUE,
    curator_id TEXT REFERENCES users(id),
    joined TEXT NOT NULL,
    last_active TEXT,
    progress_json TEXT NOT NULL DEFAULT '{}',
    is_demo INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS notes (
    curator_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    student_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (curator_id, student_id)
);
CREATE INDEX IF NOT EXISTS students_curator_idx ON users(curator_id);
'''

def now(): return datetime.now(timezone.utc).isoformat(timespec='seconds')

def connection():
    if 'db' not in g:
        g.db = sqlite3.connect(str(DB_PATH), timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys=ON')
    return g.db

@app.teardown_appcontext
def close_connection(_error):
    db = g.pop('db', None)
    if db is not None: db.close()

with app.app_context():
    connection().executescript(SCHEMA)
    connection().commit()

def problem(message, status=400):
    return jsonify(error=message), status

def body_json():
    return request.get_json(silent=True) if request.is_json else None

def empty_progress():
    return {'done': [], 'quizzes': {}, 'problems': [], 'labsDone': [], 'labsScores': {}}

def read_progress(raw):
    try:
        obj = json.loads(raw)
        return obj if isinstance(obj, dict) else empty_progress()
    except (ValueError, TypeError):
        return empty_progress()

def clean_progress(p):
    if not isinstance(p, dict): raise ValueError('Прогресс пішімі қате')
    def strings(key, max_items):
        items = p.get(key, [])
        if not isinstance(items, list): raise ValueError(key)
        return list(dict.fromkeys(v for v in items[:max_items] if isinstance(v, str) and len(v) <= 80))
    done = strings('done', 150)
    problems = strings('problems', 300)
    labs_done = p.get('labsDone', [])
    if not isinstance(labs_done, list): raise ValueError('labsDone')
    labs_done = list(dict.fromkeys(v for v in labs_done[:100] if type(v) is int and 0 <= v < 100))
    scores = p.get('quizzes', {})
    if not isinstance(scores, dict): raise ValueError('quizzes')
    clean_scores = {}
    for k, v in list(scores.items())[:150]:
        if not isinstance(k, str) or len(k) > 80 or not isinstance(v, dict): continue
        try:
            score = max(0, min(5, int(v.get('score', 0))))
            percent = max(0, min(100, int(v.get('percent', 0))))
            date = str(v.get('date', ''))[:48]
        except (ValueError, TypeError): continue
        clean_scores[k] = {'score': score, 'percent': percent, 'date': date}
    labs_scores = p.get('labsScores', {})
    if not isinstance(labs_scores, dict): raise ValueError('labsScores')
    # Laboratory measurements, conclusions and table rows may vary by exercise.
    clean_labs = {}
    for k, v in list(labs_scores.items())[:100]:
        if not isinstance(k, str) or len(k) > 20: continue
        serial = json.dumps(v, ensure_ascii=False)
        if len(serial) <= 5000: clean_labs[k] = v
    return {'done': done, 'quizzes': clean_scores, 'problems': problems,
            'labsDone': labs_done, 'labsScores': clean_labs}

def public_user(row):
    return {'id': row['id'], 'name': row['name'], 'email': row['email'],
            'role': row['role'], 'joined': row['joined'], 'lastActive': row['last_active'],
            'curatorCode': row['curator_code'] if row['role'] == 'curator' else None,
            'curatorId': row['curator_id'] if row['role'] == 'student' else None,
            'isDemo': bool(row['is_demo'])}

def user_row():
    user_id = session.get('user_id')
    return connection().execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone() if user_id else None

def require_role(role=None):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user = user_row()
            if user is None: return problem('Алдымен жүйеге кіріңіз', 401)
            if role is not None and user['role'] != role: return problem('Рұқсат жоқ', 403)
            return func(user, *args, **kwargs)
        return wrapper
    return decorator

@app.before_request
def csrf_guard():
    if 'csrf' not in session: session['csrf'] = secrets.token_urlsafe(32)
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        token = request.headers.get('X-CSRF-Token', '')
        if not hmac.compare_digest(token, session.get('csrf', '')):
            return problem('Бетті қайта жүктеп, қайталап көріңіз (CSRF)', 403)

@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'same-origin'
    response.headers['X-Frame-Options'] = 'DENY'
    if request.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store'
    return response

@app.get('/')
def homepage():
    return send_from_directory(str(BASE / 'static'), 'index.html')

@app.get('/api/me')
def me():
    u = user_row()
    result = {'user': public_user(u) if u else None, 'csrf': session['csrf']}
    if u and u['role'] == 'student': result['progress'] = read_progress(u['progress_json'])
    return jsonify(result)

EMAIL = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')
CODE = re.compile(r'^[A-Z0-9]{8}$')

def get_curator_by_code(raw):
    code = str(raw or '').strip().upper()
    if not code: return None
    if not CODE.fullmatch(code): return None
    return connection().execute('SELECT id FROM users WHERE role=? AND curator_code=?', ('curator', code)).fetchone()

@app.post('/api/register')
def register():
    data = body_json()
    if not isinstance(data, dict): return problem('JSON пішімі қате')
    name = str(data.get('name', '')).strip()
    email = str(data.get('email', '')).strip().lower()
    password = data.get('password')
    role = data.get('role')
    code = str(data.get('curatorCode') or '').strip().upper()
    if len(name) < 2 or len(name) > 90: return problem('Аты-жөніңізді дұрыс енгізіңіз (2–90 таңба)')
    if len(email) > 120 or not EMAIL.fullmatch(email): return problem('Email дұрыс емес')
    if not isinstance(password, str) or not (8 <= len(password) <= 128): return problem('Пароль кемінде 8 таңбадан тұруы керек')
    if role not in ('student', 'curator'): return problem('Рөл дұрыс емес')
    curator = get_curator_by_code(code) if role == 'student' else None
    if code and role == 'student' and curator is None: return problem('Куратор коды табылмады')
    new_code = None
    if role == 'curator':
        chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
        while True:
            candidate = ''.join(secrets.choice(chars) for _ in range(8))
            if not connection().execute('SELECT id FROM users WHERE curator_code=?',(candidate,)).fetchone():
                new_code = candidate;break
    uid = uuid4().hex
    try:
        with connection():
            connection().execute('INSERT INTO users (id,name,email,password_hash,role,curator_code,curator_id,joined,progress_json) VALUES (?,?,?,?,?,?,?,?,?)',
                (uid, name, email, generate_password_hash(password), role, new_code, curator['id'] if curator else None, now(), json.dumps(empty_progress())))
    except sqlite3.IntegrityError:
        return problem('Бұл email бұрын тіркелген. «Кіру» бөлімін пайдаланыңыз', 409)
    # Registration only creates an account. The user must then log in with their new password.
    return jsonify(ok=True, message='Тіркелу аяқталды. Енді email және пароль арқылы кіріңіз.', csrf=session['csrf']), 201

@app.post('/api/login')
def login():
    data = body_json()
    if not isinstance(data, dict): return problem('Деректер дұрыс емес')
    email = str(data.get('email', '')).strip().lower()
    password = data.get('password')
    if not isinstance(password, str): return problem('Email немесе пароль дұрыс емес', 401)
    row = connection().execute('SELECT * FROM users WHERE email=? AND is_demo=0', (email,)).fetchone()
    if not row or not check_password_hash(row['password_hash'], password):
        return problem('Email немесе пароль дұрыс емес', 401)
    session.clear(); session['csrf'] = secrets.token_urlsafe(32);session['user_id'] = row['id']; session.permanent = True
    return jsonify(user=public_user(row), progress=read_progress(row['progress_json']) if row['role']=='student' else None, csrf=session['csrf'])

@app.post('/api/logout')
@require_role()
def logout(_user):
    session.clear();session['csrf'] = secrets.token_urlsafe(32)
    return jsonify(ok=True, csrf=session['csrf'])

@app.put('/api/progress')
@require_role('student')
def save_progress(user):
    data = body_json()
    try:
        progress = clean_progress(data)
    except (ValueError, TypeError):
        return problem('Прогресс деректері дұрыс емес')
    last = now()
    with connection():
        connection().execute('UPDATE users SET progress_json=?,last_active=? WHERE id=?',
                             (json.dumps(progress, ensure_ascii=False), last, user['id']))
    return jsonify(ok=True, savedAt=last)

@app.post('/api/student/join')
@require_role('student')
def join_curator(user):
    data = body_json() or {}
    curator = get_curator_by_code(data.get('code'))
    if curator is None: return problem('Куратор коды табылмады', 404)
    with connection():
        connection().execute('UPDATE users SET curator_id=? WHERE id=?', (curator['id'], user['id']))
    return jsonify(ok=True, curatorId=curator['id'])

@app.get('/api/students')
@require_role('curator')
def students(user):
    rows = connection().execute('''SELECT u.*, COALESCE(n.body, '') AS note FROM users u
              LEFT JOIN notes n ON n.student_id=u.id AND n.curator_id=?
              WHERE u.role='student' AND u.curator_id=? ORDER BY u.joined DESC''', (user['id'], user['id'])).fetchall()
    results = []
    for row in rows:
        d = public_user(row)
        d.update(progress=read_progress(row['progress_json']), note=row['note'])
        results.append(d)
    return jsonify(students=results)

@app.put('/api/students/<student_id>/note')
@require_role('curator')
def save_note(user, student_id):
    student = connection().execute("SELECT id FROM users WHERE id=? AND role='student' AND curator_id=?", (student_id, user['id'])).fetchone()
    if not student: return problem('Оқушы табылмады', 404)
    data = body_json() or {}
    note = data.get('note')
    if not isinstance(note, str) or len(note) > 1500: return problem('Жазба 1500 таңбадан аспасын')
    with connection():
        connection().execute('INSERT INTO notes(curator_id,student_id,body) VALUES (?,?,?) ON CONFLICT(curator_id,student_id) DO UPDATE SET body=excluded.body',
                             (user['id'], student_id, note))
    return jsonify(ok=True)

@app.post('/api/curator/demo')
@require_role('curator')
def curator_demo(user):
    examples = [('Айдана Ермек', 'aydana', 11, [90, 80, 100]),
                ('Нұрсұлтан Әли', 'nursultan', 5, [60, 80]),
                ('Мәдина Болат', 'madina', 0, [])]
    topic_ids = ['k'+str(i) for i in range(1, 9)] + ['d'+str(i) for i in range(1, 10)] + ['s'+str(i) for i in range(1, 6)]
    created = 0
    with connection():
        for name, suffix, n, marks in examples:
            email = f'demo.{suffix}.{user["id"][:10]}@physix.example'
            if connection().execute('SELECT id FROM users WHERE email=?', (email,)).fetchone(): continue
            quizzes = {topic_ids[i]: {'score': mark//20, 'percent':mark, 'date':now()} for i,mark in enumerate(marks)}
            progress = {'done':topic_ids[:n], 'quizzes':quizzes, 'problems':['p1'] if n else [],
                        'labsDone':[0] if n > 5 else [], 'labsScores':{}}
            connection().execute('INSERT INTO users (id,name,email,password_hash,role,curator_id,joined,last_active,progress_json,is_demo) VALUES (?,?,?,?,?,?,?,?,?,1)',
                (uuid4().hex,name,email,generate_password_hash(secrets.token_urlsafe(32)), 'student',user['id'],now(),now() if n else None,json.dumps(progress)))
            created += 1
    return jsonify(created=created)

if __name__ == '__main__':
    print('PhysiX: http://127.0.0.1:5000')
    app.run(host=os.environ.get('PHYSIX_HOST', '127.0.0.1'), port=int(os.environ.get('PHYSIX_PORT', '5000')), debug=False)
