"""
VULNERABLE Task Management API (Browser Version)
Includes:
1. SQL Injection (search)
2. XSS (reflected in task view)
3. IDOR (no ownership check)
"""

from flask import Flask, request, jsonify, render_template, redirect, session
import sqlite3
import hashlib
import jwt

app = Flask(__name__)
app.secret_key = "weaksecret"

JWT_SECRET = "secret123"

# ---------------- DATABASE ----------------
def init_db():
    conn = sqlite3.connect('tasks.db')
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE,
                  password TEXT)''')

    c.execute('''CREATE TABLE IF NOT EXISTS tasks
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  title TEXT,
                  description TEXT)''')

    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect('tasks.db')
    conn.row_factory = sqlite3.Row
    return conn


# ---------------- HOME ----------------
@app.route('/')
def home():
    return render_template('login.html')


# ---------------- REGISTER (simple API) ----------------
@app.route('/register', methods=['POST'])
def register():
    data = request.form
    username = data['username']
    password = hashlib.sha256(data['password'].encode()).hexdigest()

    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)",
              (username, password))
    conn.commit()
    conn.close()

    return redirect('/')


# ---------------- LOGIN (BROWSER FRIENDLY) ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    username = request.form['username']
    password = hashlib.sha256(request.form['password'].encode()).hexdigest()

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username=? AND password=?",
              (username, password))
    user = c.fetchone()
    conn.close()

    if user:
        session['user_id'] = user[0]
        session['username'] = username
        return redirect('/dashboard')

    return "Login Failed"


# ---------------- DASHBOARD ----------------
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/')

    conn = get_db()
    c = conn.cursor()

    c.execute("SELECT * FROM tasks WHERE user_id=?", (session['user_id'],))
    tasks = c.fetchall()
    conn.close()

    return render_template(
        'dashboard.html',
        tasks=tasks,
        username=session.get('username')
    )
# ------------------- LOGOUT ---------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# ---------------- CREATE TASK ----------------
@app.route('/create-task', methods=['POST'])
def create_task():
    user_id = session['user_id']
    title = request.form['title']
    description = request.form['description']

    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)",
              (user_id, title, description))
    conn.commit()
    conn.close()

    return redirect('/dashboard')


# ---------------- VIEW TASK (IDOR VULNERABILITY) ----------------
@app.route('/view-task/<int:task_id>')
def view_task(task_id):
    conn = get_db()
    c = conn.cursor()

    c.execute("SELECT * FROM tasks WHERE id = ?", (task_id,))
    task = c.fetchone()
    conn.close()

    if not task:
        return "<h3 style='color:white;'>Task not found</h3>"

    return f"""
    <html>
        <body style="background:#0b0f1a; color:white; font-family:sans-serif;">
            <h2>Task Details</h2>
            <p><b>ID:</b> {task['id']}</p>
            <p><b>Title:</b> {task['title']}</p>
            <p><b>Description:</b> {task['description']}</p>
            <p><b>User ID:</b> {task['user_id']}</p>
        </body>
    </html>
    """


@app.route('/delete-task/<int:task_id>')
def delete_task(task_id):
    conn = get_db()
    c = conn.cursor()

    # (VULNERABLE STYLE: no ownership check = consistent with your project)
    c.execute("DELETE FROM tasks WHERE id = ?", (task_id,))

    conn.commit()
    conn.close()

    return redirect('/dashboard')

# ---------------- SEARCH TASKS (SQL INJECTION) ----------------
@app.route('/search')
def search():
    keyword = request.args.get('keyword', '')

    conn = get_db()
    c = conn.cursor()

    # ❌ VULNERABILITY: SQL Injection
    query = f"SELECT * FROM tasks WHERE title LIKE '%{keyword}%'"
    c.execute(query)

    results = c.fetchall()
    return jsonify([dict(row) for row in results])

# --------------------- REFLECTED XSS -----------------
@app.route('/reflect')
def reflect():
    q = request.args.get('q', '')
    return f"<h3>Result: {q}</h3>"


# ---------------- API LOGIN (JWT - WEAK) ----------------
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json

    username = data['username']
    password = hashlib.sha256(data['password'].encode()).hexdigest()

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username=? AND password=?",
              (username, password))
    user = c.fetchone()
    conn.close()

    if user:
        token = jwt.encode({'user_id': user[0]}, JWT_SECRET, algorithm="HS256")
        return jsonify({"token": token})

    return jsonify({"error": "Invalid credentials"})


# ---------------- INIT ----------------
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
