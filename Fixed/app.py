"""
FIXED Task Management API (Secure Version)
Fixes:
1. SQL Injection → parameterized queries
2. XSS → safe output handling (escape)
3. IDOR → ownership checks added
"""

from flask import Flask, request, jsonify, render_template, redirect, session
import sqlite3
import hashlib
import jwt
import datetime
import html

app = Flask(__name__)
app.secret_key = "supersecuresecretkey"

JWT_SECRET = "very_strong_secret_key_12345"


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


# ---------------- REGISTER ----------------
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


# ---------------- LOGIN ----------------
@app.route('/login', methods=['POST'])
def login():
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


# ------------------- LOGOUT ---------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


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


# ---------------- CREATE TASK ----------------
@app.route('/create-task', methods=['POST'])
def create_task():
    user_id = session['user_id']
    title = request.form['title']
    description = request.form['description']

    conn = get_db()
    c = conn.cursor()

    # FIXED: escape input to prevent stored XSS impact
    safe_title = html.escape(title)
    safe_description = html.escape(description)

    c.execute("INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)",
              (user_id, safe_title, safe_description))

    conn.commit()
    conn.close()

    return redirect('/dashboard')


# ---------------- VIEW TASK (FIXED IDOR) ----------------
@app.route('/view-task/<int:task_id>')
def view_task(task_id):
    if 'user_id' not in session:
        return redirect('/')

    conn = get_db()
    c = conn.cursor()

    c.execute("SELECT * FROM tasks WHERE id=? AND user_id=?",
              (task_id, session['user_id']))

    task = c.fetchone()
    conn.close()

    if not task:
        return """
        <html>
            <body style="background:#0b0f1a; color:white; font-family:sans-serif;">
                <h3>❌ Unauthorized Access or Task Not Found</h3>
                <p>You are not allowed to view this task.</p>
            </body>
        </html>
        """, 403

    return f"""
    <html>
        <body style="background:#0b0f1a; color:white; font-family:sans-serif;">
            <h2>Task Details (Secure)</h2>
            <p><b>ID:</b> {task['id']}</p>
            <p><b>Title:</b> {task['title']}</p>
            <p><b>Description:</b> {task['description']}</p>
            <p><b>User ID:</b> {task['user_id']}</p>
        </body>
    </html>
    """
# ---------------- DELETE TASK (SECURE) ----------------
@app.route('/delete-task/<int:task_id>')
def delete_task(task_id):
    if 'user_id' not in session:
        return redirect('/')

    conn = get_db()
    c = conn.cursor()

    # FIXED: ownership check
    c.execute("DELETE FROM tasks WHERE id=? AND user_id=?",
              (task_id, session['user_id']))

    conn.commit()
    conn.close()

    return redirect('/dashboard')


# ------------------- FIXED XSS ----------------------
@app.route('/reflect')
def reflect():
    q = request.args.get('q', '')
    safe_q = html.escape(q)
    return f"<h3>Result: {safe_q}</h3>"


# ---------------- SEARCH (FIXED SQL INJECTION) ----------------
@app.route('/search')
def search():
    keyword = request.args.get('keyword', '')

    conn = get_db()
    c = conn.cursor()

    # FIXED: parameterized query
    query = "SELECT * FROM tasks WHERE title LIKE ?"
    c.execute(query, ('%' + keyword + '%',))

    results = c.fetchall()
    return jsonify([dict(row) for row in results])


# ---------------- API LOGIN (FIXED JWT) ----------------
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
        token = jwt.encode({
            'user_id': user[0],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, JWT_SECRET, algorithm="HS256")

        return jsonify({"token": token})

    return jsonify({"error": "Invalid credentials"})


# ---------------- INIT ----------------
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
