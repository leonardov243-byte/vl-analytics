import os
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import sqlite3
import bcrypt
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'vl-analytics-dev-key')

_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'analytics.db')
_ADMIN_USER = os.environ.get('ADMIN_USER', 'admin')
_ADMIN_HASH = bcrypt.hashpw(
    os.environ.get('ADMIN_PASS', 'admin123').encode('utf-8'),
    bcrypt.gensalt()
)

def conectar_db():
    return sqlite3.connect(_DB_PATH)

with conectar_db() as con:
    cur = con.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS eventos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            proyecto TEXT NOT NULL,
            ip TEXT NOT NULL,
            ruta TEXT NOT NULL,
            pais TEXT DEFAULT 'Desconocido',
            ciudad TEXT DEFAULT 'Desconocido',
            fecha TEXT NOT NULL
        )
    ''')
    con.commit()

@app.route('/api/track', methods=['POST'])
def track():
    data = request.get_json()
    proyecto = data.get('proyecto', 'desconocido')
    ip = data.get('ip', request.remote_addr)
    ruta = data.get('ruta', '/')
    fecha = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with conectar_db() as con:
        cur = con.cursor()
        cur.execute(
            "INSERT INTO eventos (proyecto, ip, ruta, fecha) VALUES (?, ?, ?, ?)",
            (proyecto, ip, ruta, fecha)
        )
        con.commit()
    return jsonify({'ok': True})

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST'