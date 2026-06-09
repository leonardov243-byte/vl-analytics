import os
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import sqlite3
import bcrypt
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'vl-analytics-dev-key')

_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'analytics.db')
_ADMIN_USER = os.environ.get('ADMIN_USER', 'admin')
_ADMIN_PASS = os.environ.get('ADMIN_PASS', 'admin123')

import smtplib
from email.mime.text import MIMEText

def _consultar_abuseipdb(ip):
    try:
        key = os.environ.get('ABUSEIPDB_KEY')
        if not key:
            return 0
        import urllib.request as _ur
        import json as _j
        url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90'
        req = _ur.Request(url, headers={'Key': key, 'Accept': 'application/json'})
        data = _j.loads(_ur.urlopen(req, timeout=3).read())
        score = data['data']['abuseConfidenceScore']
        return 1 if score >= 50 else 0
    except:
        return 0

def _enviar_alerta(ip, ruta, pais, tipo):
    try:
        remitente = os.environ.get('ALERT_EMAIL')
        password = os.environ.get('ALERT_PASSWORD')
        destino = os.environ.get('ALERT_DESTINO')
        if not remitente or not password or not destino:
            return
        msg = MIMEText(f'Alerta VL Analytics\n\nTipo: {tipo}\nIP: {ip}\nPais: {pais}\nRuta: {ruta}')
        msg['Subject'] = f'VL Analytics - {tipo} detectado'
        msg['From'] = remitente
        msg['To'] = destino
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(remitente, password)
            server.sendmail(remitente, destino, msg.as_string())
    except Exception as e:
        print(f'Error alerta: {e}')

def conectar_db():
    return sqlite3.connect(_DB_PATH)

with conectar_db() as con:
    cur = con.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS eventos (id INTEGER PRIMARY KEY AUTOINCREMENT, proyecto TEXT NOT NULL, ip TEXT NOT NULL, ruta TEXT NOT NULL, pais TEXT DEFAULT "Desconocido", ciudad TEXT DEFAULT "Desconocido", fecha TEXT NOT NULL)''')
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
        maliciosa = _consultar_abuseipdb(ip)
        cur.execute("INSERT INTO eventos (proyecto, ip, ruta, pais, ciudad, fecha, user_agent, es_bot, sospechosa, maliciosa) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (proyecto, ip, ruta, pais, ciudad, fecha, ua, bot, 0, maliciosa))
   maliciosa = _consultar_abuseipdb(ip)
        if bot == 1 or maliciosa == 1:
            tipo = 'Bot' if bot == 1 else 'IP Maliciosa'
            import threading as _t
            _t.Thread(target=_enviar_alerta, args=(ip, ruta, pais, tipo), daemon=True).start()
            import threading as _t
            _t.Thread(target=_enviar_alerta, args=(ip, ruta, pais, 'Bot'), daemon=True).start()
        return jsonify({'ok': True})

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        if username == _ADMIN_USER and password == _ADMIN_PASS:
            session['admin'] = True
            return redirect(url_for('panel'))
        error = 'Credenciales incorrectas'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('admin', None)
    return redirect(url_for('login'))

@app.route('/')
def panel():
    if not session.get('admin'):
        return redirect(url_for('login'))
    with conectar_db() as con:
        cur = con.cursor()
        cur.execute("SELECT COUNT(*) FROM eventos")
        total_visitas = cur.fetchone()[0]
        cur.execute("SELECT COUNT(DISTINCT ip) FROM eventos")
        ips_unicas = cur.fetchone()[0]
        cur.execute("SELECT COUNT(DISTINCT proyecto) FROM eventos")
        total_proyectos = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM eventos WHERE es_bot=0 AND sospechosa=0")
        total_humanos = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM eventos WHERE es_bot=1")
        total_bots = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM eventos WHERE sospechosa=1")
        total_sospechosos = cur.fetchone()[0]
        cur.execute("SELECT proyecto, COUNT(*) as total FROM eventos GROUP BY proyecto ORDER BY total DESC")
        por_proyecto = cur.fetchall()
        cur.execute("SELECT * FROM eventos ORDER BY id DESC LIMIT 50")
        recientes = cur.fetchall()
    return render_template('panel.html',
        total_visitas=total_visitas,
        ips_unicas=ips_unicas,
        total_proyectos=total_proyectos,
        total_humanos=total_humanos,
        total_bots=total_bots,
        total_sospechosos=total_sospechosos,
        por_proyecto=por_proyecto,
        recientes=recientes
    )
@app.route('/api/stats')
def stats():
    if not session.get('admin'):
        return jsonify({'error': 'No autorizado'}), 401
    with conectar_db() as con:
        cur = con.cursor()
        cur.execute("SELECT COUNT(*) FROM eventos")
        total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(DISTINCT ip) FROM eventos")
        ips = cur.fetchone()[0]
        cur.execute("SELECT * FROM eventos ORDER BY id DESC LIMIT 50")
        recientes = cur.fetchall()
    return jsonify({'total': total, 'ips_unicas': ips, 'recientes': [list(r) for r in recientes]})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
