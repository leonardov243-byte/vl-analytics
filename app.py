import os
import sqlite3
import requests
from datetime import datetime
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)
DB_PATH = '/home/ssm-user/vl-analytics/analytics.db'

ALERT_EMAIL    = os.environ.get('ALERT_EMAIL', '')
ALERT_PASSWORD = os.environ.get('ALERT_PASSWORD', '')
ALERT_DESTINO  = os.environ.get('ALERT_DESTINO', '')
ABUSEIPDB_KEY  = os.environ.get('ABUSEIPDB_KEY', '')

def conectar_db():
    return sqlite3.connect(DB_PATH)

def _init_db():
    with conectar_db() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS eventos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                proyecto TEXT,
                ip TEXT,
                ruta TEXT,
                pais TEXT,
                ciudad TEXT,
                fecha TEXT,
                user_agent TEXT,
                es_bot INTEGER DEFAULT 0,
                sospechosa INTEGER DEFAULT 0,
                maliciosa INTEGER DEFAULT 0
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS abuseipdb_cache (
                ip TEXT PRIMARY KEY,
                score INTEGER,
                country TEXT,
                isp TEXT,
                total_reports INTEGER,
                is_malicious INTEGER,
                checked_at TEXT
            )
        """)
        con.commit()

def _es_bot(ua):
    if not ua:
        return False
    bots = ['bot','crawler','spider','scraper','python','curl','wget',
            'java','ruby','perl','php','go-http']
    return any(b in ua.lower() for b in bots)

def _get_pais(ip):
    try:
        import urllib.request as _ureq
        import json as _json2
        d = _json2.loads(_ureq.urlopen(f'http://ip-api.com/json/{ip}', timeout=2).read())
        return d.get('country', 'Desconocido'), d.get('city', 'Desconocido')
    except:
        return 'Desconocido', 'Desconocido'

def _detectar_sospechosa(ip, con):
    cur = con.cursor()
    cur.execute(
        "SELECT COUNT(*) FROM eventos WHERE ip=? AND fecha >= datetime('now', '-1 minute')",
        (ip,)
    )
    count = cur.fetchone()[0]
    if count >= 20:
        cur.execute("UPDATE eventos SET sospechosa=1 WHERE ip=?", (ip,))
        con.commit()
        return True
    return False

def _consultar_abuseipdb(ip):
    if not ABUSEIPDB_KEY:
        return 0
    try:
        with conectar_db() as con:
            row = con.execute(
                "SELECT is_malicious, checked_at FROM abuseipdb_cache WHERE ip=?", (ip,)
            ).fetchone()
            if row:
                from datetime import timedelta
                checked = datetime.fromisoformat(row[1])
                if datetime.now() - checked < timedelta(hours=24):
                    return row[0]
        r = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers={'Key': ABUSEIPDB_KEY, 'Accept': 'application/json'},
            params={'ipAddress': ip, 'maxAgeInDays': 90},
            timeout=5
        )
        data = r.json().get('data', {})
        score = data.get('abuseConfidenceScore', 0)
        is_malicious = 1 if score >= 50 else 0
        with conectar_db() as con:
            con.execute("""
                INSERT OR REPLACE INTO abuseipdb_cache
                (ip, score, country, isp, total_reports, is_malicious, checked_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                ip, score,
                data.get('countryCode', '??'),
                data.get('isp', ''),
                data.get('totalReports', 0),
                is_malicious,
                datetime.now().isoformat()
            ))
            con.commit()
        return is_malicious
    except:
        return 0

def _enviar_alerta(ip, ruta, pais, tipo):
    if not ALERT_EMAIL:
        return
    try:
        import smtplib
        from email.mime.text import MIMEText
        msg = MIMEText(f'Tipo: {tipo}\nIP: {ip}\nRuta: {ruta}\nPaís: {pais}\nFecha: {datetime.now()}')
        msg['Subject'] = f'[VL Analytics] Alerta: {tipo} - {ip}'
        msg['From'] = ALERT_EMAIL
        msg['To'] = ALERT_DESTINO
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as s:
            s.login(ALERT_EMAIL, ALERT_PASSWORD)
            s.send_message(msg)
    except Exception as e:
        print(f'[ALERTA EMAIL ERROR] {e}')

@app.route('/api/track', methods=['POST'])
def track():
    data = request.get_json(silent=True) or {}
    proyecto = data.get('proyecto', 'desconocido')
    ip       = data.get('ip', request.remote_addr)
    ruta     = data.get('ruta', '/')
    ua       = data.get('user_agent', request.headers.get('X-Real-UA', request.headers.get('User-Agent', '')))
    fecha    = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    pais, ciudad = _get_pais(ip)
    bot      = 1 if _es_bot(ua) else 0
    maliciosa = _consultar_abuseipdb(ip)

    with conectar_db() as con:
        sospechosa = 1 if _detectar_sospechosa(ip, con) else 0
        con.execute("""
            INSERT INTO eventos
            (proyecto, ip, ruta, pais, ciudad, fecha, user_agent, es_bot, sospechosa, maliciosa)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (proyecto, ip, ruta, pais, ciudad, fecha, ua, bot, sospechosa, maliciosa))
        con.commit()

    if bot == 1 or maliciosa == 1 or sospechosa == 1:
        tipo = 'Bot' if bot == 1 else ('IP Maliciosa' if maliciosa == 1 else 'Sospechosa')
        import threading as _t
        _t.Thread(target=_enviar_alerta, args=(ip, ruta, pais, tipo), daemon=True).start()

    return jsonify({'ok': True})

@app.route('/api/eventos')
def eventos():
    with conectar_db() as con:
        rows = con.execute('SELECT id, proyecto, ip, ruta, pais, CASE WHEN maliciosa=1 THEN "Maliciosa" WHEN es_bot=1 THEN "Bot" WHEN sospechosa=1 THEN "Sospechosa" ELSE "Humano" END, fecha FROM eventos ORDER BY id DESC LIMIT 50').fetchall()
    return jsonify([dict(zip(['id','proyecto','ip','ruta','pais','tipo','fecha'],r)) for r in rows])

@app.route('/api/stats')
def stats():
    with conectar_db() as con:
        total     = con.execute("SELECT COUNT(*) FROM eventos").fetchone()[0]
        unicas    = con.execute("SELECT COUNT(DISTINCT ip) FROM eventos").fetchone()[0]
        proyectos = con.execute("SELECT COUNT(DISTINCT proyecto) FROM eventos").fetchone()[0]
        humanos   = con.execute("SELECT COUNT(*) FROM eventos WHERE es_bot=0").fetchone()[0]
        bots      = con.execute("SELECT COUNT(*) FROM eventos WHERE es_bot=1").fetchone()[0]
        sospechosas = con.execute("SELECT COUNT(DISTINCT ip) FROM eventos WHERE sospechosa=1").fetchone()[0]
        maliciosas  = con.execute("SELECT COUNT(DISTINCT ip) FROM eventos WHERE maliciosa=1").fetchone()[0]
    return jsonify({
        'total': total,
        'unicas': unicas,
        'proyectos': proyectos,
        'humanos': humanos,
        'bots': bots,
        'sospechosas': sospechosas,
        'maliciosas': maliciosas
    })

@app.route('/')
def panel():
    with conectar_db() as con:
        s = con.execute('SELECT COUNT(*),COUNT(DISTINCT ip),COUNT(DISTINCT proyecto),SUM(CASE WHEN es_bot=0 THEN 1 ELSE 0 END),SUM(es_bot),COUNT(DISTINCT CASE WHEN sospechosa=1 THEN ip END),COUNT(DISTINCT CASE WHEN maliciosa=1 THEN ip END) FROM eventos').fetchone()
    return render_template('panel.html', total_visitas=s[0] or 0, ips_unicas=s[1] or 0, total_proyectos=s[2] or 0, total_humanos=s[3] or 0, total_bots=s[4] or 0, total_sospechosos=s[5] or 0, total_maliciosas=s[6] or 0)

_init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
