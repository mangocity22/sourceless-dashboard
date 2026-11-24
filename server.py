import sqlite3
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime

app = Flask(__name__)
CORS(app)

DB_PATH = "/opt/sourceless_control.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS clients (
            hwid TEXT PRIMARY KEY,
            cert_status TEXT DEFAULT 'valid',
            cmd TEXT DEFAULT 'stop_support',
            last_seen TEXT,
            rustdesk_id TEXT DEFAULT 'N/A',
            rustdesk_pw TEXT DEFAULT 'N/A',
            approval_status TEXT DEFAULT 'pending'
        )
    ''')
    
    cursor.execute("PRAGMA table_info(clients)")
    existing_columns = [column[1] for column in cursor.fetchall()]
    if 'rustdesk_id' not in existing_columns:
        cursor.execute("ALTER TABLE clients ADD COLUMN rustdesk_id TEXT DEFAULT 'N/A'")
    if 'rustdesk_pw' not in existing_columns:
        cursor.execute("ALTER TABLE clients ADD COLUMN rustdesk_pw TEXT DEFAULT 'N/A'")
    if 'approval_status' not in existing_columns:
        cursor.execute("ALTER TABLE clients ADD COLUMN approval_status TEXT DEFAULT 'pending'")
        
    conn.commit()
    conn.close()

# API: Lista clienți pentru Dashboard
@app.route('/api/admin/clients', methods=['GET'])
def get_all_clients():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT hwid, cert_status, cmd, last_seen, rustdesk_id, rustdesk_pw, approval_status FROM clients')
    rows = cursor.fetchall()
    conn.close()
    
    clients = []
    for r in rows:
        clients.append({
            "hwid": r[0],
            "cert_status": r[1],
            "cmd": r[2],
            "last_seen": r[3],
            "rustdesk_id": r[4],
            "rustdesk_pw": r[5],
            "approval_status": r[6]
        })
    return jsonify(clients)

# API: Status client
@app.route('/api/client/status', methods=['GET'])
def client_status():
    hwid = request.args.get('hwid')
    if not hwid:
        return jsonify({"error": "Missing hwid"}), 400
    
    hwid = hwid.replace('-', '').lower()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO clients (hwid, last_seen) 
        VALUES(?, ?) 
        ON CONFLICT(hwid) DO UPDATE SET last_seen=?
    ''', (hwid, now, now))
    
    cursor.execute('SELECT cmd, cert_status, rustdesk_id, rustdesk_pw, approval_status FROM clients WHERE hwid=?', (hwid,))
    row = cursor.fetchone()
    conn.commit()
    conn.close()

    return jsonify({
        "cmd": row[0] if row else "stop_support", 
        "cert_status": row[1] if row else "valid",
        "rustdesk_id": row[2] if row else "N/A",
        "rustdesk_pw": row[3] if row else "N/A",
        "approval_status": row[4] if row else "pending"
    })

# API: Comandă admin (Start/Stop support)
@app.route('/api/admin/control', methods=['POST'])
def admin_control():
    data = request.json
    hwid = data.get('hwid', '')
    new_cmd = data.get('cmd')
    
    if not hwid or new_cmd not in ['start_support', 'stop_support']:
        return jsonify({"status": "error", "message": "Invalid data"}), 400

    hwid_clean = hwid.replace('-', '').lower()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    if new_cmd == 'stop_support':
        # Căutăm și actualizăm indiferent dacă în DB HWID-ul are liniuțe sau nu
        cursor.execute('''
            UPDATE clients 
            SET cmd=?, rustdesk_id='N/A', rustdesk_pw='N/A', approval_status='pending' 
            WHERE REPLACE(LOWER(hwid), '-', '') = ?
        ''', (new_cmd, hwid_clean))
    else:
        cursor.execute('''
            INSERT INTO clients (hwid, cmd, last_seen) 
            VALUES(?, ?, DATETIME('now')) 
            ON CONFLICT(hwid) DO UPDATE SET cmd=?
        ''', (hwid_clean, new_cmd, new_cmd))
    
    conn.commit()
    conn.close()

    return jsonify({"status": "success"})

# API: Clientul trimite datele RustDesk după Aprobare
@app.route('/api/client/submit_credentials', methods=['POST'])
def submit_credentials():
    data = request.json
    hwid = data.get('hwid', '').replace('-', '').lower()
    rustdesk_id = data.get('rustdesk_id', 'N/A')
    rustdesk_pw = data.get('rustdesk_pw', 'N/A')
    status = data.get('status', 'pending')

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE clients 
        SET rustdesk_id=?, rustdesk_pw=?, approval_status=? 
        WHERE hwid=?
    ''', (rustdesk_id, rustdesk_pw, status, hwid))
    
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=8080)
