from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import re
from datetime import datetime

app = Flask(__name__)
CORS(app)

# --- MONGODB CONFIGURATION ---
MONGO_URI = "mongodb+srv://cluster0.rlrjlju.mongodb.net/?authMechanism=MONGODB-X509&authSource=%24external&tls=true"
CERT_FILE = "X509-cert-478020115322233657.pem"

try:
    client = MongoClient(MONGO_URI, tlsCertificateKeyFile=CERT_FILE, tlsAllowInvalidCertificates=True)
    db = client['kali_database']
    logs_collection = db['system_logs'] # പുതിയ ലോഡിംഗ് കളക്ഷൻ
    print("[SYSTEM] Database Connected.")
except Exception as e:
    print("[ERROR] Database Connection Failed:", e)

# സുരക്ഷയ്ക്കായി ഡാറ്റ ബൈനറി ആക്കുന്ന ഫങ്ക്ഷൻ
def text_to_binary(text):
    return ' '.join(format(ord(char), '08b') for char in text)

# --- സെക്യൂരിറ്റി മോണിറ്ററിംഗ് ഫങ്ക്ഷൻ ---
def log_activity(ip, action, status, details):
    try:
        raw_log = f"IP:{ip}|ACTION:{action}|STATUS:{status}|DETAILS:{details}"
        binary_log = text_to_binary(raw_log)
        
        log_payload = {
            "secured_log": binary_log,
            "timestamp": datetime.now()
        }
        logs_collection.insert_one(log_payload)
    except Exception as e:
        print("Logging failed:", e)

# ലോഗിൻ റൂട്ട്
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username', '').strip()
    access_code = data.get('accessCode', '').strip()
    
    # യൂസറുടെ ഐപി അഡ്രസ് എടുക്കുന്നു
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    # 1. ലോഗിൻ പേജിൽ വല്ല അനാവശ്യ കമാൻഡുകളും (SQL/XSS) അടിക്കുന്നുണ്ടോ എന്ന് നോക്കുന്നു
    secure_pattern = re.compile("^[a-zA-Z0-9_]+$")
    if not secure_pattern.match(username) or not secure_pattern.match(access_code):
        log_activity(user_ip, "LOGIN_ATTEMPT", "SUSPICIOUS", f"Malicious input tried: {username}")
        return jsonify({"status": "error", "message": "MALICIOUS INPUT DETECTED!"}), 400

    # 2. ശരിയായ ലോഗിൻ പരിശോധന
    if username == "admin" and access_code == "nebula70": # നിങ്ങളുടെ കോഡ് ഇവിടെ നൽകാം
        log_activity(user_ip, "LOGIN", "SUCCESS", "Admin access granted")
        return jsonify({"status": "success", "message": "ACCESS GRANTED"})
    else:
        log_activity(user_ip, "LOGIN_ATTEMPT", "FAILED", f"Wrong credentials for user: {username}")
        return jsonify({"status": "error", "message": "INVALID CREDENTIALS"})

# --- സിസ്റ്റം ഫയലുകളിൽ തൊടാൻ ശ്രമിച്ചാൽ ട്രാക്ക് ചെയ്യാനുള്ള റൂട്ട് ---
@app.route('/track_intrusion', methods=['POST'])
def track_intrusion():
    data = request.json
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    action = data.get('action', 'UNKNOWN_ACCESS')
    details = data.get('details', '')
    
    log_activity(user_ip, "INTRUSION_ALERT", "WARNING", f"User tried to touch: {details}")
    return jsonify({"status": "logged"})

if __name__ == '__main__':
    app.run(debug=True)
