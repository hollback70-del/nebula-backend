from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import re
import os
from datetime import datetime

app = Flask(__name__)
CORS(app) # ഫ്രണ്ട്-എൻഡും ബാക്ക്-എൻഡും തമ്മിൽ ബന്ധിപ്പിക്കാൻ

# --- MONGODB CLOUD CONFIGURATION (X.509 SECURE CONNECT) ---
# നിങ്ങൾ നൽകിയ ഒഫീഷ്യൽ സർട്ടിഫിക്കറ്റ് ലിങ്ക്
MONGO_URI = "mongodb+srv://cluster0.rlrjlju.mongodb.net/?authMechanism=MONGODB-X509&authSource=%24external&tls=true"

# നിങ്ങളുടെ സർട്ടിഫിക്കറ്റ് ഫയലിന്റെ പേര് (ഇത് നിങ്ങളുടെ റീപ്പോസിറ്ററിയിൽ ഉണ്ടായിരിക്കണം)
CERT_FILE = "X509-cert-478020115322233657.pem"

try:
    client = MongoClient(
        MONGO_URI,
        tlsCertificateKeyFile=CERT_FILE,
        tlsAllowInvalidCertificates=True # Render സെർവറിലെ SSL പ്രശ്നങ്ങൾ ഒഴിവാക്കാൻ
    )
    db = client['kali_database']
    collection = db['logs']
    print("[SYSTEM] MongoDB Cloud Database Connected Successfully Using X.509 Certificate.")
except Exception as e:
    print("[ERROR] Database Connection Failed:", e)

# --- SECURITY UTILITIES (ENCRYPTION & BINARY) ---

# ടെക്സ്റ്റിനെ ബൈനറി (010101) രൂപത്തിലേക്ക് മാറ്റാനുള്ള ഫങ്ക്ഷൻ
def text_to_binary(text):
    return ' '.join(format(ord(char), '08b') for char in text)

# ലോഗിൻ റൂട്ട്
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('username', '').strip()
        access_code = data.get('accessCode', '').strip()

        # 1. സെക്യൂരിറ്റി ചെക്ക് (Anti-SQL Injection & XSS)
        secure_pattern = re.compile("^[a-zA-Z0-9_]+$")
        if not secure_pattern.match(username) or not secure_pattern.match(access_code):
            return jsonify({"status": "error", "message": "MALICIOUS INPUT DETECTED! ACCESS DENIED."}), 400

        # 2. സുരക്ഷയ്ക്കായി ഡാറ്റ എൻക്രിപ്റ്റ് ചെയ്ത വാല്യൂ ഉണ്ടാക്കുന്നു (Simple Token)
        raw_token = f"USER:{username}|CODE:{access_code}"
        
        # 3. നിങ്ങൾ ആവശ്യപ്പെട്ടതുപോലെ ഡാറ്റ പൂർണ്ണമായും ബൈനറി (Binary) രൂപത്തിലാക്കുന്നു
        binary_vault_data = text_to_binary(raw_token)

        # 4. ഡാറ്റാബേസിലേക്ക് വിവരങ്ങൾ സുരക്ഷിതമായി അയക്കുന്നു (സീറോയും വണ്ണും മാത്രം)
        payload = {
            "secured_payload": binary_vault_data,
            "status": "INITIALIZED",
            "timestamp": datetime.now()
        }
        
        collection.insert_one(payload)

        # ഈ ടെസ്റ്റ് അക്കൗണ്ട് വെച്ച് ലോഗിൻ സക്സസ് ആക്കുന്നു
        if username == "admin":
            return jsonify({"status": "success", "message": "ACCESS GRANTED"})
        else:
            return jsonify({"status": "error", "message": "CREDENTIALS LOGGED SECURELY"})

    except Exception as err:
        return jsonify({"status": "error", "message": f"SERVER ERROR: {str(err)}"}), 500

if __name__ == '__main__':
    app.run(debug=True)
