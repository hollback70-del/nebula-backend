from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import re

app = Flask(__name__)
CORS(app) # ഫ്രണ്ട്-എൻഡും ബാക്ക്-എൻഡും തമ്മിൽ ബന്ധിപ്പിക്കാൻ

# നിങ്ങളുടെ MongoDB ക്ലൗഡ് ഡാറ്റാബേസ് ലിങ്ക് ഇവിടെ നൽകുക
# <password> എന്നതിന് പകരം നിങ്ങളുടെ ഡാറ്റാബേസ് പാസ്‌വേഡ് നൽകണം
MONGO_URI = "your_mongodb_connection_string_here"
client = MongoClient(MONGO_URI)
db = client['nebula_database']
users_collection = db['users']

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username', '').strip()
    access_code = data.get('accessCode', '').strip()

    # സെക്യൂരിറ്റി ചെക്ക് (Anti-SQL Injection & XSS)
    secure_pattern = re.compile("^[a-zA-Z0-9_]+$")
    if not secure_pattern.match(username) or not secure_pattern.match(access_code):
        return jsonify({"status": "error", "message": "MALICIOUS INPUT DETECTED!"}), 400

    # ഡാറ്റാബേസിൽ യൂസർ ഉണ്ടോ എന്ന് പരിശോധിക്കുന്നു
    user = users_collection.find_one({"username": username, "access_code": access_code})

    if user:
        return jsonify({"status": "success", "message": "ACCESS GRANTED"})
    else:
        return jsonify({"status": "error", "message": "INVALID CREDENTIALS"})

if __name__ == '__main__':
    app.run(debug=True)
