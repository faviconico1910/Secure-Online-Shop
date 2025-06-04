from flask import Flask, request, jsonify, render_template, session, redirect
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import base64
import firebase_admin
from firebase_admin import credentials, firestore

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = 'your_secret_key'

cred = credentials.ApplicationDefault()
firebase_admin.initialize_app(cred)
db = firestore.client()

def encrypt_card(card_number, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(card_number.encode())
    return {
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'nonce': base64.b64encode(cipher.nonce).decode(),
        'tag': base64.b64encode(tag).decode()
    }

def hash_password(password):
    h = SHA256.new()
    h.update(password.encode())
    return h.hexdigest()


@app.route('/', methods=['GET'])
def index():
    username = session.get('username')
    if request.method == 'GET':
        return render_template('index.html', username=username)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    card = data.get('card')

    # Kiểm tra username tồn tại chưa
    users_ref = db.collection('Users')
    query = users_ref.where('username', '==', username).stream()
    if any(query):
        return jsonify({"error": "Username đã tồn tại"}), 400

    # Hash password
    hashed_pw = hash_password(password)

    # Mã hóa thẻ tín dụng
    aes_key = get_random_bytes(16)
    encrypted_card = encrypt_card(card, aes_key)

    # Lưu dữ liệu vào Firestore
    users_ref.document(username).set({
        "username": username,
        "password_hash": hashed_pw,
        "encrypted_card": encrypted_card,
        # KHÔNG nên lưu aes_key ở đây trong thực tế
        "aes_key_base64": base64.b64encode(aes_key).decode()
    })

    return jsonify({"message": "Đăng ký thành công"})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Thiếu username hoặc password"}), 400
    
    # Kiểm tra username tồn tại hay không
    users_ref = db.collection('Users').document(username)
    user_doc = users_ref.get()
    
    if not user_doc.exists:
        return jsonify({"error": "Username không tồn tại"}), 400
    
    user_data = user_doc.to_dict()
    hashed_input_pw = hash_password(password)

    if hashed_input_pw != user_data.get("password_hash"):
        return jsonify({"error": "Mật khẩu không đúng"}), 401
    
    session['username'] = username

    return jsonify({"message": "Đăng nhập thành công"})

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
