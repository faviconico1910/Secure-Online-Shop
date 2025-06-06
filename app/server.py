from flask import Flask, request, jsonify, render_template, session, redirect
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import base64
from dotenv import load_dotenv
import os
from datetime import datetime
import firebase_admin
from firebase_admin import credentials, firestore

cred = credentials.ApplicationDefault()
firebase_admin.initialize_app(cred)

db = firestore.client()

load_dotenv()

app = Flask(__name__, static_folder='static', template_folder='templates')

app.secret_key = os.getenv("SECRET_KEY")
token_secret = os.getenv("TOKEN_SECRET")

def encrypt_card(card_number, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(card_number.encode())
    return {
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'nonce': base64.b64encode(cipher.nonce).decode(),
        'tag': base64.b64encode(tag).decode()
    }

def generate_search_token(value: str, secret_key: str):
    h = SHA256.new()
    h.update((value + secret_key).encode())
    return h.hexdigest()

def hash_password(password):
    h = SHA256.new()
    h.update(password.encode())
    return h.hexdigest()

def generate_order_token(username, order_id):
    key = get_random_bytes(16)
    h = SHA256.new()
    h.update((username + order_id + str(datetime.utcnow())).encode())
    return base64.b64encode(h.digest()).decode()[:16]

@app.route('/', methods=['GET'])
def index():
    username = session.get('username')
    if request.method == 'GET':
        return render_template('index.html', username=username)

@app.route('/register', methods=['POST'])
def register():
    if not request.is_json:
        return jsonify({"error": "Request không phải JSON"}), 400

    data = request.get_json()
    if not data:
        return jsonify({"error": "Dữ liệu JSON không hợp lệ"}), 400

    username = data.get('username')
    password = data.get('password')
    card = data.get('card')

    if not username or not password or not card:
        return jsonify({"error": "Thiếu thông tin đăng ký"}), 400

    users_ref = db.collection('Users')
    query = users_ref.where('username', '==', username).stream()
    if any(query):
        return jsonify({"error": "Username đã tồn tại"}), 400

    hashed_pw = hash_password(password)
    aes_key = get_random_bytes(16)
    encrypted_card = encrypt_card(card, aes_key)
    search_token = generate_search_token(username, token_secret)

    users_ref.document(username).set({
        "username": username,
        "password_hash": hashed_pw,
        "encrypted_card": encrypted_card,
        "search_token": search_token,
        "role": "customer"
    })

    return jsonify({"message": "Đăng ký thành công"})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Thiếu username hoặc password"}), 400

    search_token = generate_search_token(username, token_secret)
    query = db.collection('Users').where('search_token', '==', search_token).stream()
    user_doc = next(query, None)
    if not user_doc:
        return jsonify({"error": "Username không tồn tại"}), 400

    user_data = user_doc.to_dict()
    hashed_input_pw = hash_password(password)

    if hashed_input_pw != user_data.get("password_hash"):
        return jsonify({"error": "Mật khẩu không đúng"}), 401

    session['username'] = username
    session['role'] = user_data.get("role")
    return jsonify({"message": "Đăng nhập thành công"})

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    return redirect('/')

@app.route('/orders', methods=['POST', 'GET'])
def order():
    if request.method == 'GET':
        if 'username' not in session or session.get('role') != 'customer':
            return redirect('/')

        username = session['username']
        orders_ref = db.collection('Orders').document(username).collection('Orders')
        orders_docs = orders_ref.stream()

        orders = []
        for doc in orders_docs:
            order_data = doc.to_dict()
            order_data['order_id'] = doc.id
            orders.append(order_data)

        return render_template('order.html', orders=orders, username=username)

    elif request.method == 'POST':
        if 'username' not in session:
            return jsonify({"error": "Vui lòng đăng nhập"}), 401

        data = request.get_json()
        username = data.get('username')
        productname = data.get('productname')
        cost = data.get('cost')
        quantity = data.get('quantity')

        if not all([username, productname, cost, quantity]):
            return jsonify({"error": "Thiếu thông tin đơn hàng"}), 400

        if username != session['username']:
            return jsonify({"error": "Thông tin người dùng không hợp lệ"}), 403

        order_id = f"order_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{hash(username) % 1000:03d}"
        token = generate_order_token(username, order_id)
        orders_ref = db.collection('Orders').document(username).collection('Orders')
        orders_ref.document(order_id).set({
            "productname": productname,
            "cost": float(cost),
            "quantity": int(quantity),
            "created_at": datetime.utcnow().isoformat(),
            "status": "pending",
            "token": token
        })

        return jsonify({"message": "Đặt hàng thành công!", "order_id": f"{username}/{token}"}), 200

@app.route('/admin/orders')
def admin_view_orders():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect('/')

    # Lấy tất cả đơn hàng từ collection group "Orders"
    orders_query = db.collection_group("Orders").stream()

    all_orders = []
    for doc in orders_query:
        data = doc.to_dict()
        order_id = doc.id
        username = doc.reference.parent.parent.id  # Lấy username từ path
        data['order_id'] = order_id
        data['username'] = username
        all_orders.append(data)

    return render_template('admin_orders.html', orders=all_orders, username=session['username'])


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)