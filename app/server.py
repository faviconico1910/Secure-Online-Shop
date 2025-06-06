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
try:
    import oqs
    OQS_AVAILABLE = True
except ImportError:
    OQS_AVAILABLE = False
    print("Warning: python-oqs not available. ML-DSA functionality will be disabled.")

# Initialize Firebase
try:
    cred = credentials.ApplicationDefault()
    firebase_admin.initialize_app(cred)
    db = firestore.client()
except Exception as e:
    print(f"Firebase initialization error: {e}")
    db = None

load_dotenv()

app = Flask(__name__, static_folder='static', template_folder='templates')

app.secret_key = os.getenv("SECRET_KEY", "default-secret-key-change-this")
token_secret = os.getenv("TOKEN_SECRET", "default-token-secret-change-this")

def encrypt_card(card_number, key):
    """Encrypt card number using AES-GCM"""
    try:
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(card_number.encode())
        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'nonce': base64.b64encode(cipher.nonce).decode(),
            'tag': base64.b64encode(tag).decode()
        }
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

def decrypt_card(encrypted_data, key):
    """Decrypt card number using AES-GCM"""
    try:
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        tag = base64.b64decode(encrypted_data['tag'])
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode()
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

def generate_search_token(value: str, secret_key: str):
    """Generate search token for privacy-preserving lookup"""
    h = SHA256.new()
    h.update((value + secret_key).encode())
    return h.hexdigest()

def hash_password(password):
    """Hash password using SHA256 (consider using bcrypt in production)"""
    h = SHA256.new()
    h.update(password.encode())
    return h.hexdigest()

def generate_order_token(username, order_id):
    """Generate order token"""
    h = SHA256.new()
    h.update((username + order_id + str(datetime.utcnow())).encode())
    return base64.b64encode(h.digest()).decode()[:16]

def generate_mldsa_keys():
    """Generate ML-DSA key pair"""
    if not OQS_AVAILABLE:
        return None, None
    
    try:
        # Use the correct oqs API
        sig = oqs.Signature('Dilithium2')
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
        return public_key, private_key
    except Exception as e:
        print(f"ML-DSA key generation error: {e}")
        return None, None

@app.route('/', methods=['GET'])
def index():
    username = session.get('username')
    return render_template('index.html', username=username)

@app.route('/register', methods=['POST'])
def register():
    if not request.is_json:
        return jsonify({"error": "Request không phải JSON"}), 400

    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Dữ liệu JSON không hợp lệ"}), 400

        username = data.get('username')
        password = data.get('password')
        card = data.get('card')

        if not username or not password or not card:
            return jsonify({"error": "Thiếu thông tin đăng ký"}), 400

        # Check if Firebase is available
        if not db:
            return jsonify({"error": "Database connection failed"}), 500

        # Check if username exists
        users_ref = db.collection('Users')
        query = users_ref.where('username', '==', username).limit(1).stream()
        if any(query):
            return jsonify({"error": "Username đã tồn tại"}), 400

        # Hash password and encrypt card
        hashed_pw = hash_password(password)
        aes_key = get_random_bytes(16)
        encrypted_card = encrypt_card(card, aes_key)
        
        if not encrypted_card:
            return jsonify({"error": "Encryption failed"}), 500

        search_token = generate_search_token(username, token_secret)

        # Generate ML-DSA keys if available
        public_key, private_key = generate_mldsa_keys()
        
        user_data = {
            "username": username,
            "password_hash": hashed_pw,
            "encrypted_card": encrypted_card,
            "aes_key": base64.b64encode(aes_key).decode(),  # Store AES key (in production, use better key management)
            "search_token": search_token,
            "role": "customer"
        }

        # Add ML-DSA keys if available
        if public_key and private_key:
            user_data.update({
                "mldsa_public_key": base64.b64encode(public_key).decode(),
                "mldsa_private_key": base64.b64encode(private_key).decode()
            })

        users_ref.document(username).set(user_data)
        return jsonify({"message": "Đăng ký thành công"})

    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON data"}), 400

        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({"error": "Thiếu username hoặc password"}), 400

        if not db:
            return jsonify({"error": "Database connection failed"}), 500

        search_token = generate_search_token(username, token_secret)
        query = db.collection('Users').where('search_token', '==', search_token).limit(1).stream()
        user_doc = next(query, None)
        
        if not user_doc:
            return jsonify({"error": "Username không tồn tại"}), 400

        user_data = user_doc.to_dict()
        hashed_input_pw = hash_password(password)

        if hashed_input_pw != user_data.get("password_hash"):
            return jsonify({"error": "Mật khẩu không đúng"}), 401

        session['username'] = username
        session['role'] = user_data.get("role", "customer")
        return jsonify({"message": "Đăng nhập thành công"})

    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    return redirect('/')

@app.route('/orders', methods=['POST', 'GET'])
def order():
    try:
        if request.method == 'GET':
            if 'username' not in session or session.get('role') != 'customer':
                return redirect('/')

            if not db:
                return render_template('order.html', orders=[], username=session['username'], error="Database connection failed")

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
            if not data:
                return jsonify({"error": "Invalid JSON data"}), 400

            username = data.get('username')
            productname = data.get('productname')
            cost = data.get('cost')
            quantity = data.get('quantity')

            if not all([username, productname, cost, quantity]):
                return jsonify({"error": "Thiếu thông tin đơn hàng"}), 400

            if username != session['username']:
                return jsonify({"error": "Thông tin người dùng không hợp lệ"}), 403

            if not db:
                return jsonify({"error": "Database connection failed"}), 500

            # Generate unique order ID
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            user_hash = abs(hash(username)) % 1000
            order_id = f"order_{timestamp}_{user_hash:03d}"
            
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

    except Exception as e:
        print(f"Order error: {e}")
        if request.method == 'GET':
            return render_template('order.html', orders=[], username=session.get('username', ''), error="Internal server error")
        else:
            return jsonify({"error": "Internal server error"}), 500

@app.route('/admin/orders')
def admin_view_orders():
    try:
        if 'username' not in session or session.get('role') != 'admin':
            return redirect('/')

        if not db:
            return render_template('admin_orders.html', orders=[], username=session['username'], error="Database connection failed")

        # Get all orders from collection group "Orders"
        orders_query = db.collection_group("Orders").stream()

        all_orders = []
        for doc in orders_query:
            data = doc.to_dict()
            order_id = doc.id
            username = doc.reference.parent.parent.id  # Get username from path
            data['order_id'] = order_id
            data['username'] = username
            all_orders.append(data)

        return render_template('admin_orders.html', orders=all_orders, username=session['username'])

    except Exception as e:
        print(f"Admin orders error: {e}")
        return render_template('admin_orders.html', orders=[], username=session.get('username', ''), error="Internal server error")

@app.route('/payment', methods=['POST'])
def payment():
    try:
        if 'username' not in session:
            return jsonify({"error": "Vui lòng đăng nhập"}), 401

        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON data"}), 400

        username = data.get('username')
        order_id = data.get('order_id')

        if not username or not order_id:
            return jsonify({"error": "Thiếu thông tin thanh toán"}), 400

        if username != session['username']:
            return jsonify({"error": "Thông tin người dùng không hợp lệ"}), 403

        if not db:
            return jsonify({"error": "Database connection failed"}), 500

        # Get order information
        orders_ref = db.collection('Orders').document(username).collection('Orders').document(order_id)
        order_doc = orders_ref.get()
        if not order_doc.exists:
            return jsonify({"error": "Đơn hàng không tồn tại"}), 404

        order_data = order_doc.to_dict()
        
        # If ML-DSA is available, use digital signature
        if OQS_AVAILABLE:
            message = f"{username}{order_id}{order_data['cost']}{order_data['quantity']}".encode()

            # Get user's ML-DSA keys
            user_doc = db.collection('Users').document(username).get()
            if not user_doc.exists:
                return jsonify({"error": "Người dùng không tồn tại"}), 404

            user_data = user_doc.to_dict()
            
            if 'mldsa_public_key' in user_data and 'mldsa_private_key' in user_data:
                public_key = base64.b64decode(user_data['mldsa_public_key'])
                private_key = base64.b64decode(user_data['mldsa_private_key'])

                # Sign with ML-DSA
                sig = oqs.Signature('Dilithium2')
                signature = sig.sign(message, private_key)

                # Verify signature
                is_valid = sig.verify(message, signature, public_key)
                if not is_valid:
                    return jsonify({"error": "Chữ ký không hợp lệ"}), 403

                # Update order status with signature
                orders_ref.update({
                    "status": "paid",
                    "payment_signature": base64.b64encode(signature).decode(),
                    "payment_time": datetime.utcnow().isoformat()
                })
            else:
                # Fallback: update without signature
                orders_ref.update({
                    "status": "paid",
                    "payment_time": datetime.utcnow().isoformat()
                })
        else:
            # No ML-DSA available, simple status update
            orders_ref.update({
                "status": "paid",
                "payment_time": datetime.utcnow().isoformat()
            })

        return jsonify({"message": "Thanh toán thành công!"})

    except Exception as e:
        print(f"Payment error: {e}")
        return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)