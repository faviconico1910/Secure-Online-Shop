from flask import Flask, request, jsonify, render_template, session, redirect, flash
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import base64
from dotenv import load_dotenv
import os
from datetime import datetime, timedelta, timezone
import firebase_admin
from firebase_admin import credentials, firestore
import logging
import json
import hashlib
logging.basicConfig(level=logging.DEBUG)
from vnpay import create_vnpay_instance

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

ECDHE_KEYS = {}  # lưu ephemeral private key tạm thời cho mỗi phiên (user/session)

# Yêu cầu liboqs-python để sử dụng ML-DSA
try:
    import oqs
    OQS_AVAILABLE = True
    print("ML-DSA quantum-safe cryptography is available")
except ImportError:
    raise ImportError("liboqs-python is required for ML-DSA. Please install it to enable quantum-safe cryptography.")

load_dotenv()
# Initialize Firebase
app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.getenv("SECRET_KEY", "default-secret-key-change-this")
token_secret = os.getenv("TOKEN_SECRET", "default-token-secret-change-this")

# Initialize Firebase
try:
    cred = credentials.ApplicationDefault()
    firebase_admin.initialize_app(cred)
    db = firestore.client()
except Exception as e:
    print(f"Firebase initialization error: {e}")
    db = None

# Local in-memory store for private keys
PRIVATE_KEYS = {}

# Lấy giá trị từ biến môi trường
VNPAY_TMN_CODE = os.getenv('VNPAY_TMN_CODE')
VNPAY_HASH_SECRET = os.getenv('VNPAY_HASH_SECRET')
VNPAY_URL = os.getenv('VNPAY_URL')
VNPAY_RETURN_URL = os.getenv('VNPAY_RETURN_URL')

# Khởi tạo vnpay instance
vnpay = create_vnpay_instance(
    tmn_code=VNPAY_TMN_CODE,
    hash_secret=VNPAY_HASH_SECRET,
    vnpay_url=VNPAY_URL,
    return_url=VNPAY_RETURN_URL
)

# Trong /init_ecdh
@app.route('/init_ecdh', methods=['POST'])
def init_ecdh():
    data = request.get_json()
    is_registration = data.get('is_registration', False) if data else False

    if not is_registration and 'username' not in session:
        app.logger.warning("Khởi tạo ECDHE thất bại: Không có username trong session")
        return jsonify({'error': 'Chưa đăng nhập: Vui lòng đăng nhập trước'}), 401

    try:
        if not data or 'client_pub' not in data:
            app.logger.error("Lỗi khởi tạo ECDHE: Thiếu hoặc khóa công khai client không hợp lệ")
            return jsonify({'error': 'Yêu cầu không hợp lệ: Thiếu khóa công khai client'}), 400

        client_pub_pem = data.get('client_pub')
        try:
            client_public_key = serialization.load_pem_public_key(
                client_pub_pem.encode(), backend=default_backend()
            )
        except Exception as e:
            app.logger.error(f"Lỗi phân tích khóa công khai client: {e}")
            return jsonify({'error': 'Khóa công khai client không hợp lệ'}), 400

        server_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        server_public_key = server_private_key.public_key()

        shared_key = server_private_key.exchange(ec.ECDH(), client_public_key)

        # Đảm bảo khớp với client: sử dụng HKDF để tạo khóa AES 128-bit
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=16,  # 128-bit key
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)

        if is_registration:
            import uuid
            temp_token = str(uuid.uuid4())
            ECDHE_KEYS[temp_token] = derived_key
            app.logger.debug(f"Lưu temp_token: {temp_token} với khóa: {derived_key.hex()}")
            server_pub_pem = server_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            return jsonify({'server_pub': server_pub_pem, 'temp_token': temp_token})
        else:
            ECDHE_KEYS[session['username']] = derived_key
            server_pub_pem = server_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            app.logger.info(f"Khởi tạo ECDHE thành công cho user: {session['username']}")
            return jsonify({'server_pub': server_pub_pem})

    except Exception as e:
        app.logger.error(f"Lỗi khởi tạo ECDHE: {e}")
        return jsonify({'error': f'Lỗi server: {str(e)}'}), 500

def encrypt_card_with_ecdh(card_number, username):
    try:
        key = ECDHE_KEYS.get(username)
        if not key:
            raise ValueError("ECDHE session key not found")
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(card_number.encode())
        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'nonce': base64.b64encode(cipher.nonce).decode(),
            'tag': base64.b64encode(tag).decode()
        }
    except Exception as e:
        app.logger.error(f"ECDHE encryption error: {e}")
        return None

def decrypt_with_ecdh(encrypted_b64, iv_b64, username):
    try:
        key = ECDHE_KEYS.get(username)
        if not key:
            raise ValueError("ECDHE session key not found")
        cipher = AES.new(key, AES.MODE_GCM, nonce=base64.b64decode(iv_b64))
        plaintext = cipher.decrypt(base64.b64decode(encrypted_b64))
        return plaintext.decode('utf-8')
    except Exception as e:
        app.logger.error(f"ECDHE decryption error for {username}: {e}")
        raise ValueError("Decryption failed")


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

def generate_search_token(value: str):
    salt = get_random_bytes(16)
    h = SHA256.new()
    h.update(salt + value.encode())
    return base64.b64encode(salt).decode(), h.hexdigest()

def hash_password(password):
    salt = get_random_bytes(16) # 16 bytes ngẫu nhiên
    h = SHA256.new()
    h.update(salt + password.encode())
    return {
        'salt': base64.b64encode(salt).decode(),
        'hash': h.hexdigest()
    }

def generate_order_token(username, order_id):
    h = SHA256.new()
    h.update((username + order_id + str(datetime.utcnow())).encode())
    return base64.b64encode(h.digest()).decode()[:16]

def generate_mldsa_keys():
    try:
        sig = oqs.Signature('Dilithium2')
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
        return public_key, private_key
    except Exception as e:
        print(f"ML-DSA key generation error: {e}")
        return None, None

def sign_payment_data(payment_data, username):
    try:
        if username not in PRIVATE_KEYS:
            app.logger.error(f"No private key found for user {username}")
            return None
        sig = oqs.Signature('Dilithium2')
        sig.generate_keypair()
        sig.secret_key = PRIVATE_KEYS[username]
        data_to_sign = json.dumps(payment_data, sort_keys=True).encode('utf-8')
        signature = sig.sign(data_to_sign)
        return base64.b64encode(signature).decode()
    except Exception as e:
        app.logger.error(f"ML-DSA signing error: {e}")
        return None

def verify_payment_signature(payment_data, signature_b64, public_key_b64):
    try:
        sig = oqs.Signature('Dilithium2')
        public_key = base64.b64decode(public_key_b64)
        sig.import_public_key(public_key)
        data_to_verify = json.dumps(payment_data, sort_keys=True).encode('utf-8')
        signature = base64.b64decode(signature_b64)
        return sig.verify(data_to_verify, signature, public_key)
    except Exception as e:
        app.logger.error(f"ML-DSA verification error: {e}")
        return False

def generate_payment_hash(order_id, username, amount, timestamp):
    data = f"{order_id}:{username}:{amount}:{timestamp}:{token_secret}"
    return hashlib.sha256(data.encode()).hexdigest()

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
        temp_token = data.get('temp_token')
        encrypted_card = {
            "ciphertext": data.get('encrypted_card'),
            "nonce": data.get('card_iv'),
            "tag": data.get('card_tag')
        }

        if not username or not password or not temp_token or not all(encrypted_card.values()):
            return jsonify({"error": "Thiếu thông tin đăng ký hoặc dữ liệu không hợp lệ"}), 400

        if not db:
            return jsonify({"error": "Database connection failed"}), 500

        users_ref = db.collection('Users')
        query = users_ref.where('username', '==', username).limit(1).stream()
        if any(query):
            return jsonify({"error": "Username đã tồn tại"}), 400

        # Debug dữ liệu nhận được
        app.logger.debug(f"Dữ liệu encrypted_card: {encrypted_card}")
        app.logger.debug(f"temp_token: {temp_token}, ECDHE_KEYS: {ECDHE_KEYS}")

        # Giải mã thẻ tín dụng với temp_token
        key = ECDHE_KEYS.get(temp_token)
        if not key:
            app.logger.error(f"Khóa tạm thời không hợp lệ cho temp_token: {temp_token}")
            return jsonify({"error": "Khóa tạm thời không hợp lệ"}), 400

        plaintext_card = decrypt_card(encrypted_card, key)
        if not plaintext_card:
            app.logger.error(f"Giải mã thất bại với key: {key.hex()}, encrypted_card: {encrypted_card}")
            return jsonify({"error": "Giải mã thẻ tín dụng thất bại"}), 400

        # Tiếp tục xử lý đăng ký
        password_data = hash_password(password)
        hashed_pw = password_data['hash']
        password_salt = password_data['salt']

        search_token_salt, search_token = generate_search_token(username)

        public_key, private_key = generate_mldsa_keys()
        if not public_key or not private_key:
            return jsonify({"error": "Không tạo được khóa lượng tử"}), 500

        user_data = {
            "username": username,
            "password_hash": hashed_pw,
            "password_salt": password_salt,
            "search_token": search_token,
            "search_token_salt": search_token_salt,
            "encrypted_card": encrypted_card,
            "role": "customer",
            "created_at": datetime.utcnow().isoformat(),
            "mldsa_public_key": base64.b64encode(public_key).decode(),
            "quantum_safe_enabled": True
        }

        users_ref.document(username).set(user_data)
        PRIVATE_KEYS[username] = private_key
        ECDHE_KEYS.pop(temp_token, None)

        return jsonify({"message": "Đăng ký thành công", "quantum_safe": True})

    except Exception as e:
        app.logger.error(f"Registration error: {e}")
        return jsonify({"error": f"Lỗi server: {str(e)}"}), 500


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

        # Tìm người dùng bằng username
        users_ref = db.collection('Users').document(username)
        user_doc = users_ref.get()
        
        if not user_doc.exists:
            return jsonify({"error": "Username không tồn tại"}), 400
        
        user_data = user_doc.to_dict()
        
        # Xác minh search token
        search_token_salt = user_data.get('search_token_salt')
        if not search_token_salt:
            return jsonify({"error": "Không tìm thấy salt cho search token"}), 500
        search_h = SHA256.new()
        search_h.update(base64.b64decode(search_token_salt) + username.encode())
        if search_h.hexdigest() != user_data.get('search_token'):
            return jsonify({"error": "Username không tồn tại"}), 400

        # Xác minh mật khẩu
        password_salt = user_data.get('password_salt')
        if not password_salt:
            return jsonify({"error": "Không tìm thấy salt cho mật khẩu"}), 500
        hashed_input_pw = SHA256.new()
        hashed_input_pw.update(base64.b64decode(password_salt) + password.encode())
        if hashed_input_pw.hexdigest() != user_data.get('password_hash'):
            return jsonify({"error": "Mật khẩu không đúng"}), 401

        # Đảm bảo khóa ML-DSA
        if username not in PRIVATE_KEYS:
            public_key, private_key = generate_mldsa_keys()
            PRIVATE_KEYS[username] = private_key
            users_ref.update({"mldsa_public_key": base64.b64encode(public_key).decode()})
            app.logger.info(f"PRIVATE_KEYS regenerated for {username} on login")

        session['username'] = username
        session['role'] = user_data.get('role', 'customer')
        session['quantum_safe_enabled'] = True
        
        return jsonify({
            "message": "Đăng nhập thành công",
            "quantum_safe": True
        })

    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/logout')
def logout():
    username = session.pop('username', None)
    session.pop('username', None)
    session.pop('role', None)
    session.pop('quantum_safe_enabled', None)
    if username:
        PRIVATE_KEYS.pop(username, None)  # Xóa khóa riêng
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
            quantity = data.get('quantity')

            encrypted_name = {
                "ciphertext": data.get('productname'),
                "nonce": data.get('productname_iv'),
                "tag": data.get('productname_tag')
            }
            encrypted_cost = {
                "ciphertext": data.get('cost'),
                "nonce": data.get('cost_iv'),
                "tag": data.get('cost_tag')
            }

            key = ECDHE_KEYS.get(username)
            if not key:
                app.logger.warning(f"⚠️ Không tìm thấy ECDHE key cho {username}")
                return jsonify({"error": "Phiên ECDHE không hợp lệ. Vui lòng đăng nhập lại."}), 400
            # Giải mã với ECDHE
            try:
                productname = decrypt_card(encrypted_name, key)
                cost_str = decrypt_card(encrypted_cost, key)
                cost = float(cost_str)
            except Exception as e:
                return jsonify({"error": "Giải mã thất bại hoặc phiên ECDHE không hợp lệ"}), 400

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

@app.route('/create_payment_url')
def create_payment_url():
    """Tạo URL thanh toán VNPay với bảo mật ML-DSA bắt buộc"""
    if 'username' not in session:
        flash('Vui lòng đăng nhập', 'error')
        app.logger.warning("Redirect fallback tại bước 1")
        return redirect('/')
    
    username = session['username']
    order_id = request.args.get('order_id')
    
    if not order_id:
        flash('Không tìm thấy mã đơn hàng', 'error')
        app.logger.warning("Redirect fallback tại bước 2")
        return redirect('/orders')

    try:
        # Lấy đơn hàng từ Firestore
        order_ref = db.collection('Orders').document(username).collection('Orders').document(order_id)
        order_doc = order_ref.get()
        
        if not order_doc.exists:
            flash('Không tìm thấy đơn hàng', 'error')
            app.logger.warning("Redirect fallback tại bước 3")
            return redirect('/orders')

        order = order_doc.to_dict()

        # Kiểm tra trạng thái đơn hàng
        if order.get('status') == 'resolved':
            flash('Đơn hàng đã được thanh toán', 'info')
            app.logger.warning("Redirect fallback tại bước 4")
            return redirect('/orders')
        
        # Lấy thông tin user để có ML-DSA keys
        user_ref = db.collection('Users').document(username)
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            flash('Không tìm thấy thông tin người dùng', 'error')
            app.logger.warning("Redirect fallback tại bước 5")
            return redirect('/orders')
            
        user_data = user_doc.to_dict()
        
        app.logger.info(f"PRIVATE_KEYS hiện tại: {list(PRIVATE_KEYS.keys())}")
        if username not in PRIVATE_KEYS:
            flash('Không tìm thấy khóa ML-DSA. Vui lòng đăng nhập lại.', 'error')
            app.logger.warning("Redirect fallback tại bước 6")
            return redirect('/orders')

        # Tạo payment data để ký
        amount = float(order.get('cost', 0))
        payment_timestamp = datetime.utcnow().isoformat()
        
        payment_data = {
            "order_id": order_id,
            "username": username,
            "amount": amount,
            "timestamp": payment_timestamp,
            "product_name": order.get('productname', ''),
            "quantity": order.get('quantity', 1)
        }
        
        # Ký dữ liệu thanh toán với ML-DSA
        signature = sign_payment_data(payment_data, username)
        if not signature:
            app.logger.error(f"Failed to sign payment data with ML-DSA for user: {username}")
            flash('Không thể ký dữ liệu thanh toán với ML-DSA', 'error')
            app.logger.warning("Redirect fallback tại bước 7")
            return redirect('/orders')
        
        # Tạo hash bảo mật cho payment
        payment_hash = generate_payment_hash(order_id, username, amount, payment_timestamp)
        
        # Tạo URL thanh toán VNPay
        order_info = f"Thanh toan don hang {order_id}"
        ip_addr = request.remote_addr or '127.0.0.1'
        
        payment_url, txn_ref = vnpay.create_payment_url(
            order_info=order_info,
            amount=amount,
            order_id=order_id,
            ip_addr=ip_addr
        )

        # Lưu thông tin payment vào session với security data
        session[f'payment_{txn_ref}'] = {
            'order_id': order_id,
            'username': username,
            'amount': amount,
            'payment_data': payment_data,
            'payment_hash': payment_hash,
            'signature': signature,
            'quantum_safe_used': True,
            'created_at': payment_timestamp
        }
        
        # Lưu security metadata vào database
        security_ref = db.collection('PaymentSecurity').document(txn_ref)
        security_ref.set({
            'order_id': order_id,
            'username': username,
            'payment_hash': payment_hash,
            'quantum_safe_used': True,
            'signature_created': True,
            'created_at': payment_timestamp,
            'status': 'pending'
        })
        
        flash('Thanh toán được bảo mật bằng chữ ký số lượng tử ML-DSA', 'info')
        app.logger.debug(f"Secure payment URL created with ML-DSA: {payment_url}")
        return redirect(payment_url)
        
    except Exception as e:
        app.logger.error(f"Error creating secure payment URL: {e}")
        flash('Có lỗi xảy ra khi tạo URL thanh toán', 'error')
        app.logger.warning("Redirect fallback tại bước 7")
        return redirect('/orders')

@app.route('/payment_return')
def payment_return():
    """Xử lý kết quả trả về từ VNPay với xác thực ML-DSA bắt buộc"""
    try:
        # Lấy tất cả parameters từ request
        request_params = dict(request.args)
        
        # Xác thực chữ ký VNPay
        is_valid, response_code, txn_ref = vnpay.verify_return_url(request_params)
        
        if not is_valid:
            flash('Chữ ký VNPay không hợp lệ', 'error')
            return redirect('/orders?payment_status=failed')
        
        # Lấy thông tin giao dịch từ session
        payment_info = session.get(f'payment_{txn_ref}')
        if not payment_info:
            flash('Không tìm thấy thông tin giao dịch', 'error')
            return redirect('/orders?payment_status=failed')
        
        order_id = payment_info['order_id']
        username = payment_info['username']
        
        # Xác thực ML-DSA signature
        user_ref = db.collection('Users').document(username)
        user_doc = user_ref.get()
        user_data = user_doc.to_dict()
        if not user_doc.exists or not user_data.get('mldsa_public_key'):
            app.logger.error(f"ML-DSA public key not found for user: {username}")
            flash('Không tìm thấy khóa công khai ML-DSA', 'error')
            return redirect('/orders?payment_status=failed')

        signature_valid = verify_payment_signature(
            payment_info['payment_data'],
            payment_info['signature'],
            user_data['mldsa_public_key']
        )
        
        if not signature_valid:
            app.logger.error(f"ML-DSA signature verification failed for payment: {txn_ref}")
            flash('Chữ ký số lượng tử không hợp lệ', 'error')
            return redirect('/orders?payment_status=failed')
        
        app.logger.info(f"ML-DSA signature verified successfully for payment: {txn_ref}")
        
        # Xác thực payment hash
        expected_hash = generate_payment_hash(
            order_id, username, 
            payment_info['amount'], 
            payment_info['payment_data']['timestamp']
        )
        
        if expected_hash != payment_info.get('payment_hash'):
            app.logger.error(f"Payment hash verification failed for: {txn_ref}")
            flash('Dữ liệu thanh toán không hợp lệ', 'error')
            return redirect('/orders?payment_status=failed')
        
        if response_code == '00':
            # Thanh toán thành công và chữ ký hợp lệ
            try:
                order_ref = db.collection('Orders').document(username).collection('Orders').document(order_id)
                order_ref.update({
                    'status': 'resolved',
                    'payment_method': 'vnpay',
                    'transaction_ref': txn_ref,
                    'paid_at': datetime.now(timezone(timedelta(hours=7))),
                    'quantum_safe_verified': True,
                    'signature_verified': True
                })
                
                # Cập nhật security record
                security_ref = db.collection('PaymentSecurity').document(txn_ref)
                security_ref.update({
                    'status': 'completed',
                    'signature_verified': True,
                    'completed_at': datetime.now(timezone(timedelta(hours=7))).isoformat()
                })
                
                # Xóa thông tin giao dịch khỏi session
                session.pop(f'payment_{txn_ref}', None)
                
                flash('Thanh toán thành công với bảo mật lượng tử ML-DSA!', 'success')
                return redirect('/orders?payment_status=success')
                
            except Exception as e:
                app.logger.error(f"Error updating order status: {e}")
                flash('Có lỗi cập nhật đơn hàng', 'warning')
                return redirect('/orders?payment_status=success')
        else:
            # Thanh toán thất bại
            error_msg = vnpay.get_error_message(response_code)
            flash(f'Thanh toán thất bại: {error_msg}', 'error')
            
            # Cập nhật security record
            try:
                security_ref = db.collection('PaymentSecurity').document(txn_ref)
                security_ref.update({
                    'status': 'failed',
                    'failure_reason': error_msg,
                    'failed_at': datetime.utcnow().isoformat()
                })
            except:
                pass
            
            # Xóa thông tin giao dịch
            session.pop(f'payment_{txn_ref}', None)
            
            return redirect('/orders?payment_status=failed')
            
    except Exception as e:
        app.logger.error(f"Error processing secure payment return: {e}")
        flash('Có lỗi xảy ra khi xử lý kết quả thanh toán', 'error')
        return redirect('/orders?payment_status=failed')

@app.route('/payment_security/<txn_ref>')
def payment_security_info(txn_ref):
    """API để kiểm tra thông tin bảo mật của giao dịch"""
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        security_ref = db.collection('PaymentSecurity').document(txn_ref)
        security_doc = security_ref.get()
        
        if not security_doc.exists:
            return jsonify({"error": "Transaction not found"}), 404
            
        security_data = security_doc.to_dict()
        
        # Chỉ trả về thông tin nếu user sở hữu giao dịch
        if security_data.get('username') != session['username']:
            return jsonify({"error": "Forbidden"}), 403
            
        return jsonify({
            "transaction_ref": txn_ref,
            "quantum_safe_used": True,
            "signature_verified": security_data.get('signature_verified', False),
            "status": security_data.get('status', 'unknown'),
            "created_at": security_data.get('created_at'),
            "completed_at": security_data.get('completed_at')
        })
        
    except Exception as e:
        app.logger.error(f"Error fetching payment security info: {e}")
        return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)