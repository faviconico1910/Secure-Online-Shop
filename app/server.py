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

def encrypt_card(card_number, key):
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
    h = SHA256.new()
    h.update((value + secret_key).encode())
    return h.hexdigest()

def hash_password(password):
    h = SHA256.new()
    h.update(password.encode())
    return h.hexdigest()

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
        # Generate ML-DSA keys (required)
        public_key, private_key = generate_mldsa_keys()
        if not public_key or not private_key:
            return jsonify({"error": "Không tạo được khóa lượng tử"}), 500
        user_data = {
            "username": username,
            "password_hash": hashed_pw,
            "encrypted_card": encrypted_card,
            "aes_key": base64.b64encode(aes_key).decode(),
            "search_token": search_token,
            "role": "customer",
            "created_at": datetime.utcnow().isoformat(),
            "mldsa_public_key": base64.b64encode(public_key).decode(),
            "quantum_safe_enabled": True
        }
        users_ref.document(username).set(user_data)
        PRIVATE_KEYS[username] = private_key
        return jsonify({"message": "Đăng ký thành công", "quantum_safe": True})
    except Exception as e:
        app.logger.error(f"Registration error: {e}")
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
        user_ref = db.collection('Users').document(username)
        # Đảm bảo generate key runtime cho user nếu mất
        if username not in PRIVATE_KEYS:
            public_key, private_key = generate_mldsa_keys()
            PRIVATE_KEYS[username] = private_key
            user_ref.update({"mldsa_public_key": base64.b64encode(public_key).decode()})
            app.logger.info(f"PRIVATE_KEYS regenerated for {username} on login")

        if hashed_input_pw != user_data.get("password_hash"):
            return jsonify({"error": "Mật khẩu không đúng"}), 401

        session['username'] = username
        session['role'] = user_data.get("role", "customer")
        session['quantum_safe_enabled'] = True  # Always True since ML-DSA is required
        
        return jsonify({
            "message": "Đăng nhập thành công",
            "quantum_safe": True
        })

    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    session.pop('quantum_safe_enabled', None)
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

@app.route('/create_payment_url')
def create_payment_url():
    """Tạo URL thanh toán VNPay với bảo mật ML-DSA bắt buộc"""
    if 'username' not in session:
        flash('Vui lòng đăng nhập', 'error')
        return redirect('/')
    
    username = session['username']
    order_id = request.args.get('order_id')
    
    if not order_id:
        flash('Không tìm thấy mã đơn hàng', 'error')
        return redirect('/orders')

    try:
        # Lấy đơn hàng từ Firestore
        order_ref = db.collection('Orders').document(username).collection('Orders').document(order_id)
        order_doc = order_ref.get()
        
        if not order_doc.exists:
            flash('Không tìm thấy đơn hàng', 'error')
            return redirect('/orders')

        order = order_doc.to_dict()

        # Kiểm tra trạng thái đơn hàng
        if order.get('status') == 'resolved':
            flash('Đơn hàng đã được thanh toán', 'info')
            return redirect('/orders')
        
        # Lấy thông tin user để có ML-DSA keys
        user_ref = db.collection('Users').document(username)
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            flash('Không tìm thấy thông tin người dùng', 'error')
            return redirect('/orders')
            
        user_data = user_doc.to_dict()
        
        app.logger.info(f"PRIVATE_KEYS hiện tại: {list(PRIVATE_KEYS.keys())}")
        if username not in PRIVATE_KEYS:
            flash('Không tìm thấy khóa ML-DSA. Vui lòng đăng nhập lại.', 'error')
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