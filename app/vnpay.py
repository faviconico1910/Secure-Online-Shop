"""
VNPay Integration Module - Fixed Version
File: vnpay_fixed.py
"""

import hashlib
import hmac
import urllib.parse
import time
from datetime import datetime, timedelta, timezone
from collections import OrderedDict


class VNPayConfig:
    """VNPay configuration class"""
    def __init__(self, tmn_code, hash_secret, vnpay_url, return_url):
        self.tmn_code = tmn_code
        self.hash_secret = hash_secret
        self.vnpay_url = vnpay_url
        self.return_url = return_url


class VNPay:
    """VNPay payment gateway integration - Fixed version"""
    
    def __init__(self, config: VNPayConfig):
        self.config = config
    
    def create_payment_url(self, order_info, amount, order_id, ip_addr='127.0.0.1'):
        """
        Tạo URL thanh toán VNPay - Fixed version
        
        Args:
            order_info (str): Thông tin đơn hàng
            amount (int/float): Số tiền (VNĐ)
            order_id (str): Mã đơn hàng
            ip_addr (str): IP address của client
            
        Returns:
            tuple: (payment_url, txn_ref)
        """
        # Tạo mã giao dịch duy nhất
        txn_ref = f"{order_id}_{int(time.time())}"
        
        # Tính thời gian hết hạn (15 phút)
        vn_tz = timezone(timedelta(hours=7))
        now = datetime.now(vn_tz)
        expire_time = now + timedelta(minutes=15)
        
        # Tạo parameters - QUAN TRỌNG: không được có khoảng trắng thừa
        vnp_params = {
            'vnp_Version': '2.1.0',
            'vnp_Command': 'pay',
            'vnp_TmnCode': self.config.tmn_code,
            'vnp_Amount': str(int(float(amount) * 100)),  # Chuyển sang đơn vị nhỏ nhất
            'vnp_CurrCode': 'VND',
            'vnp_TxnRef': txn_ref,
            'vnp_OrderInfo': order_info,
            'vnp_OrderType': 'other',
            'vnp_Locale': 'vn',
            'vnp_CreateDate': now.strftime('%Y%m%d%H%M%S'),
            'vnp_IpAddr': ip_addr,
            'vnp_ExpireDate': expire_time.strftime('%Y%m%d%H%M%S'),
            'vnp_ReturnUrl': self.config.return_url
        }
        
        # Tạo URL với chữ ký
        query_string = self._build_query_string(vnp_params)
        payment_url = f"{self.config.vnpay_url}?{query_string}"
        
        return payment_url, txn_ref
    
    def verify_return_url(self, request_params):
        """
        Xác thực chữ ký từ VNPay return URL
        
        Args:
            request_params (dict): Parameters từ VNPay return
            
        Returns:
            tuple: (is_valid, response_code, txn_ref)
        """
        # Lấy secure hash từ response
        received_hash = request_params.get('vnp_SecureHash', '')
        
        # Tạo copy và xóa secure hash
        verify_params = dict(request_params)
        verify_params.pop('vnp_SecureHash', None)
        verify_params.pop('vnp_SecureHashType', None)
        
        # Tạo expected hash
        expected_hash = self._create_secure_hash(verify_params)
        
        # So sánh hash (case insensitive)
        is_valid = received_hash.upper() == expected_hash.upper()
        
        return (
            is_valid,
            request_params.get('vnp_ResponseCode', ''),
            request_params.get('vnp_TxnRef', '')
        )
    
    def _build_query_string(self, params):
        """Tạo query string với chữ ký - Fixed version"""
        # Tạo secure hash trước
        secure_hash = self._create_secure_hash(params)
        
        # Sắp xếp parameters theo alphabet
        sorted_params = sorted(params.items())
        
        # Tạo query string - QUAN TRỌNG: encode đúng cách
        query_parts = []
        for k, v in sorted_params:
            encoded_value = urllib.parse.quote_plus(str(v), safe='')
            query_parts.append(f"{k}={encoded_value}")
        
        # Thêm secure hash
        query_parts.append(f"vnp_SecureHash={secure_hash}")
        
        return '&'.join(query_parts)
    

    def _create_secure_hash(self, params):
        """Tạo secure hash theo kiểu dùng chuỗi URL-encoded giống hàm get_payment_url (KHÔNG khuyến khích nếu theo chuẩn VNPay)"""

        # 1. Sắp xếp theo alphabet
        sorted_params = sorted(params.items())

        # 2. Tạo query string đã URL-encoded
        query_string = '&'.join(f"{k}={urllib.parse.quote_plus(str(v))}" for k, v in sorted_params)

        # 3. Debug chuỗi trước khi ký
        print(f"Encoded query string for HMAC: {query_string}")

        # 4. Tạo HMAC SHA512
        secure_hash = hmac.new(
            self.config.hash_secret.encode('utf-8'),
            query_string.encode('utf-8'),
            hashlib.sha512
        ).hexdigest()

        print(f"Secure hash: {secure_hash}")
        return secure_hash

    
    @staticmethod
    def get_error_message(response_code):
        """Lấy thông báo lỗi theo mã response"""
        error_messages = {
            '00': 'Giao dịch thành công',
            '07': 'Trừ tiền thành công. Giao dịch bị nghi ngờ (liên quan tới lừa đảo, giao dịch bất thường).',
            '09': 'Giao dịch không thành công do: Thẻ/Tài khoản của khách hàng chưa đăng ký dịch vụ InternetBanking tại ngân hàng.',
            '10': 'Giao dịch không thành công do: Khách hàng xác thực thông tin thẻ/tài khoản không đúng quá 3 lần',
            '11': 'Giao dịch không thành công do: Đã hết hạn chờ thanh toán. Xin quý khách vui lòng thực hiện lại giao dịch.',
            '12': 'Giao dịch không thành công do: Thẻ/Tài khoản của khách hàng bị khóa.',
            '13': 'Giao dịch không thành công do Quý khách nhập sai mật khẩu xác thực giao dịch (OTP).',
            '24': 'Giao dịch không thành công do: Khách hàng hủy giao dịch',
            '51': 'Giao dịch không thành công do: Tài khoản của quý khách không đủ số dư để thực hiện giao dịch.',
            '65': 'Giao dịch không thành công do: Tài khoản của Quý khách đã vượt quá hạn mức giao dịch trong ngày.',
            '70': 'Giao dịch không thành công do: Ngân hàng bảo trì hoặc sai chữ ký.',
            '75': 'Ngân hàng thanh toán đang bảo trì.',
            '79': 'Giao dịch không thành công do: KH nhập sai mật khẩu thanh toán quá số lần quy định.',
            '99': 'Các lỗi khác (lỗi còn lại, không có trong danh sách mã lỗi đã liệt kê)'
        }
        
        return error_messages.get(response_code, f'Lỗi không xác định: {response_code}')


# Utility functions for easy usage
def create_vnpay_instance(tmn_code, hash_secret, vnpay_url, return_url):
    """Tạo VNPay instance"""
    config = VNPayConfig(tmn_code, hash_secret, vnpay_url, return_url)
    return VNPay(config)


def test_vnpay_signature(tmn_code, hash_secret):
    """Test function để kiểm tra chữ ký VNPay - với dữ liệu thực tế"""
    
    # Dữ liệu test giống với log của bạn
    test_params = {
        'vnp_Version': '2.1.0',
        'vnp_Command': 'pay',
        'vnp_TmnCode': tmn_code,
        'vnp_Amount': '76000000',  # Từ log của bạn
        'vnp_CurrCode': 'VND',
        'vnp_TxnRef': 'order_20250606_075656_394_1749240619',  # Từ log
        'vnp_OrderInfo': 'Thanh toan don hang order_20250606_075656_394',
        'vnp_OrderType': 'other',
        'vnp_Locale': 'vn',
        'vnp_ReturnUrl': 'https://d5b7-14-191-104-116.ngrok-free.app/payment_return',
        'vnp_IpAddr': '172.18.0.1',
        'vnp_CreateDate': '20250607031019',
        'vnp_ExpireDate': '20250607032519'
    }
    
    config = VNPayConfig(tmn_code, hash_secret, '', '')
    vnpay = VNPay(config)
    
    print("=== TEST VNPAY SIGNATURE ===")
    print(f"TMN Code: {tmn_code}")
    print(f"Hash Secret: {hash_secret}")
    print()
    
    secure_hash = vnpay._create_secure_hash(test_params)
    query_string = vnpay._build_query_string(test_params)
    
    print(f"Expected hash từ code: {secure_hash}")
    print(f"Hash từ log của bạn: 7233fae43b31b9afaeb9843c2f1698a0e1a716d71f640cf3cf6d8e26a0d610db3d93a432ffc960746c092de63dd7483eba316371c34be111369f003056e2f440")
    print(f"So sánh: {'MATCH' if secure_hash.upper() == '7233fae43b31b9afaeb9843c2f1698a0e1a716d71f640cf3cf6d8e26a0d610db3d93a432ffc960746c092de63dd7483eba316371c34be111369f003056e2f440'.upper() else 'NO MATCH'}")
    print()
    print(f"Query string: {query_string}")
    
    return secure_hash, query_string


# Test với thông tin sandbox từ code của bạn
if __name__ == "__main__":
    test_vnpay_signature('ATL2SY6W', 'XEVB4ZNWKLQXXVX0MV72KY7U0CTICYYR')