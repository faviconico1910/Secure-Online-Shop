let cart = []; // Khai báo cart làm biến toàn cục

document.addEventListener('DOMContentLoaded', function () {
    // Lấy phần tử hiển thị số lượng giỏ hàng
    const cartCountElement = document.getElementById('cartCount');
    // Lấy toast element để hiển thị thông báo
    const toastLive = new bootstrap.Toast(document.getElementById('liveToast'));
    // Lấy nút mở giỏ hàng
    const openCartBtn = document.getElementById('openCartBtn');

    // Khởi tạo số lượng ban đầu từ giỏ hàng
    let cartCount = parseInt(cartCountElement.textContent) || 0;

    // Hàm cập nhật số lượng tổng trên giao diện
    function updateCartCount() {
        cartCount = cart.reduce((total, item) => total + item.quantity, 0);
        cartCountElement.textContent = cartCount;
    }

    // Hàm hiển thị toast và thêm sản phẩm vào giỏ hàng
    window.ShowToast = function(productName, price) {
        // Kiểm tra trạng thái đăng nhập
        const openAuthModalBtn = document.getElementById('openAuthModalBtn');
        if (openAuthModalBtn) {
            openAuthModalBtn.click();
            return;
        }

        // Thêm sản phẩm vào giỏ hàng
        const existingProduct = cart.find(item => item.name === productName);
        if (existingProduct) {
            existingProduct.quantity++;
        } else {
            cart.push({ name: productName, price: price, quantity: 1 });
        }

        // Cập nhật số lượng và giao diện
        updateCartCount();
        renderCart();
        toastLive.show();
    };

    // Hàm render giỏ hàng trong modal
    function renderCart() {
        const modalBody = document.getElementById('modalbody');
        const modalTotal = document.getElementById('modaltotal');

        modalBody.innerHTML = '';
        let total = 0;

        cart.forEach((item, index) => {
            const itemTotal = item.price * item.quantity;
            total += itemTotal;

            modalBody.innerHTML += `
                <div class="d-flex justify-content-between align-items-center mb-2 py-2 border-bottom">
                    <div>${item.name} - ${item.price.toLocaleString()} x ${item.quantity}</div>
                    <div>
                        <button class="btn btn-sm btn-primary" onclick="increaseQuantity(${index})">+1</button>
                        <button class="btn btn-sm btn-danger" onclick="decreaseQuantity(${index})">-1</button>
                        <button class="btn btn-sm btn-outline-danger" onclick="removeItem(${index})">Xóa</button>
                    </div>
                </div>
            `;
        });

        modalTotal.textContent = `Tổng: ${total.toLocaleString()} VNĐ`;
    }

    // Hàm tăng số lượng sản phẩm
    window.increaseQuantity = function(index) {
        cart[index].quantity++;
        updateCartCount();
        renderCart();
    };

    // Hàm giảm số lượng sản phẩm
    window.decreaseQuantity = function(index) {
        if (cart[index].quantity > 1) {
            cart[index].quantity--;
        } else {
            removeItem(index);
        }
        updateCartCount();
        renderCart();
    };

    // Hàm xóa sản phẩm khỏi giỏ hàng
    window.removeItem = function(index) {
        cart.splice(index, 1);
        updateCartCount();
        renderCart();
    };

    // Thêm sự kiện click cho nút "Giỏ Hàng"
    openCartBtn.addEventListener('click', function () {
        const openAuthModalBtn = document.getElementById('openAuthModalBtn');
        if (openAuthModalBtn) {
            openAuthModalBtn.click();
            return;
        }

        const modal = new bootstrap.Modal(document.getElementById('Modal'));
        renderCart();
        modal.show();
    });

    // Hàm xác nhận đặt hàng
    window.checkProduct = async function () {
        // Kiểm tra trạng thái đăng nhập
        const openAuthModalBtn = document.getElementById('openAuthModalBtn');
        if (openAuthModalBtn) {
            openAuthModalBtn.click();
            return;
        }

        // Kiểm tra giỏ hàng có rỗng không
        if (cart.length === 0) {
            const emptyCartToast = new bootstrap.Toast(document.getElementById('liveToast-modal-warning'));
            emptyCartToast.show();
            return;
        }

        try {
            // Lấy username từ session (giả sử server trả về username trong một phần tử HTML hoặc biến toàn cục)
            const usernameElement = document.querySelector('.username-display'); // Cần có phần tử hiển thị username
            const username = usernameElement ? usernameElement.textContent.replace('Chào, ', '').replace('!', '').trim() : null;

            if (!username) {
                throw new Error('Không tìm thấy thông tin người dùng');
            }

            // Gửi từng sản phẩm trong giỏ hàng đến server
            for (const item of cart) {
                const response = await fetch('/orders', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        username: username,
                        productname: item.name,
                        cost: item.price,
                        quantity: item.quantity
                    })
                });

                const data = await response.json();
                if (!response.ok) {
                    throw new Error(data.error || 'Đặt hàng thất bại');
                }
            }

            /// Hiển thị thông báo thành công
            const successToastEl = document.getElementById('liveToast-modal-success');
            if (successToastEl) {
                const successToast = new bootstrap.Toast(successToastEl);
                successToast.show();
            } else {
                console.error('Không tìm thấy phần tử #liveToast-modal-success');
                alert('Đặt hàng thành công!');
            }

            // Xóa giỏ hàng sau khi đặt hàng thành công
            cart = [];
            updateCartCount();
            renderCart();

            // Đóng modal giỏ hàng
            // const modal = bootstrap.Modal.getInstance(document.getElementById('Modal'));
            // modal.hide();

        } catch (err) {
            alert('Lỗi: ' + err.message);
        }
    };
    // Hàm gửi yêu cầu thanh toán
    window.processPayment = async function(orderId) {
        const usernameElement = document.querySelector('.username-display');
        const username = usernameElement ? usernameElement.textContent.replace('Chào, ', '').replace('!', '').trim() : null;

        if (!username) {
            alert('Vui lòng đăng nhập để thanh toán');
            return;
        }

        try {
            // Gửi yêu cầu đến server để ký số ML-DSA
            const response = await fetch('/payment', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: username,
                    order_id: orderId
                })
            });

            const data = await response.json();
            if (response.ok) {
                const successToast = new bootstrap.Toast(document.getElementById('liveToast-payment-success'));
                successToast.show();
            } else {
                throw new Error(data.error || 'Thanh toán thất bại');
            }
        } catch (err) {
            alert('Lỗi thanh toán: ' + err.message);
        }
    };
    // Hàm mở form thanh toán
    window.openPaymentForm = function(orderId, productName, cost, quantity) {
        currentOrderId = orderId;
        const orderInfoElement = document.getElementById('orderInfo');
        if (orderInfoElement) {
            const total = cost * quantity;
            orderInfoElement.textContent = `${productName} - ${cost.toLocaleString()} x ${quantity} = ${total.toLocaleString()} VNĐ (Order #${orderId})`;
        }
        
        // Reset form
        const paymentForm = document.getElementById('paymentForm');
        if (paymentForm) {
            paymentForm.reset();
        }
        
        // Show modal
        const paymentModal = document.getElementById('paymentModal');
        if (paymentModal) {
            const modal = new bootstrap.Modal(paymentModal);
            modal.show();
        }
    };

    // Hàm xử lý thanh toán với ML-DSA
    window.processPayment = async function() {
        if (!currentOrderId) return;

        // Validate form
        const form = document.getElementById('paymentForm');
        if (!form || !form.checkValidity()) {
            if (form) form.reportValidity();
            return;
        }

        const confirmBtn = document.getElementById('confirmPaymentBtn');
        const btnText = document.getElementById('paymentBtnText');
        const loading = document.getElementById('paymentLoading');

        // Show loading state
        if (confirmBtn) confirmBtn.disabled = true;
        if (btnText) btnText.classList.add('d-none');
        if (loading) loading.classList.remove('d-none');

        try {
            const usernameElement = document.querySelector('.username-display');
            const username = usernameElement ? usernameElement.textContent.replace('Chào, ', '').replace('!', '').trim() : null;

            if (!username) {
                throw new Error('Vui lòng đăng nhập để thanh toán');
            }

            // Get form data
            const paymentData = {
                username: username,
                order_id: currentOrderId,
                card_number: document.getElementById('cardNumber')?.value.replace(/\s/g, '') || '',
                expiry_date: document.getElementById('expiryDate')?.value || '',
                cvv: document.getElementById('cvv')?.value || '',
                card_holder: document.getElementById('cardHolder')?.value || ''
            };

            // Send payment request with ML-DSA signature
            const response = await fetch('/payment', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(paymentData)
            });

            const data = await response.json();
            
            if (response.ok) {
                // Success - show success toast
                const successToast = document.getElementById('liveToast-payment-success');
                if (successToast) {
                    const toast = new bootstrap.Toast(successToast);
                    toast.show();
                }
                
                // Close modal
                const paymentModal = document.getElementById('paymentModal');
                if (paymentModal) {
                    const modal = bootstrap.Modal.getInstance(paymentModal);
                    if (modal) modal.hide();
                }
                
                // Update UI - change button to disabled state
                updateOrderStatus(currentOrderId, 'resolved');
                
            } else {
                throw new Error(data.error || 'Thanh toán thất bại');
            }
            
        } catch (err) {
            // Show error toast
            const errorToast = document.getElementById('liveToast-payment-failed');
            if (errorToast) {
                const toast = new bootstrap.Toast(errorToast);
                toast.show();
            }
            console.error('Payment error:', err.message);
        } finally {
            // Reset button state
            if (confirmBtn) confirmBtn.disabled = false;
            if (btnText) btnText.classList.remove('d-none');
            if (loading) loading.classList.add('d-none');
        }
    };

    // Hàm cập nhật trạng thái đơn hàng trên UI
    function updateOrderStatus(orderId, newStatus) {
        // Find the order row and update it
        const rows = document.querySelectorAll('tbody tr');
        rows.forEach(row => {
            const orderIdCell = row.cells[0];
            if (orderIdCell && orderIdCell.textContent === orderId) {
                // Update status badge
                const statusCell = row.cells[5];
                if (statusCell) {
                    statusCell.innerHTML = '<span class="badge bg-success">resolved</span>';
                }
                
                // Update action button
                const actionCell = row.cells[6];
                if (actionCell) {
                    actionCell.innerHTML = `
                        <button class="btn btn-secondary btn-sm" disabled>
                            <i class="bi bi-check-circle"></i> Đã thanh toán
                        </button>
                    `;
                }
            }
        });
    }
});