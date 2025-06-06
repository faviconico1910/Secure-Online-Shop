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
});