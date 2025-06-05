document.addEventListener('DOMContentLoaded', function () {
    // Khởi tạo mảng giỏ hàng
    let cart = [];
    
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
            // Người dùng chưa đăng nhập, kích hoạt modal đăng nhập
            openAuthModalBtn.click();
            return;
        }

        // Người dùng đã đăng nhập, tiếp tục thêm sản phẩm vào giỏ hàng
        const existingProduct = cart.find(item => item.name === productName);
        
        if (existingProduct) {
            existingProduct.quantity++;
        } else {
            cart.push({ name: productName, price: price, quantity: 1 });
        }

        // Cập nhật số lượng tổng và giao diện giỏ hàng
        updateCartCount();
        renderCart();

        // Hiển thị thông báo
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
    // Thêm sự kiện click cho nút "Giỏ Hàng"
    openCartBtn.addEventListener('click', function () {
        // Kiểm tra trạng thái đăng nhập
        const openAuthModalBtn = document.getElementById('openAuthModalBtn');
        if (openAuthModalBtn) {
            // Người dùng chưa đăng nhập, kích hoạt modal đăng nhập
            openAuthModalBtn.click();
            return;
        }

        // Người dùng đã đăng nhập, mở modal giỏ hàng
        const modal = new bootstrap.Modal(document.getElementById('Modal'));
        renderCart();
        modal.show();
    });
});