document.addEventListener('DOMContentLoaded', function () {
    const openAuthModalBtn = document.getElementById('openAuthModalBtn');
    const authModalEl = document.getElementById('authModal');
    const authModal = new bootstrap.Modal(authModalEl);

    openAuthModalBtn.addEventListener('click', function () {
        authModal.show();
    });
});

document.addEventListener('DOMContentLoaded', function () {
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');
    const toggleText = document.getElementById('toggleText');
    const authModalTitle = document.getElementById('authModalTitle');

    // Xử lý Đăng nhập
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('loginUsername').value.trim();
        const password = document.getElementById('loginPassword').value.trim();

        try {
        const res = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await res.json();
        if (res.ok) {
            alert('Đăng nhập thành công!');
            window.location.reload(); // Tải lại trang để cập nhật trạng thái người dùng
        } else {
            alert(data.error || 'Đăng nhập thất bại!');
        }
        } catch (err) {
            alert('Lỗi: ' + err.message);
        }
    });

    // Xử lý Đăng ký
    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('registerUsername').value.trim();
        const password = document.getElementById('registerPassword').value.trim();
        const confirmPassword = document.getElementById('registerConfirmPassword').value.trim();
        const card = document.getElementById('registerCard').value.trim();

        if (password !== confirmPassword) {
            alert('Mật khẩu và xác nhận mật khẩu không khớp!');
            return;
        }

        try {
        const res = await fetch('/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password, card })
        });

        const data = await res.json();
        if (res.ok) {
            alert('Đăng ký thành công!');
            // Chuyển sang form Đăng nhập
            registerForm.classList.add('d-none');
            loginForm.classList.remove('d-none');
            authModalTitle.textContent = 'Đăng nhập';
            toggleText.innerHTML = 'Chưa có tài khoản? <a href="javascript:void(0)" onclick="toggleAuthForm()">Đăng ký</a>';
        } else {
            alert(data.error || 'Đăng ký thất bại!');
        }
        } catch (err) {
        alert('Lỗi: ' + err.message);
        }
    });

    // Hàm chuyển đổi giữa Đăng nhập và Đăng ký
    window.toggleAuthForm = function () {
        if (loginForm.classList.contains('d-none')) {
            // Hiển thị form Đăng nhập
            loginForm.classList.remove('d-none');
            registerForm.classList.add('d-none');
            authModalTitle.textContent = 'Đăng nhập';
            toggleText.innerHTML = 'Chưa có tài khoản? <a href="javascript:void(0)" onclick="toggleAuthForm()">Đăng ký</a>';
        } else {
        // Hiển thị form Đăng ký
            loginForm.classList.add('d-none');
            registerForm.classList.remove('d-none');
            authModalTitle.textContent = 'Đăng ký';
            toggleText.innerHTML = 'Đã có tài khoản? <a href="javascript:void(0)" onclick="toggleAuthForm()">Đăng nhập</a>';
        }
    };
});

  document.addEventListener('DOMContentLoaded', function () {
    const logoutBtn = document.getElementById('logout');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', function () {
        window.location.href = '/logout';
      });
    }
  });
