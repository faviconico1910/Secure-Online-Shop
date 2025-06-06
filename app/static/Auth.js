document.addEventListener('DOMContentLoaded', function () {
    const openAuthModalBtn = document.getElementById('openAuthModalBtn');
    const authModalEl = document.getElementById('authModal');
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');
    const toggleText = document.getElementById('toggleText');
    const authModalTitle = document.getElementById('authModalTitle');
    const logoutBtn = document.getElementById('logout');
    const authModal = authModalEl ? new bootstrap.Modal(authModalEl) : null;

    // Mở modal đăng nhập/đăng ký
    if (openAuthModalBtn && authModal) {
        openAuthModalBtn.addEventListener('click', function () {
            authModal.show();
        });
    }

    // Xử lý đăng xuất
    if (logoutBtn) {
        logoutBtn.addEventListener('click', function () {
            window.location.href = '/logout';
        });
    }

    // Xử lý đăng nhập
    if (loginForm) {
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
                    window.location.reload();
                } else {
                    alert(data.error || 'Đăng nhập thất bại!');
                }
            } catch (err) {
                alert('Lỗi: ' + err.message);
            }
        });
    }

    // Xử lý đăng ký
    if (registerForm) {
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
    }

    // Hàm chuyển đổi giữa đăng nhập và đăng ký
    window.toggleAuthForm = function () {
        if (loginForm.classList.contains('d-none')) {
            loginForm.classList.remove('d-none');
            registerForm.classList.add('d-none');
            authModalTitle.textContent = 'Đăng nhập';
            toggleText.innerHTML = 'Chưa có tài khoản? <a href="javascript:void(0)" onclick="toggleAuthForm()">Đăng ký</a>';
        } else {
            loginForm.classList.add('d-none');
            registerForm.classList.remove('d-none');
            authModalTitle.textContent = 'Đăng ký';
            toggleText.innerHTML = 'Đã có tài khoản? <a href="javascript:void(0)" onclick="toggleAuthForm()">Đăng nhập</a>';
        }
    };
});