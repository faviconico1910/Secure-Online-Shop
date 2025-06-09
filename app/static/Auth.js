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
                    window.sessionStorage.removeItem('ecdhe_temp_token');
                    await initECDHE();
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
            // Khởi tạo ECDHE với isRegistration = true
            await initECDHE(true);

            const encrypted = await aesEncrypt(card);

            const tempToken = window.sessionStorage.getItem('ecdhe_temp_token');
            if (!tempToken) {
                throw new Error("Không tìm thấy temp_token để mã hóa");
            }

            console.log("Dữ liệu gửi lên:", { username, password, encrypted, tempToken });
            
            const res = await fetch('/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username,
                    password,
                    encrypted_card: encrypted.ciphertext,
                    card_iv: encrypted.iv,
                    card_tag: encrypted.tag,
                    temp_token: tempToken // Gửi temp_token để server xác thực
                })
            });

            const data = await res.json();
            if (res.ok) {
                registerForm.classList.add('d-none');
                loginForm.classList.remove('d-none');
                authModalTitle.textContent = 'Đăng nhập';
                toggleText.innerHTML = 'Chưa có tài khoản? <a href="javascript:void(0)" onclick="toggleAuthForm()">Đăng ký</a>';

                alert('Đăng ký thành công! Đang tự động đăng nhập...');

                // Tự động đăng nhập
                const loginRes = await fetch('/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });

                if (loginRes.ok) {
                    await initECDHE(); // Khởi tạo ECDHE với session sau khi đăng nhập
                    window.sessionStorage.removeItem('ecdhe_temp_token'); // Xóa temp_token
                    window.location.reload();
                } else {
                    alert('Đăng ký thành công, nhưng đăng nhập thất bại!');
                }
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

document.addEventListener('DOMContentLoaded', async function () {
    // Nếu đã đăng nhập rồi (ví dụ có nút logout hiển thị) thì khởi tạo ECDHE luôn
    if (document.getElementById('logout')) {
        try {
            await initECDHE();
            console.log("✅ Đã khởi tạo lại ECDHE sau khi reload trang");
        } catch (e) {
            console.error("❌ Lỗi khởi tạo lại ECDHE:", e.message);
        }
    }
});
