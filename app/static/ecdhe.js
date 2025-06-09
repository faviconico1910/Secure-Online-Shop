let sessionAesKey = null;

async function initECDHE(isRegistration = false) {
    try {
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "ECDH",
                namedCurve: "P-256",
            },
            true,
            ["deriveBits"]
        );

        const publicKeyBuffer = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
        const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(publicKeyBuffer)));
        const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${publicKeyBase64.match(/.{1,64}/g).join("\n")}\n-----END PUBLIC KEY-----`;

        const response = await fetch("/init_ecdh", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ client_pub: publicKeyPem, is_registration: isRegistration })
        });

        const data = await response.json();
        console.log('↩️ Phản hồi /init_ecdh:', data);

        if (!response.ok) {
            console.error("❌ Lỗi từ server:", data.error || "Không rõ nguyên nhân");
            throw new Error(data.error || "Lỗi khởi tạo ECDHE: Server trả về lỗi");
        }

        if (!data.server_pub) {
            console.error("❌ Không nhận được server_pub:", data);
            throw new Error("Lỗi khởi tạo ECDHE: Server không trả về khóa công khai");
        }

        const serverPubPem = data.server_pub.replace(/-----.*?-----|\n/g, '');
        const serverPubBytes = Uint8Array.from(atob(serverPubPem), c => c.charCodeAt(0));

        const serverKey = await window.crypto.subtle.importKey(
            "spki",
            serverPubBytes,
            { name: "ECDH", namedCurve: "P-256" },
            false,
            []
        );
        
        // 1. deriveBits
        const sharedBits = await window.crypto.subtle.deriveBits(
            {
                name: "ECDH",
                public: serverKey
            },
            keyPair.privateKey,
            256  // phải >= độ dài HKDF input (SHA-256)
        );

        // 2. Áp dụng HKDF giống server
        const keyMaterial = await window.crypto.subtle.importKey(
            "raw",
            sharedBits,
            { name: "HKDF" },
            false,
            ["deriveKey"]
        );

        sessionAesKey = await window.crypto.subtle.deriveKey(
            {
                name: "HKDF",
                hash: "SHA-256",
                salt: new Uint8Array([]), // salt=None bên Python
                info: new TextEncoder().encode("handshake data")
            },
            keyMaterial,
            { name: "AES-GCM", length: 128 },
            true,
            ["encrypt", "decrypt"]
        );

        // Xuất key raw ra log
        const rawKey = await window.crypto.subtle.exportKey('raw', sessionAesKey);
        const rawKeyHex = Array.from(new Uint8Array(rawKey))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');

        console.log("✅ Client sessionAesKey (raw hex):", rawKeyHex);

        // Lưu temp_token nếu là đăng ký
        if (isRegistration && data.temp_token) {
            window.sessionStorage.setItem('ecdhe_temp_token', data.temp_token);
            console.log("✅ Lưu temp_token:", data.temp_token);
        }

        console.log("✅ Khởi tạo ECDHE thành công");
        // Xuất khóa AES thành hex để kiểm tra

    } catch (error) {
        console.error("❌ Lỗi khởi tạo ECDHE:", error.message);
        throw error;
    }
}

async function aesEncrypt(text) {
    if (!sessionAesKey) {
        throw new Error("ECDHE key chưa được khởi tạo. Hãy gọi initECDHE() trước.");
    }

    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // Đảm bảo 12 byte
    const encoded = new TextEncoder().encode(text);
    const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        sessionAesKey,
        encoded
    );

    const encryptedArray = new Uint8Array(encrypted);
    const ciphertextLength = encryptedArray.length - 16; // Tag luôn là 16 byte
    const ciphertext = encryptedArray.slice(0, ciphertextLength);
    const tag = encryptedArray.slice(ciphertextLength); // Lấy 16 byte tag

    const result = {
        ciphertext: btoa(String.fromCharCode(...ciphertext)),
        iv: btoa(String.fromCharCode(...iv)),
        tag: btoa(String.fromCharCode(...tag))
    };
    console.log("Dữ liệu mã hóa:", {
        ciphertextLength: ciphertext.length,
        ivLength: iv.length,
        tagLength: tag.length,
        result
    });
    return result;
}

