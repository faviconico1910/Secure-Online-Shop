let publicKey, privateKey;
window.readyToSign = false;  // trạng thái cho biết đã sẵn sàng ký hay chưa

Module.onRuntimeInitialized = () => {
  try {
    const pkPtr = Module._malloc(1312);   // Dilithium2 public key
    const skPtr = Module._malloc(2528);   // Dilithium2 secret key

    Module._keypair(pkPtr, skPtr);

    publicKey = new Uint8Array(Module.HEAPU8.buffer, pkPtr, 1312);
    privateKey = new Uint8Array(Module.HEAPU8.buffer, skPtr, 2528);

    window.readyToSign = true;  // đánh dấu đã sẵn sàng
    console.log("✅ MLDSA keypair generated & readyToSign = true");
  } catch (err) {
    console.error("❌ Failed to generate keypair:", err);
  }
};

async function signMessage(messageStr) {
  if (!window.readyToSign || !privateKey) {
    throw new Error("Private key chưa sẵn sàng");
  }
  console.log("📩 Signing message:", messageStr);
  const msgPtr = Module._malloc(messageStr.length);
  const msgBuf = new Uint8Array(Module.HEAPU8.buffer, msgPtr, messageStr.length);
  for (let i = 0; i < messageStr.length; i++) msgBuf[i] = messageStr.charCodeAt(i);

  const sigPtr = Module._malloc(2420);  // chữ ký Dilithium2
  const sigLenPtr = Module._malloc(4);  // output length

  Module._sign(sigPtr, sigLenPtr, msgPtr, messageStr.length, privateKey.byteOffset);
  const signature = new Uint8Array(Module.HEAPU8.buffer, sigPtr, 2420);

  Module._free(msgPtr);
  Module._free(sigLenPtr);

  return signature;
}
