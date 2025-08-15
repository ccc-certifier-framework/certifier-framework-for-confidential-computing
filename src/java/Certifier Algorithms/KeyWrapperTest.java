public class KeyWrapperTest {
    static {
        System.loadLibrary("key_wrapper");
    }

    public static void main(String[] args) {
        KeyWrapper key = new KeyWrapper();

        // 1. Generate a new key
        if (!key.generate(2048)) {
            System.err.println("Key generation failed");
            return;
        }
        System.out.println("✅ RSA key generated.");

        // 2. Sign a message
        String message = "Hello from Android!";
        String signature = key.sign(message);
        if (signature == null || signature.isEmpty()) {
            System.err.println("Signing failed");
            return;
        }
        System.out.println("✍️ Message signed.");

        // 3. Verify the signature
        boolean verified = key.verify(message, signature);
        System.out.println("✅ Signature verified: " + verified);

        // 4. Export + Import key to simulate transfer/storage
        String serializedKey = key.export_key();
        KeyWrapper key2 = new KeyWrapper();
        boolean restored = key2.import_key(serializedKey);
        if (!restored) {
            System.err.println("Failed to restore key");
            return;
        }

        // Verify again using the restored key
        boolean reverified = key2.verify(message, signature);
        System.out.println("🔁 Signature verified using restored key: " + reverified);
    }
}
