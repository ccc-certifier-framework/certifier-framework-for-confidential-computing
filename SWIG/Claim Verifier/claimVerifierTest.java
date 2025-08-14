public class ClaimVerifierTest {
    static {
        System.loadLibrary("claim_verifier");
    }

    public static void main(String[] args) {
        // These should be real serialized protobufs
        String serializedClaim = getSerializedSignedClaim();  // stub
        String serializedKey = getSerializedKey();             // stub

        ClaimVerifier verifier = new ClaimVerifier();
        boolean result = verifier.verify(serializedClaim, serializedKey);

        if (result) {
            System.out.println("✅ Claim successfully verified.");
        } else {
            System.out.println("❌ Claim verification failed.");
        }
    }

    // These are just placeholders.
    // Replace with actual Base64-encoded or raw serialized protobufs.
    private static String getSerializedSignedClaim() {
        return "...";  // TODO: inject real base64/byte string here
    }

    private static String getSerializedKey() {
        return "...";  // TODO: inject public key here
    }
}
