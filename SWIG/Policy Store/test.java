package certifier.framework;

public class PolicyStoreTest {
    static {
        System.loadLibrary("policy_store");
    }

    public static void main(String[] args) {
        policy_store store = new policy_store(10);
        store.add_entry("example", "string", "hello");
        int idx = store.find_entry("example", "string");

        if (idx >= 0) {
            System.out.println("Found entry at: " + idx);
        } else {
            System.out.println("Entry not found.");
        }
    }
}
