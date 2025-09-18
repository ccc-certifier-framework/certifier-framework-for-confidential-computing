package org.certifier.examples;

import org.certifier.TrustManager;
import org.certifier.SecureAuthenticatedChannel;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Desktop usage:
 *   java org.certifier.examples.SimpleApp --mode=server --port=8080
 *   java org.certifier.examples.SimpleApp --mode=client --host=127.0.0.1 --port=8080
 *
 * Android usage (no command line):
 *   // In your Activity:
 *   String workDir = getFilesDir().getAbsolutePath();
 *   String result  = org.certifier.examples.SimpleApp.runCertifier(workDir);
 *   // Or choose explicit mode/host/port:
 *   // String result = org.certifier.examples.SimpleApp.runCertifier(workDir, "client", "127.0.0.1", 8080);
 */
public class SimpleApp {

    static { System.loadLibrary("certifier_native"); }
    public static native String runCertifierNative(String workDir, String mode, String host, int port);
    public static String runCertifier(String workDir) {
        return runCertifierNative(workDir, "client", "127.0.0.1", 8080);
    }
    public static String runCertifier(String workDir, String mode, String host, int port) {
        return runCertifierNative(workDir, mode, host, port);
    }

    // Loads your NDK shared library (built via CMake).
    // Ensure add_library(...) name in CMakeLists.txt matches "certifier_native".
    static { System.loadLibrary("certifier_native"); }

    /**
     * JNI entry (implementation in C++): run the Certifier workflow.
     * You can route to native-only logic, or have native call back into Java as needed.
     */
    public static native String runCertifierNative(String workDir, String mode, String host, int port);

    /**
     * Android-friendly convenience: default to client:127.0.0.1:8080.
     * Calls the JNI implementation above.
     */
    public static String runCertifier(String workDir) {
        return runCertifierNative(workDir, "client", "127.0.0.1", 8080);
    }

    /**
     * Android-friendly convenience with explicit options.
     */
    public static String runCertifier(String workDir, String mode, String host, int port) {
        return runCertifierNative(workDir, mode, host, port);
    }

    // ----------------------------- Desktop entrypoint -----------------------------

    public static void main(String[] args) throws Exception {
        String mode = "client";
        String host = "127.0.0.1";
        int port = 8080;

        for (int i = 0; i < args.length; i++) {
            if (args[i].startsWith("--mode=")) mode = args[i].substring(7);
            else if (args[i].startsWith("--host=")) host = args[i].substring(7);
            else if (args[i].startsWith("--port=")) port = Integer.parseInt(args[i].substring(7));
        }

        if (mode.equals("server")) {
            runServer(port);
        } else {
            runClient(host, port);
        }
    }

    // ----------------------------- Original logic -----------------------------

    private static void runServer(int port) throws Exception {
        TrustManager tm = new TrustManager();
        if (!tm.init_policy_key() || !tm.initialize_enclave()) {
            System.err.println("TrustManager init failed");
            return;
        }
        // First-time cold init, then warm restarts subsequently as needed
        if (!tm.cold_init()) {
            System.err.println("cold_init() failed");
            return;
        }
        tm.print_trust_data();
        System.out.println("AuthKeyInitialized=" + tm.isAuthKeyInitialized() +
                ", PrimaryAdmissionsCertValid=" + tm.isPrimaryAdmissionsCertValid());

        // Demo plaintext accept loop; replace with secure server path later.
        try (ServerSocket ss = new ServerSocket(port)) {
            System.out.println("[Server] Listening on " + port);
            try (Socket s = ss.accept()) {
                System.out.println("[Server] Connection from " + s.getRemoteSocketAddress());
                BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
                String line = br.readLine();
                System.out.println("[Server] Received: " + line);
                s.getOutputStream().write(("ACK:" + line + "\n").getBytes(StandardCharsets.UTF_8));
            }
        }

        tm.clear_sensitive_data();
    }

    private static void runClient(String host, int port) throws Exception {
        TrustManager tm = new TrustManager();
        if (!tm.init_policy_key() || !tm.initialize_enclave()) {
            System.err.println("TrustManager init failed");
            return;
        }
        if (!tm.warm_restart()) {
            System.err.println("warm_restart() failed (try cold_init() once on first run)");
            return;
        }
        tm.print_trust_data();

        SecureAuthenticatedChannel ch = new SecureAuthenticatedChannel();
        if (!ch.init_client_ssl(host, port)) {
            System.err.println("init_client_ssl failed");
            return;
        }

        System.out.println("[Client] PeerId=" + ch.getPeerId());
        byte[] cert = ch.getPeerCert();
        System.out.println("[Client] PeerCertLen=" + cert.length);

        byte[] msg = "Hello Secure World!\n".getBytes(StandardCharsets.UTF_8);
        ch.write(msg);

        byte[] buf = new byte[1024];
        int n = ch.read(buf);
        System.out.println("[Client] Read: " + new String(buf, 0, n, StandardCharsets.UTF_8));
        ch.close();

        tm.clear_sensitive_data();
    }
}
