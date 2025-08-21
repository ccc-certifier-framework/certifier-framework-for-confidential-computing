package org.certifier;

import java.nio.charset.StandardCharsets;

public class SecureAuthenticatedChannel {
    static {
        System.loadLibrary("certifier_jni");
    }

    public SecureAuthenticatedChannel() {}

    public native void close();
    public native int read(byte[] buffer); // returns bytes read
    public native int write(byte[] data);  // returns bytes written
    public native boolean init_client_ssl(String serverAddr, int port);

    private static native int cf_channel_peer_id(long nativePtr, byte[] out, int outLen);
    private static native int cf_channel_peer_cert(long nativePtr, byte[] out, int outLen);

    private transient long swigCPtr;

    public String getPeerId() {
        byte[] buf = new byte[256];
        int n = cf_channel_peer_id(this.swigCPtr, buf, buf.length);
        if (n <= 0) return "";
        return new String(buf, 0, n, StandardCharsets.UTF_8);
    }

    public byte[] getPeerCert() {
        byte[] buf = new byte[4096];
        int n = cf_channel_peer_cert(this.swigCPtr, buf, buf.length);
        if (n <= 0) return new byte[0];
        byte[] out = new byte[n];
        System.arraycopy(buf, 0, out, 0, n);
        return out;
    }
}
