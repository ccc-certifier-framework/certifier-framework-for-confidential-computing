package org.certifier;

public class TrustManager {
    static {
        System.loadLibrary("certifier_jni"); // built from CMake
    }

    // Native C++ bound via SWIG
    public TrustManager() { }

    public native boolean init_policy_key();
    public native boolean initialize_enclave();
    public native boolean cold_init();
    public native boolean warm_restart();
    public native void print_trust_data();
    public native void clear_sensitive_data();

    // Shimmed flags (1 = true, 0 = false)
    private static native int cf_tm_auth_key_initialized(long nativePtr);
    private static native int cf_tm_primary_admissions_cert_valid(long nativePtr);

    // SWIG exposes the native pointer in a hidden field for directors; name may vary by SWIG version.
    // Typically it’s something like swigCPtr. Adjust if needed.
    private transient long swigCPtr;

    // Accessors matching mentor’s ask:
    public boolean isAuthKeyInitialized() {
        return cf_tm_auth_key_initialized(this.swigCPtr) == 1;
    }

    public boolean isPrimaryAdmissionsCertValid() {
        return cf_tm_primary_admissions_cert_valid(this.swigCPtr) == 1;
    }
}
