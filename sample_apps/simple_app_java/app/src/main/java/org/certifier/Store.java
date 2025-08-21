package org.certifier;

public class Store {
    static {
        System.loadLibrary("certifier_jni");
    }

    public Store() {}

    public native long get_num_entries();
    public native int  find_entry(String tag, String type);
    public native String tag(long ent);
    public native String type(long ent);
    public native long get_entry(long ent);
    public native boolean delete_entry(long ent);
    public native boolean update_or_insert(String tag, String type, String value);
    public native void print();
}
