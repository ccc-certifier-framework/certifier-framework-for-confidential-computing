# How to Run

```
swig -c++ -java policy_store.i
```

# Compile `.so` (Shared Library for Java)

> Assuming JNI headers are at `/usr/lib/jvm/java-17-amazon-corretto/include`

```
g++ -fPIC -c policy_store_wrap.cxx -Iinclude \
  -I/usr/lib/jvm/java-17-amazon-corretto/include \
  -I/usr/lib/jvm/java-17-amazon-corretto/include/linux
```
```
g++ -shared policy_store_wrap.o -o libpolicy_store.so
```

> Place 'libpolicy_store.so' somewhere in your 'LD_LIBRARY_PATH'

# Run the Java Test

Compile:
```
javac certifier/framework/*.java PolicyStoreTest.java
java certifier.framework.PolicyStoreTest
```
