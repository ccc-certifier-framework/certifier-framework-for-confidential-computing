# Generate SWIG Output

```
swig -c++ -java simulated_enclave.i
```
This creates:

- simulated_enclave_wrap.cxx
- simulated_enclave.java
- simulated_enclaveJNI.java

# Compile `.so` (Shared Library for Java)

> Assuming headers are in `include/` and JNI path is:

```
g++ -fPIC -c simulated_enclave_wrap.cxx -Iinclude \
  -I/usr/lib/jvm/java-17-amazon-corretto/include \
  -I/usr/lib/jvm/java-17-amazon-corretto/include/linux
```
```
g++ -shared simulated_enclave_wrap.o -o libsimulated_enclave.so
```

# Run the Java Test

Compile:
```
javac simulated_enclave*.java SimulatedTest.java
java SimulatedTest
```
