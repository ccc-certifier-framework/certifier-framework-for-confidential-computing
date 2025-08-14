# How to Run

```
swig -c++ -java claim_verifier.i
```

# Compile `.so` (Shared Library for Java)

```
g++ -fPIC -c claim_verifier.cc claim_verifier_wrap.cxx -Iinclude \
  -I/usr/lib/jvm/java-17-amazon-corretto/include \
  -I/usr/lib/jvm/java-17-amazon-corretto/include/linux
```
```
g++ -shared claim_verifier.o claim_verifier_wrap.o -o libclaim_verifier.so
```

# Run the Java Test

Replace the placeholders with actual serialized data (either: raw binary loaded as byte string, or Base64-decoded if coming from Java)

## Compile:

```
javac ClaimVerifier.java ClaimVerifierJNI.java ClaimVerifierTest.java
```

## Run:

```
java ClaimVerifierTest
```

> Make sure libclaim_verifier.so is in your LD_LIBRARY_PATH or same directory.
