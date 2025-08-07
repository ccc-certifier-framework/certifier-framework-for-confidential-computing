# Note:

> `key_message` (in `certifier_algorithms.h`) is a protobuf class. To wrap it in SWIG, I have created a SWIG-friendly wrapper class.
> The wrapper class internally uses `key_message` and exposes clean `std::string' methods for"
> - loading a key
> - exporting a key
> - signing/verification

# How to Run

```
swig -c++ -java key_wrapper.i
```

# Compile

```
g++ -fPIC -c key_wrapper.cc key_wrapper_wrap.cxx -Iinclude -I/usr/lib/jvm/java-17-amazon-corretto/include -I/usr/lib/jvm/java-17-amazon-corretto/include/linux
```
```
g++ -shared key_wrapper.o key_wrapper_wrap.o -o libkey_wrapper.so
```

# Java Testing

The Java test class uses the wrapped KeyWrapper class to:
1. Generate an RSA key
2. Sign a message
3. Verify the signature
4. Export and import the key (round trip)
