# Python Bindings to Certifier Framework interfaces

This document describes the build workflow and toolchain used to generate and
use Python bindings to access Certifier Framework interfaces

NOTE: This build-infrastructure to generate Python bindings to access
Certifier classes and interfaces is evolving and under development.

## Build process

We use the [SWIG tool](https://www.swig.org/) to generate Python and C++ wrappers
around public Certifier Framework interfaces. The genereated C++ classes and code
is then used to produce a shared library.

We also use the
[Python support in the protobuf compiler](https://protobuf.dev/getting-started/pythontutorial/)
to generate Python wrappers for message-formats described by the
[certifier.proto](../certifier_service/certprotos/certifier.proto)
protobuf file.

The following picture describes the build workflow.
The build instructions are in the [certifier.mak](../src/certifier.mak) file.

```mermaid
flowchart TB
  subgraph Code Generation: Certifier Framework Public interfaces
  direction TB

    include/certifier_framework.h --> id1([SWIG])
    include/certifier_framework.i --> id1([SWIG])
    id1([SWIG]) -- "-c++" --> id2(certifier_framework_wrap.cc)
    id1([SWIG]) -- "-python" --> id3{{certifier_framework.py}}
  end

  subgraph Build
  direction TB
    id2(certifier_framework_wrap.cc) --> certifier_framework_wrap.o
    certifier_framework_wrap.o -- "(link with other objects)" --> id4{{libcertifier_framework.so}}
  end

  subgraph Test: tests/pytests
  direction TB
    id4{{libcertifier_framework.so}} --> test_libcertifier_framework.py
    id3{{certifier_framework.py}} --> test_certifier_framework.py
  end
```

```mermaid
flowchart TB
  subgraph Code Generation from protobuf
  direction TB

    certifier_service/certprotos/certifier.proto --> id8([protoc])
    id8([protoc]) -- "--cpp_out" --> id5(certifier_pb.h)
    id8([protoc]) -- "--cpp_out" --> id6(certifier_pb.cc)
    id8([protoc]) -- "--python_out" --> certifier_pb2.py
  end

  subgraph Test: tests/pytests
  direction TB
    certifier_pb2.py --> test_certifier_protobuf_interfaces.py
  end
```

These generated Python modules are then used to develop Python-apps to access
the Certifier Service.

