
# Java Simple Example (SWIG/JNI) — Build & Run Guide

This is a **copy‑pasteable** guide to build and run the Java port of the Certifier Framework’s `simple_app`, using **SWIG + JNI**. It avoids hardcoded paths by auto‑detecting include/library directories and passing them to SWIG & CMake. It also includes the exact **run commands** for the Java server and client.

> Works on Linux/macOS or Windows via **WSL**. For pure Windows (MSVC), see the notes under **Troubleshooting** about `native/build/Debug` and `.dll` paths.

---

## Overview — What you’ll do

1. Build the Certifier C++ repo (so headers/libs exist).  
2. Auto‑detect JNI + Certifier include/lib paths (`native/detect_paths.sh`).  
3. Generate SWIG wrappers for `TrustManager` and `SecureAuthenticatedChannel`.  
4. Build the JNI shared library with CMake (`libcertifier_jni.so`/`.dylib`/`.dll`).  
5. Run the **Java server** and **Java client** with Gradle.

> If you’re starting from scratch, also drop in the `CMakeLists.txt`, `cf_shims.h/.cc`, and the SWIG `.i` files provided in the repo or in the “Appendix” below.

---

## Prerequisites

### Ubuntu / WSL
```bash
sudo apt update
sudo apt install -y build-essential cmake swig openjdk-17-jdk libssl-dev protobuf-compiler
```

### macOS (Homebrew)
```bash
brew install cmake swig openjdk@17 openssl protobuf
```

Ensure `JAVA_HOME` points to your JDK 17 (the detection script tries to auto‑find it if unset).

---

## Project layout (assumed)
```
<repo_root>/
  native/                      # SWIG .i files, shims, CMakeLists.txt, detect_paths.sh
  app/                         # Java sources & Gradle build files
```

---

## 1) Build the Certifier C++ project (once)
Follow the upstream instructions to build the C++ libraries and headers. The JNI build below links against those libs (we’ll discover them automatically).

---

## 2) Auto‑detect paths

From the **repo root** (the directory that contains `native/` and `app/`):

```bash
chmod +x native/detect_paths.sh
./native/detect_paths.sh
source paths.env
```

This writes `paths.env` with:
- `CERTIFIER_INC1/2/3` — include roots for Certifier headers
- `JNI_INC1/2` — JNI header folders (from `JAVA_HOME`)
- `CERTIFIER_LIBDIR` — a candidate folder containing `lib*.a`/`lib*.so`

If you move repos or switch JDKs later, re‑run the script.

---

## 3) Generate SWIG wrappers

```bash
cd native
source ../paths.env

# TrustManager
swig -c++ -java -package org.certifier \
  -outdir ../app/src/main/java/org/certifier \
  -I"$CERTIFIER_INC1" -I"$CERTIFIER_INC2" ${CERTIFIER_INC3:+-I"$CERTIFIER_INC3"} \
  trust_manager.i

# SecureAuthenticatedChannel
swig -c++ -java -package org.certifier \
  -outdir ../app/src/main/java/org/certifier \
  -I"$CERTIFIER_INC1" -I"$CERTIFIER_INC2" ${CERTIFIER_INC3:+-I"$CERTIFIER_INC3"} \
  secure_authenticated_channel.i
```

> Because we pass `-I` include flags, your `.i` files should use **relative** includes like  
> `#include "trust_manager/trust_manager.h"` rather than absolute paths.

---

## 4) Build the JNI shared library

```bash
# still under <repo_root>/native
cmake -B build -S .
cmake --build build -j
```
You should see a library named roughly **`libcertifier_jni.so`** (Linux/WSL), **`libcertifier_jni.dylib`** (macOS), or **`certifier_jni.dll`** (Windows).

> If linking fails with “undefined reference…”, scroll down to **Troubleshooting → Linker errors** and update the list of libraries in `native/CMakeLists.txt` to match what your build produced.

---

## 5) Configure Gradle to find the JNI library

Open `app/build.gradle` and ensure it contains:

```gradle
plugins {
    id 'application'
}

repositories { mavenCentral() }
dependencies { }

application {
    // Entry point (adjust if your package/class name differs)
    mainClass = 'org.certifier.examples.SimpleApp'
}

tasks.run {
    // Make sure this folder actually contains certifier_jni.{so|dylib|dll}
    jvmArgs "-Djava.library.path=${projectDir}/../native/build"
}
```

**Windows/MSVC note:** if CMake places binaries under `native/build/Debug` (or `Release`), change the path to that folder.

---

## 6) Run the Java app

Open **two terminals**.

### Terminal A — Server
```bash
cd app
gradle run --args="--mode=server --port=8080"
```

### Terminal B — Client
```bash
cd app
gradle run --args="--mode=client --host=127.0.0.1 --port=8080"
```

**Expected output**
- **Server:** trust init lines, flags (`AuthKeyInitialized`, `PrimaryAdmissionsCertValid`), “Listening on 8080…”, “Received: Hello Secure World!”
- **Client:** `init_client_ssl(...) OK`, `PeerId=...`, `PeerCertLen=NNNN`, “Read: ACK: Hello Secure World!”

Success checklist:
- No `UnsatisfiedLinkError`.
- Client shows a non‑zero `PeerCertLen` (TLS builds).
- Client receives `ACK: Hello Secure World!`.

---

## Troubleshooting

### UnsatisfiedLinkError: `no certifier_jni`  
Java can’t find the JNI library.
- Verify the file exists: `ls native/build/*certifier_jni*` (or `native/build/Debug/*certifier_jni*` on MSVC).
- Update one line in `app/build.gradle`:
  ```gradle
  tasks.run { jvmArgs "-Djava.library.path=${projectDir}/../native/build" }
  ```
  (Change to `../native/build/Debug` if that’s where the binary is.)

### SWIG can’t find headers
- Re‑run the detector and re‑source the env file:  
  ```bash
  ./native/detect_paths.sh && source paths.env
  ```
- Ensure your `swig` command includes `-I"$CERTIFIER_INC1"` `-I"$CERTIFIER_INC2"` (and `INC3` if present).

### Linker errors (undefined references)
- List the actual libs and match names in `native/CMakeLists.txt` (drop `lib` prefix and extension):
  ```bash
  ls -1 "$CERTIFIER_LIBDIR"/lib*
  ```
- Then edit the link line:
  ```cmake
  target_link_libraries(certifier_jni PRIVATE
    trust_manager
    secure_authenticated_channel
    certifier_core
    ssl crypto protobuf pthread   # keep/remove per your platform
  )
  ```
  On macOS, you usually don’t need `pthread` explicitly; on Windows/MSVC, you may need `ws2_32 bcrypt` instead of `ssl/crypto/pthread`.

### Port already in use
- Change the port for the server and match it on the client:
  ```bash
  gradle run --args="--mode=server --port=9090"
  gradle run --args="--mode=client --host=127.0.0.1 --port=9090"
  ```

---

## Appendix A — Minimal `native/CMakeLists.txt` (drop‑in)

```cmake
cmake_minimum_required(VERSION 3.16)
project(certifier_jni LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)

# Env vars (from detect_paths.sh)
set(CERTIFIER_INC1   $ENV{CERTIFIER_INC1})
set(CERTIFIER_INC2   $ENV{CERTIFIER_INC2})
set(CERTIFIER_INC3   $ENV{CERTIFIER_INC3})
set(JNI_INC1         $ENV{JNI_INC1})
set(JNI_INC2         $ENV{JNI_INC2})
set(CERTIFIER_LIBDIR $ENV{CERTIFIER_LIBDIR})

include_directories(${JNI_INC1} ${JNI_INC2})
if (EXISTS "${CERTIFIER_INC1}") include_directories(${CERTIFIER_INC1}) endif()
if (EXISTS "${CERTIFIER_INC2}") include_directories(${CERTIFIER_INC2}) endif()
if (EXISTS "${CERTIFIER_INC3}") include_directories(${CERTIFIER_INC3}) endif()

add_library(certifier_jni SHARED
  cf_shims.cc
  trust_manager_wrap.cxx
  secure_authenticated_channel_wrap.cxx
)

if (EXISTS "${CERTIFIER_LIBDIR}")
  link_directories(${CERTIFIER_LIBDIR})
endif()

# Adjust these names to match your build output (see: ls -1 ${CERTIFIER_LIBDIR}/lib*)
target_link_libraries(certifier_jni PRIVATE
  trust_manager
  secure_authenticated_channel
  certifier_core
)

if(APPLE)
  target_link_libraries(certifier_jni PRIVATE ssl crypto protobuf)
elseif(UNIX)
  target_link_libraries(certifier_jni PRIVATE ssl crypto protobuf pthread dl)
elseif(WIN32)
  target_link_libraries(certifier_jni PRIVATE ws2_32 bcrypt)
endif()

set_target_properties(certifier_jni PROPERTIES OUTPUT_NAME "certifier_jni")
```

---

## Appendix B — `native/detect_paths.sh` (drop‑in)

```bash
#!/usr/bin/env bash
set -euo pipefail

# Repo root
if git rev-parse --show-toplevel >/dev/null 2>&1; then
  CERTIFIER_ROOT="$(git rev-parse --show-toplevel)"
else
  CERTIFIER_ROOT="$PWD"
fi

# Key headers
TM_H="$(find "$CERTIFIER_ROOT" -type f -name 'trust_manager.h' | head -n1 || true)"
CH_H="$(find "$CERTIFIER_ROOT" -type f -name 'secure_authenticated_channel*.h' | head -n1 || true)"
STORE_H="$(find "$CERTIFIER_ROOT" -type f -name 'store.h' | head -n1 || true)"

if [[ -z "${TM_H:-}" || -z "${CH_H:-}" ]]; then
  echo "ERROR: Could not find trust_manager.h or secure_authenticated_channel*.h under $CERTIFIER_ROOT"
  exit 1
fi

# Compute include roots
inc_root_of () { python3 - <<'PY'
import os, sys
h = sys.argv[1]; d = os.path.dirname(h)
print(os.path.dirname(d))
PY
}
CERTIFIER_INC1="$(inc_root_of "$TM_H")"
CERTIFIER_INC2="$(inc_root_of "$CH_H")"
CERTIFIER_INC3=""; [[ -n "${STORE_H:-}" ]] && CERTIFIER_INC3="$(inc_root_of "$STORE_H")"

# JNI
if [[ -z "${JAVA_HOME:-}" ]]; then
  for J in /usr/lib/jvm/java-21* /usr/lib/jvm/java-17* /usr/lib/jvm/*; do
    [[ -d "$J/include" ]] && JAVA_HOME="$J" && break
  done
fi
[[ -z "${JAVA_HOME:-}" ]] && { echo "ERROR: set JAVA_HOME to a JDK (17+)."; exit 1; }
JNI_INC1="$JAVA_HOME/include"
case "$(uname -s)" in
  Linux)  JNI_INC2="$JAVA_HOME/include/linux"  ;;
  Darwin) JNI_INC2="$JAVA_HOME/include/darwin" ;;
  *)      JNI_INC2="$JAVA_HOME/include/linux"  ;;
esac

# Lib dir guess
CERTIFIER_LIBDIR="$(find "$CERTIFIER_ROOT" -type d -name lib | head -n1 || true)"

cat > paths.env <<EOF
export CERTIFIER_ROOT="$CERTIFIER_ROOT"
export CERTIFIER_INC1="$CERTIFIER_INC1"
export CERTIFIER_INC2="$CERTIFIER_INC2"
export CERTIFIER_INC3="$CERTIFIER_INC3"
export JAVA_HOME="$JAVA_HOME"
export JNI_INC1="$JNI_INC1"
export JNI_INC2="$JNI_INC2"
export CERTIFIER_LIBDIR="$CERTIFIER_LIBDIR"
EOF

echo "Wrote paths.env:"
cat paths.env
```

---

## Appendix C — Expected console output (sample)

**Server**
```
[Trust] init_policy_key ... OK
[Trust] initialize_enclave ... OK
[Trust] cold_init ... OK
AuthKeyInitialized=true, PrimaryAdmissionsCertValid=true
[Server] Listening on 8080 ...
[Server] Received: Hello Secure World!
```

**Client**
```
[Trust] init_policy_key ... OK
[Trust] initialize_enclave ... OK
[Trust] warm_restart ... OK
[Client] init_client_ssl(127.0.0.1:8080) ... OK
[Client] PeerId=CN=SimpleServer,O=Certifier,...
[Client] PeerCertLen=1432
[Client] Read: ACK: Hello Secure World!
```
