# Running the simple Java application


# Certifier Framework — Java “Simple Example” (SWIG/JNI) Setup

This guide gives you **copy‑pasteable** steps to build and run a Java port of the Certifier Framework’s `simple_app`, **without hardcoding any paths**. We’ll auto‑detect include and library directories and feed them to SWIG/CMake/Gradle via environment variables.

---

## What you’ll get

- A shell script that **auto‑detects paths** to headers, JNI includes, and libraries.
- SWIG commands that **don’t use absolute paths**.
- A CMake config that **reads env vars** instead of hardcoding.
- Gradle run configuration to load your JNI `.so`.
- A client/server Java **SimpleApp** structure mirroring the C++ “simple example”.

> You’ll still need your Certifier Framework repo built so headers/libs exist.

---

## A) One‑time auto‑detect script

Create `detect_paths.sh` in your project **root** (the folder that has `native/` and `app/`):

```bash
#!/usr/bin/env bash
set -euo pipefail

# 1) Point this at your certifier repo root (edit ONLY if needed)
# If you're currently inside the repo, this auto-detects it:
if git rev-parse --show-toplevel >/dev/null 2>&1; then
  CERTIFIER_ROOT="$(git rev-parse --show-toplevel)"
else
  # Fallback: set this manually if the line above doesn't work
  CERTIFIER_ROOT="$HOME/certifier-framework-for-confidential-computing"
fi

# 2) Find key headers
TM_H="$(find "$CERTIFIER_ROOT" -type f -name 'trust_manager.h' | head -n1)"
CH_H="$(find "$CERTIFIER_ROOT" -type f -name 'secure_authenticated_channel*.h' | head -n1)"
STORE_H="$(find "$CERTIFIER_ROOT" -type f -name 'store.h' | head -n1 || true)"

if [[ -z "${TM_H:-}" || -z "${CH_H:-}" ]]; then
  echo "Could not find trust_manager.h or secure_authenticated_channel*.h under $CERTIFIER_ROOT"
  exit 1
fi

# 3) Compute their include roots (parent of the folder that contains the header)
inc_root_of () { python3 - <<'PY'
import os,sys
h=sys.argv[1]
d=os.path.dirname(h)              # .../trust_manager
print(os.path.dirname(d))         # .../include (parent)
PY
}

CERTIFIER_INC1="$(inc_root_of "$TM_H")"
CERTIFIER_INC2="$(inc_root_of "$CH_H")"

# Optional store
if [[ -n "${STORE_H:-}" ]]; then
  CERTIFIER_INC3="$(inc_root_of "$STORE_H")"
else
  CERTIFIER_INC3=""
fi

# 4) JNI includes (auto-detect JAVA_HOME if not set)
if [[ -z "${JAVA_HOME:-}" ]]; then
  for J in /usr/lib/jvm/java-21* /usr/lib/jvm/java-17* /usr/lib/jvm/*; do
    [[ -d "$J/include" ]] && export JAVA_HOME="$J" && break
  done
fi
JNI_INC1="$JAVA_HOME/include"
if [[ -d "$JAVA_HOME/include/linux" ]]; then
  JNI_INC2="$JAVA_HOME/include/linux"
else
  JNI_INC2="$JAVA_HOME/include/linux-x86_64"
fi

# 5) Guess a lib directory inside certifier build (adjust later if needed)
CERTIFIER_LIBDIR="$(find "$CERTIFIER_ROOT" -type d -name lib | head -n1 || true)"

# 6) Save to a file we can source
cat > paths.env <<EOF
export CERTIFIER_ROOT="$CERTIFIER_ROOT"
export CERTIFIER_INC1="$CERTIFIER_INC1"
export CERTIFIER_INC2="$CERTIFIER_INC2"
export CERTIFIER_INC3="$CERTIFIER_INC3"
export JNI_INC1="$JNI_INC1"
export JNI_INC2="$JNI_INC2"
export CERTIFIER_LIBDIR="$CERTIFIER_LIBDIR"
EOF

echo "Wrote paths.env with:"
cat paths.env
```

Run it:
```bash
chmod +x detect_paths.sh
./detect_paths.sh
source paths.env
```

Now you have env vars:
- `CERTIFIER_INC1/2/3` → include roots (where `trust_manager/...h`, `secure_authenticated_channel/...h`, `store.h` live)
- `JNI_INC1/2` → JNI include dirs
- `CERTIFIER_LIBDIR` → a first guess at your **lib** folder

---

## B) SWIG commands (no hardcoded paths)

From your `native/` folder:

```bash
# Ensure env vars are loaded:
source ../paths.env

# Generate wrappers into your Java package
swig -c++ -java \
  -package org.certifier \
  -outdir ../app/src/main/java/org/certifier \
  -I"$CERTIFIER_INC1" -I"$CERTIFIER_INC2" ${CERTIFIER_INC3:+-I"$CERTIFIER_INC3"} \
  trust_manager.i

swig -c++ -java \
  -package org.certifier \
  -outdir ../app/src/main/java/org/certifier \
  -I"$CERTIFIER_INC1" -I"$CERTIFIER_INC2" ${CERTIFIER_INC3:+-I"$CERTIFIER_INC3"} \
  secure_authenticated_channel.i

# Optional (do last)
if [[ -f store.i ]]; then
  swig -c++ -java \
    -package org.certifier \
    -outdir ../app/src/main/java/org/certifier \
    -I"$CERTIFIER_INC1" -I"$CERTIFIER_INC2" ${CERTIFIER_INC3:+-I"$CERTIFIER_INC3"} \
    store.i
fi
```

Because you pass `-I"$CERTIFIER_INC*"` to SWIG, your `.i` files can keep the simple includes like:
```swig
%{ #include "trust_manager/trust_manager.h" %}
%include "trust_manager/trust_manager.h"
```
No absolute paths required.

---

## C) CMake without hardcoded paths

Use this `native/CMakeLists.txt`. It **reads env vars** created by `detect_paths.sh`:

```cmake
cmake_minimum_required(VERSION 3.16)
project(certifier_jni)

# Read env vars created by detect_paths.sh
set(CERTIFIER_INC1 $ENV{CERTIFIER_INC1})
set(CERTIFIER_INC2 $ENV{CERTIFIER_INC2})
set(CERTIFIER_INC3 $ENV{CERTIFIER_INC3})
set(JNI_INC1 $ENV{JNI_INC1})
set(JNI_INC2 $ENV{JNI_INC2})
set(CERTIFIER_LIBDIR $ENV{CERTIFIER_LIBDIR})

message(STATUS "CERTIFIER_INC1=${CERTIFIER_INC1}")
message(STATUS "CERTIFIER_INC2=${CERTIFIER_INC2}")
message(STATUS "CERTIFIER_INC3=${CERTIFIER_INC3}")
message(STATUS "JNI_INC1=${JNI_INC1}")
message(STATUS "JNI_INC2=${JNI_INC2}")
message(STATUS "CERTIFIER_LIBDIR=${CERTIFIER_LIBDIR}")

# Include dirs
include_directories(${JNI_INC1} ${JNI_INC2})
include_directories(${CERTIFIER_INC1} ${CERTIFIER_INC2})
if (EXISTS "${CERTIFIER_INC3}")
  include_directories(${CERTIFIER_INC3})
endif()

# Sources (SWIG generated files should already exist)
add_library(certifier_jni SHARED
  cf_shims.cc
  trust_manager_wrap.cxx
  secure_authenticated_channel_wrap.cxx
  # store_wrap.cxx   # enable if you generated it
)

# Where to search for libs
if (EXISTS "${CERTIFIER_LIBDIR}")
  link_directories(${CERTIFIER_LIBDIR})
endif()

# TODO: Replace with actual certifier libs from your build.
# Tip: run:  ls -1 ${CERTIFIER_LIBDIR}/lib*
target_link_libraries(certifier_jni PRIVATE
  # certifier_core
  # trust_manager
  # secure_authenticated_channel
  # store
  ssl crypto
  # protobuf pthread
)

set_target_properties(certifier_jni PROPERTIES OUTPUT_NAME "certifier_jni")
```

Build JNI lib:
```bash
cd native
cmake -B build -S .
cmake --build build -j
```

If you get linker errors (**undefined reference**):
1. List available libs:
   ```bash
   ls -1 "$CERTIFIER_LIBDIR"/lib*
   ```
2. Add missing ones to `target_link_libraries` (drop the `lib` prefix and `.a/.so` suffix), e.g. `protobuf`, `pthread`, `trust_manager`, `secure_authenticated_channel`, etc.  
3. Rebuild.

---

## D) Gradle: point JVM to your JNI `.so`

In `app/build.gradle`, add:

```gradle
tasks.run {
    jvmArgs "-Djava.library.path=${projectDir}/../native/build"
}
```

If your `.so` ends up in a different folder (e.g., `native/build/Debug`), update the path accordingly.

---

## E) Quick sanity checklist (fastest green path)

1. From your **certifier repo**, run its usual build to produce headers & libs.
2. In your **Java project root**:
   ```bash
   ./detect_paths.sh
   source paths.env
   ```
3. Generate SWIG wrappers:
   ```bash
   cd native
   source ../paths.env
   # (run SWIG commands from section B)
   ```
4. Build JNI:
   ```bash
   cmake -B build -S .
   cmake --build build -j
   ```
5. Run Java (server then client in two terminals):
   ```bash
   cd ../app
   gradle run --args="--mode=server --port=8080"
   gradle run --args="--mode=client --host=127.0.0.1 --port=8080"
   ```

---

## F) Discover the **real** library names (no guessing)

```bash
source paths.env
find "$CERTIFIER_ROOT" -maxdepth 4 -type f -name 'lib*.a' -o -name 'lib*.so'
```

Whatever you see (e.g., `libtrust_manager.a`, `libsecure_authenticated_channel.a`, `libcertifier_core.a`) → add as:
```cmake
target_link_libraries(certifier_jni PRIVATE trust_manager secure_authenticated_channel certifier_core ssl crypto protobuf pthread)
```

---

## G) If headers still aren’t found (brute force check)

```bash
# Where are the headers?
find "$CERTIFIER_ROOT" -type f -name 'trust_manager.h' \
  -o -name 'secure_authenticated_channel*.h' \
  -o -name 'store.h'

# What folder do they live in?
dirname "$(find "$CERTIFIER_ROOT" -type f -name 'trust_manager.h' | head -n1)"
# The parent of that dirname is the include root you pass with -I to SWIG and CMake.
```

Then re-run:
```bash
./detect_paths.sh && source paths.env
```

---

## Notes on the Java side

- Be sure `System.loadLibrary("certifier_jni")` is called (e.g., in your `TrustManager`/`SecureAuthenticatedChannel` classes).
- If you SWIG additional functions later (e.g., `server_dispatch`, `client_application`), you can remove any placeholder Java `ServerSocket` logic and drive the real secure channel like the C++ sample.
- The mentor‑required flags/fields (`auth key initialized`, `primary admissions cert valid`, `peer id`, `peer cert`) should be exposed via tiny C++ shim helpers that call **public** getters or safe exports, then bound through SWIG.

---

### Troubleshooting Quick Hits

- **`java.lang.UnsatisfiedLinkError: no certifier_jni in java.library.path`**  
  Ensure the `.so` lives in the folder set by `-Djava.library.path` (see section D).

- **Undefined references to OpenSSL/Protobuf**  
  Add `ssl`, `crypto`, `protobuf`, and `pthread` to `target_link_libraries` (Linux).

- **Header not found during SWIG**  
  Re-run `./detect_paths.sh`, make sure `CERTIFIER_INC*` are set, and pass `-I` flags as shown.

- **Symbols from Certifier libs unresolved**  
  Check `ls "$CERTIFIER_LIBDIR"/lib*`, add the matching targets (without `lib` prefix) to CMake.
```
