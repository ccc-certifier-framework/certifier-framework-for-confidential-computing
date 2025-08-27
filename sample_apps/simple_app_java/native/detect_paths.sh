#!/usr/bin/env bash
set -euo pipefail
# native/detect_paths.sh — auto-detect include/lib/JNI paths; writes paths.env

# 1) Repo root
if git rev-parse --show-toplevel >/dev/null 2>&1; then
  CERTIFIER_ROOT="$(git rev-parse --show-toplevel)"
else
  CERTIFIER_ROOT="$PWD"
fi

# 2) Key headers
TM_H="$(find "$CERTIFIER_ROOT" -type f -name 'trust_manager.h' | head -n1 || true)"
CH_H="$(find "$CERTIFIER_ROOT" -type f -name 'secure_authenticated_channel*.h' | head -n1 || true)"
STORE_H="$(find "$CERTIFIER_ROOT" -type f -name 'store.h' | head -n1 || true)"

if [[ -z "${TM_H:-}" || -z "${CH_H:-}" ]]; then
  echo "ERROR: Could not find trust_manager.h or secure_authenticated_channel*.h under $CERTIFIER_ROOT"
  exit 1
fi

# 3) Compute include roots (parent of the folder containing the header)
inc_root_of () { python3 - <<'PY'
import os, sys
h = sys.argv[1]
d = os.path.dirname(h)       # .../trust_manager
print(os.path.dirname(d))    # parent (often .../include)
PY
}
CERTIFIER_INC1="$(inc_root_of "$TM_H")"
CERTIFIER_INC2="$(inc_root_of "$CH_H")"
CERTIFIER_INC3=""
[[ -n "${STORE_H:-}" ]] && CERTIFIER_INC3="$(inc_root_of "$STORE_H")"

# 4) JDK / JNI
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

# 5) Guess lib dir
CERTIFIER_LIBDIR="$(find "$CERTIFIER_ROOT" -type d -name lib | head -n1 || true)"

# 6) Write env file
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
