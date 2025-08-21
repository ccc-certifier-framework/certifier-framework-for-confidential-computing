#!/usr/bin/env bash
set -euo pipefail

# detect_paths.sh
# Auto-detects include/lib/JNI paths for the Certifier Java simple app.
# Writes exports to paths.env (source it before running SWIG/CMake).

# 1) Figure out CERTIFIER_ROOT (the repo you built)
if git rev-parse --show-toplevel >/dev/null 2>&1; then
  CERTIFIER_ROOT="$(git rev-parse --show-toplevel)"
else
  # Fallback: change this if your repo is elsewhere
  CERTIFIER_ROOT="$HOME/certifier-framework-for-confidential-computing"
fi

# 2) Find key headers inside the repo
TM_H="$(find "$CERTIFIER_ROOT" -type f -name 'trust_manager.h' | head -n1 || true)"
CH_H="$(find "$CERTIFIER_ROOT" -type f -name 'secure_authenticated_channel*.h' | head -n1 || true)"
STORE_H="$(find "$CERTIFIER_ROOT" -type f -name 'store.h' | head -n1 || true)"

if [[ -z "${TM_H:-}" || -z "${CH_H:-}" ]]; then
  echo "ERROR: Could not find trust_manager.h or secure_authenticated_channel*.h under: $CERTIFIER_ROOT"
  echo "       Make sure the repo is built and headers are present."
  exit 1
fi

# 3) Compute include roots (parent of the folder that contains each header)
inc_root_of () { python3 - <<'PY'
import os, sys
h = sys.argv[1]
d = os.path.dirname(h)       # .../trust_manager
print(os.path.dirname(d))    # parent (often .../include)
PY
}

CERTIFIER_INC1="$(inc_root_of "$TM_H")"
CERTIFIER_INC2="$(inc_root_of "$CH_H")"
if [[ -n "${STORE_H:-}" ]]; then
  CERTIFIER_INC3="$(inc_root_of "$STORE_H")"
else
  CERTIFIER_INC3=""
fi

# 4) Locate JAVA_HOME / JNI includes
if [[ -z "${JAVA_HOME:-}" ]]; then
  # try common JDK locations
  for J in /usr/lib/jvm/java-21* /usr/lib/jvm/java-17* /usr/lib/jvm/*; do
    [[ -d "$J/include" ]] && JAVA_HOME="$J" && break
  done
fi
if [[ -z "${JAVA_HOME:-}" ]]; then
  echo "ERROR: JAVA_HOME not set and no JDK found under /usr/lib/jvm/*"
  echo "       Install a JDK (17+ recommended) or export JAVA_HOME then re-run."
  exit 1
fi

JNI_INC1="$JAVA_HOME/include"
case "$(uname -s)" in
  Linux)  JNI_INC2="$JAVA_HOME/include/linux"  ;;
  Darwin) JNI_INC2="$JAVA_HOME/include/darwin" ;;
  *)      JNI_INC2="$JAVA_HOME/include/linux"  ;;  # default
esac

# 5) Guess a library directory inside the certifier build output
# (You may adjust this if your build places libs elsewhere)
CERTIFIER_LIBDIR="$(find "$CERTIFIER_ROOT" -type d -name lib | head -n1 || true)"

# 6) Write everything to paths.env for easy sourcing
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

echo "Wrote paths.env with:"
cat paths.env
