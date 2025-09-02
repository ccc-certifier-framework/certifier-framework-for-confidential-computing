#!/bin/bash
# ############################################################################
# prepare-test.sh: Driver script to run build-and-test for cf_utility.
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

if [ -z "{$CERTIFIER_ROOT}+set" ] ; then
  echo " "
  CERTIFIER_ROOT=../../..
else
  echo " "
  echo "CERTIFIER_ROOT already set."
fi
EXAMPLE_DIR=.

echo " "
echo "Certifier root: $CERTIFIER_ROOT"
echo "Example directory: $EXAMPLE_DIR"

ARG_SIZE="$#"

if [ $ARG_SIZE != 1 ] ; then
  echo "Must call with an arguments, as follows:"
  echo "  ./prepare-test.sh fresh"
  echo "  ./prepare-test.sh all"
  echo "  ./prepare-test.sh compile-utilities"
  echo "  ./prepare-test.sh make-keys"
  echo "  ./prepare-test.sh all"
  echo "  ./prepare-test.sh make-policy"
  echo "  ./prepare-test.sh compile-certifier"
  echo "  ./prepare-test.sh copy-files"
  exit
fi

function do-fresh() {
  echo "do-fresh"
}

function do-compile-utilities() {
  echo "do-compile-utilities"
}

function do-make-keys() {
  echo "do-make-keys"
}

function do-compile-program() {
  echo "do-compile-program"
}

function do-make-policy() {
  echo "do-make-policy"
}

function do-compile-certifier() {
  echo "do-compile-certifier"
}

function do-copy-files() {
  echo "do-copy-files"
}

function do-all() {
  echo "do-all"
}

if [ "$1" == "fresh" ] ; then
  echo " "
  do-fresh
  exit
fi

if [ "$1" == "all" ] ; then
  echo " "
  do-compile-utilities
  do-make-keys
  do-compile-program
  do-make-policy
  do-compile-certifier
  do-copy-files
  exit
fi

if [ "$1" == "compile-utilities" ] ; then
  echo " "
  do-compile-utilities
fi

if [ "$1" == "make-keys" ] ; then
  echo " "
  do-make-keys
fi

if [ "$1" == "compile-program" ] ; then
  echo " "
  do-compile-program
fi

if [ "$1" == "make-policy" ] ; then
  echo " "
  do-make-policy
fi

if [ "$1" == "compile-certifier" ] ; then
  echo " "
  do-compile-certifier
fi

if [ "$1" == "copy-files" ] ; then
  echo " "
  do-copy-files
fi
