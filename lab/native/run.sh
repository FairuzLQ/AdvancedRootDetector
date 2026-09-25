#!/usr/bin/env bash
# Builds the native lab runner with the host compiler (LAB_SANITIZE=1 adds ASan/UBSan).
# Output: lab/native/build/lab_native
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$here/build"
"${CXX:-clang++}" -std=c++17 -O1 -Wall -Wextra -Werror \
    ${LAB_SANITIZE:+-fsanitize=address,undefined} "$here/lab_native.cpp" -o "$here/build/lab_native"
echo "$here/build/lab_native"
