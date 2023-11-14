#!/bin/sh

set -e


CFLAGS="$CFLAGS -Wall -Wpedantic -Wextra -Werror -Wno-unused-parameter"

cmake -S . -B build -GNinja -Werror=dev \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_C_FLAGS_DEBUG="-g -fsanitize=address,undefined" \
    "$@"
