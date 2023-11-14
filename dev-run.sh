#!/bin/sh

set -e

ninja -C build
exec ./build/riscv examples/strlen.elf
#exec riscv32-elf-gdb -ex 'target remote | ./build/riscv -gdb examples/strlen.elf'

