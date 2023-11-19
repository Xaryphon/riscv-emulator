#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <elf.h>

#include "devices/uart/ns16550.h"
#include "elf_loader.h"
#include "gdbserver.h"
#include "logger.h"
#include "inst.h"
#include "exec.h"
#include "memory_builder.h"

static void rv_dump_memory_map(rv_MemoryDevice *map) {
    rv_debug(" address      size  flags  data");
    for (; map->size != 0; map++) {
        rv_debug("%0" RV_PRIx_PADDED "  %08zx   %c%c%c%c  %p", map->address, map->size,
                 map->flags & RV_MEMORY_SHOULD_FREE ? 'F' : ' ',
                 map->flags & RV_MEMORY_READ ? 'r' : '-',
                 map->flags & RV_MEMORY_WRITE ? 'w' : '-',
                 map->flags & RV_MEMORY_EXECUTE ? 'x' : '-',
                 map->data);
    }
}

#define ROM_ADDR 0x80000000
#define URT_ADDR 0x40000000
#define RAM_ADDR 0x10000000
#define RAM_SIZE 4096

// TODO: Move to unit tests
void rv_test_sign_extend(rv_UInt value, size_t sign_bit_index, rv_UInt expected) {
    rv_UInt result = rv_sign_extend(value, sign_bit_index);
    if (result == expected) {
        rv_info("PASS 0x%0" RV_PRIx_PADDED " :%zu -> 0x%0" RV_PRIx_PADDED, value, sign_bit_index, result);
    } else {
        rv_error("FAIL 0x%0" RV_PRIx_PADDED " :%zu -> 0x%0" RV_PRIx_PADDED " expected 0x%0" RV_PRIx_PADDED, value, sign_bit_index, result, expected);
    }
}

void rv_test_signed_less_than(rv_UInt lhs, rv_UInt rhs, bool expected) {
    bool result = rv_signed_less_than(lhs, rhs);
    if (result == expected) {
        rv_info("PASS 0x%0" RV_PRIx_PADDED " < 0x%0" RV_PRIx_PADDED " -> %s", lhs, rhs, result ? "true" : "false");
    } else {
        rv_error("FAIL 0x%0" RV_PRIx_PADDED " < 0x%0" RV_PRIx_PADDED " -> %s expected %s", lhs, rhs, result ? "true" : "false", expected ? "true" : "false");
    }
}

void rv_print_usage(void) {
    rv_error("Usage: riscv [-gdb] [--] ELF_PATH");
}

int main(int argc, char **argv) {
#if 0
    // FIXME: Make work for XLEN=64
    rv_test_sign_extend(0, 15, 0);
    rv_test_sign_extend(69, 15, 69);
    rv_test_sign_extend(128, 7, 0xffffff80);
    rv_test_sign_extend(242, 7, 0xffffff00 | 242);
    rv_test_sign_extend(0x80000000, 31, 0x80000000);
    rv_test_sign_extend(0, 31, 0);
    rv_test_sign_extend(0x87654321, 31, 0x87654321);

    return 0;
#endif
#if 0
    // FIXME: Make work for XLEN=64
    rv_test_signed_less_than(0, 0, false);
    rv_test_signed_less_than(128, 16, false);
    rv_test_signed_less_than(16, 128, true);
    rv_test_signed_less_than(0xffffffff, 0x80000000, false);
    rv_test_signed_less_than(0x80000000, 0xffffffff, true);
    rv_test_signed_less_than(0xffffffff, 0xffffffff, false);
    rv_test_signed_less_than(128, 0xffffffff, false);
    rv_test_signed_less_than(0xffffffff, 128, true);
    return 0;
#endif

    if (argc < 2) {
        rv_print_usage();
        return 1;
    }

    bool arg_end = false;
    bool arg_gdb = false;
    const char *arg_elf = NULL;
    for (char **argp = argv + 1; *argp != NULL; argp++) {
        if (!arg_end && **argp == '-') {
            if (strcmp("-gdb", *argp) == 0) {
                arg_gdb = true;
            } else if (strcmp("--", *argp) == 0) {
                arg_end = true;
            } else {
                rv_error("Unknown option '%s'", *argp);
                rv_print_usage();
                return 1;
            }
        } else {
            if (arg_elf != NULL) {
                rv_error("ELF_PATH already set '%s'", arg_elf);
                rv_print_usage();
                return 1;
            }
            arg_elf = *argp;
        }
    }

    if (arg_elf == NULL) {
        rv_error("ELF_PATH required");
        rv_print_usage();
        return 1;
    }

    int rom_fd = open(arg_elf, O_RDONLY);
    if (rom_fd == -1) {
        rv_error("Failed to open rom.fd: %s(%d) %s", strerrorname_np(errno), errno, strerrordesc_np(errno));
        return 1;
    }

    off_t rom_size = lseek(rom_fd, 0, SEEK_END);
    if (rom_size == -1) {
        rv_error("Failed to get rom.fd size: %s(%d) %s", strerrorname_np(errno), errno, strerrordesc_np(errno));
        return 1;
    }

    void *rom_ptr = mmap(NULL, rom_size, PROT_READ, MAP_SHARED, rom_fd, 0);
    if (rom_ptr == NULL) {
        rv_error("Failed to map rom.fd: %s(%d) %s", strerrorname_np(errno), errno, strerrordesc_np(errno));
        return 1;
    }

    rv_UInt entry;
    rv_MemoryBuilder *builder = rv_create_memory_builder(8);
    assert(builder);
    if (!rv_load_elf(rom_ptr, rom_size, builder, ROM_ADDR, &entry)) {
        rv_error("Failed to load elf");
        rv_memory_destroy(builder);
        return 1;
    }

    if (!rv_dev_uart_ns16550_init(builder, URT_ADDR)) {
        rv_error("Failed to init UART");
        rv_memory_destroy(builder);
        return 1;
    }

    void *ram_ptr = malloc(RAM_SIZE);
    if (ram_ptr == NULL) {
        rv_error("Failed to allocate ram: %s(%d) %s", strerrorname_np(errno), errno, strerrordesc_np(errno));
        return 1;
    }
    memset(ram_ptr, 0xff, RAM_SIZE);
    strcpy(ram_ptr, "Hello World!\n");

    rv_MemoryDevice *ram = rv_memory_push(builder, RAM_ADDR, RAM_SIZE);
    assert(ram);
    ram->data = ram_ptr;
    ram->flags = RV_MEMORY_READ | RV_MEMORY_WRITE;

    rv_Environment env = {
        .memory = rv_memory_get_list(builder),
    };

    rv_Hart hart = {
        .pc = entry,
        .x[1] = RAM_ADDR + RAM_SIZE,
        .x[9] = RAM_ADDR,
    };

    (void)rv_dump_memory_map(env.memory);

    if (arg_gdb) {
        rv_GDBServer *gdb = rv_create_gdb_server(&env, &hart);
        rv_gdb_run_forever(gdb, stdin, stdout);
        rv_gdb_destroy(gdb);
    } else {
        rv_Trap trap;
        do {
            trap = rv_run(&env, &hart);
        } while (rv_handle_trap(&env, &hart, trap));
        switch (trap) {
        case RV_TRAP_SUCCESS: /* Unreachable */ break;
        case RV_TRAP_PAGE_FAULT: rv_warn("Hart halted with a page fault"); break;
        case RV_TRAP_UNIMPLEMENTED: rv_warn("Hart encountered an unimplemented instruction"); break;
        case RV_TRAP_ILLEGAL_INSTRUCTION: rv_warn("Hart halted with an illegal instruction"); break;
        case RV_TRAP_EBREAK: rv_warn("Hart hit an EBREAK"); break;
        }
        rv_dump_hart(&hart);
    }

    rv_memory_destroy(builder);
    free(ram_ptr);
}

