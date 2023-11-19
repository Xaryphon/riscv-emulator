#include "environment.h"

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "logger.h"

const char *const rv_register_names[32] = {
    "zero", "ra", "sp",  "gp",  "tp", "t0", "t1", "t2",
    "s0",   "s1", "a0",  "a1",  "a2", "a3", "a4", "a5",
    "a6",   "a7", "s2",  "s3",  "s4", "s5", "s6", "s7",
    "s8",   "s9", "s10", "s11", "t3", "t4", "t5", "t6",
};

void rv_dump_hart(rv_Hart *hart) {
#if 0
    rv_debug("pc  : %0" RV_PRIx_PADDED "  x1  : %0" RV_PRIx_PADDED "  x2  : %0" RV_PRIx_PADDED "  x3  : %0" RV_PRIx_PADDED, hart->pc, hart->x[0], hart->x[1], hart->x[2]);
    for (size_t i = 3; i < sizeof(hart->x) / sizeof(*hart->x); i += 4) {
        rv_debug("x%-2zu : %0" RV_PRIx_PADDED "  x%-2zu : %0" RV_PRIx_PADDED "  x%-2zu : %0" RV_PRIx_PADDED "  x%-2zu : %0" RV_PRIx_PADDED, i + 1, hart->x[i], i + 2, hart->x[i + 1], i + 3, hart->x[i + 2], i + 4, hart->x[i + 3]);
    }
#else
    rv_debug("pc  %0" RV_PRIx_PADDED "  ra  %0" RV_PRIx_PADDED "  sp  %0" RV_PRIx_PADDED "  gp  %0" RV_PRIx_PADDED, hart->pc, hart->x[0], hart->x[1], hart->x[2]);
    for (size_t i = 3; i < sizeof(hart->x) / sizeof(*hart->x); i += 4) {
        rv_debug("%-3s %0" RV_PRIx_PADDED "  %-3s %0" RV_PRIx_PADDED "  %-3s %0" RV_PRIx_PADDED "  %-3s %0" RV_PRIx_PADDED, rv_register_names[i + 1], hart->x[i], rv_register_names[i+ 2], hart->x[i + 1], rv_register_names[i + 3], hart->x[i + 2], rv_register_names[i + 4], hart->x[i + 3]);
    }
#endif
}

rv_MemoryDevice *rv_memory_resolve(rv_Environment *env, rv_UInt address) {
    for (rv_MemoryDevice *mem = env->memory; mem->size != 0; mem++) {
        if (address >= mem->address && address < mem->address + mem->size) {
            return mem;
        }
    }
    return NULL;
}

bool rv_memory_access(rv_Environment *env, void *ptr, rv_UInt address, size_t size, uint32_t flags) {
    rv_MemoryDevice *mem = rv_memory_resolve(env, address);
    if (mem == NULL) {
        rv_warn("Failed to resolve address 0x%0" RV_PRIx_PADDED, address);
        return false;
    }

    size_t offset = address - mem->address;
    if (offset + size > mem->size) {
        rv_warn("Failed to access address 0x%0" RV_PRIx_PADDED " size 0x%zx", address, size);
        return false;
    }

    switch (flags & RV_MEMORY_CALLBACK_OPERATION_MASK) {
    case RV_MEMORY_CALLBACK_READ:
        if (!(mem->flags & RV_MEMORY_READ)) {
            rv_warn("Failed to read memory address 0x%0" RV_PRIx_PADDED " size 0x%zx: Memory not marked as readable", address, size);
            return false;
        }
        if (mem->callback != NULL)
            return mem->callback(mem->data, offset, ptr, size, RV_MEMORY_CALLBACK_READ);
        memcpy(ptr, (uint8_t*)mem->data + offset, size);
        break;
    case RV_MEMORY_CALLBACK_WRITE:
        if (!(mem->flags & RV_MEMORY_WRITE)) {
            rv_warn("Failed to write memory address 0x%0" RV_PRIx_PADDED " size 0x%zx: Memory not marked as writable", address, size);
            return false;
        }
        if (mem->callback != NULL)
            return mem->callback(mem->data, offset, ptr, size, RV_MEMORY_CALLBACK_WRITE);
        memcpy((uint8_t*)mem->data + offset, ptr, size);
        break;
    default:
        abort();
    }

    return true;
}

bool rv_read_memory(rv_Environment *env, rv_UInt address, void *out, size_t bytes) {
    assert(bytes <= sizeof(rv_UInt));
    rv_MemoryDevice *mem = rv_memory_resolve(env, address);
    if (mem == NULL) {
        rv_warn("Failed to resolve address 0x%0" RV_PRIx_PADDED, address);
        return false;
    }
    size_t offset = address - mem->address;
    if (offset + bytes > mem->size) {
        rv_warn("Failed to access address 0x%0" RV_PRIx_PADDED " size 0x%zx", address, bytes);
        return false;
    }
    memcpy(out, (uint8_t*)mem->data + offset, bytes);
    return true;
}

bool rv_write_memory(rv_Environment *env, rv_UInt address, void *value, size_t bytes) {
    rv_MemoryDevice *mem = rv_memory_resolve(env, address);
    if (mem == NULL) {
        rv_warn("Failed to resolve address 0x%0" RV_PRIx_PADDED, address);
        return false;
    }

    size_t offset = address - mem->address;
    if (offset + bytes > mem->size) {
        rv_warn("Failed to access address 0x%0" RV_PRIx_PADDED " size 0x%zx", address, bytes);
        return false;
    }

    memcpy((uint8_t*)mem->data + offset, value, bytes);
    return true;
}

