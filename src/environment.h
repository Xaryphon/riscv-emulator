#pragma once

#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef RV_XLEN
#define RV_XLEN 32
#endif

#if RV_XLEN == 32
typedef uint32_t rv_UInt;
typedef int32_t rv_SInt;
#define RV_PRIx PRIx32
#define RV_PRI_PAD "8"
#elif RV_XLEN == 64
typedef uint64_t rv_UInt;
typedef int64_t rv_SInt;
#define RV_PRIx PRIx64
#define RV_PRI_PAD "16"
#else
#error "RV_XLEN is invalid"
#endif

#define RV_PRIx_PADDED RV_PRI_PAD RV_PRIx

typedef struct rv_Hart {
    rv_UInt pc;
    rv_UInt x[31];
} rv_Hart;

#define RV_MEMORY_EXECUTE 0x1
#define RV_MEMORY_WRITE 0x2
#define RV_MEMORY_READ 0x4
#define RV_MEMORY_SHOULD_FREE 0x8

#define RV_MEMORY_CALLBACK_READ 0x0
#define RV_MEMORY_CALLBACK_WRITE 0x1
#define RV_MEMORY_CALLBACK_OPERATION_MASK 0x1

typedef struct rv_MemoryDevice rv_MemoryDevice;
typedef bool rv_MemoryCallback(void *data, rv_UInt offset, void *dest, size_t size, uint32_t flags);

typedef struct rv_MemoryDevice {
    void *data;
    size_t size;
    uint32_t flags;
    rv_UInt address;
    rv_MemoryCallback *callback;
} rv_MemoryDevice;
#define RV_MEMORY_DEVICE_LAST ((rv_MemoryDevice){ .size = 0 })

typedef struct rv_Environment {
    rv_MemoryDevice *memory;
} rv_Environment;

rv_MemoryDevice *rv_memory_resolve(rv_Environment *, rv_UInt address);
bool rv_memory_access(rv_Environment *, void *dest, rv_UInt address, size_t size, uint32_t flags);

extern const char *const rv_register_names[32];
void rv_dump_hart(rv_Hart *);

static inline rv_UInt rv_sign_extend(rv_UInt value, size_t sign_bit_index) {
    rv_UInt high_bit = (rv_UInt)1 << (sizeof(rv_UInt) * CHAR_BIT - 1);;
    rv_UInt sign_bit = (rv_UInt)1 << sign_bit_index;
    rv_UInt low_mask = sign_bit - 1;
    rv_UInt value_sign = value & sign_bit;
    rv_UInt extended_sign = ~(((high_bit ^ value_sign) - sign_bit) ^ high_bit);
    return (value & low_mask) | (extended_sign & ~low_mask);
}

static inline bool rv_signed_less_than(rv_UInt lhs, rv_UInt rhs) {
    rv_UInt sign_bit = (rv_UInt)1 << (sizeof(rv_UInt) * CHAR_BIT - 1);
    if ((lhs & sign_bit) ^ (rhs & sign_bit))
        return lhs & sign_bit;
    else
        return lhs < rhs;
}

// https://stackoverflow.com/a/2637138
static inline rv_UInt rv_swap_bytes(rv_UInt val) {
#if RV_XLEN == 32
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF );
    return (val << 16) | (val >> 16);
#elif RV_XLEN == 64
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL ) | ((val >> 8) & 0x00FF00FF00FF00FFULL );
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL ) | ((val >> 16) & 0x0000FFFF0000FFFFULL );
    return (val << 32) | (val >> 32);
#else
#error "Unimplemented XLEN"
#endif
}

