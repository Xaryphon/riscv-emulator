#include "memory_builder.h"
#include "logger.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

struct rv_MemoryBuilder {
    rv_MemoryDevice *data;
    size_t count;
    size_t capacity;
};

bool rv_memory_grow(rv_MemoryBuilder *builder, size_t by_at_least) {
    size_t new_capacity = builder->count + by_at_least;
    if (new_capacity <= builder->capacity)
        return true;

    if (builder->capacity == 0)
        new_capacity += 1;

    if (new_capacity < builder->capacity * 2)
        new_capacity = builder->capacity * 2;

    rv_MemoryDevice *ptr = realloc(builder->data, sizeof(rv_MemoryDevice) * new_capacity);
    if (ptr == NULL)
        return false;

    memset(ptr + builder->capacity, 0, sizeof(rv_MemoryDevice) * (new_capacity - builder->capacity));

    builder->data = ptr;
    builder->capacity = new_capacity;
    return true;
}

rv_MemoryBuilder *rv_create_memory_builder(size_t initial_capacity) {
    rv_MemoryBuilder *builder = malloc(sizeof(rv_MemoryBuilder));
    if (builder == NULL)
        return NULL;

    memset(builder, 0, sizeof(*builder));

    if (!rv_memory_grow(builder, initial_capacity)) {
        free(builder);
        return NULL;
    }

    return builder;
}

void rv_memory_destroy(rv_MemoryBuilder *builder) {
    if (builder == NULL || builder->data == NULL)
        return;

    for (rv_MemoryDevice *mem = builder->data; mem->size != 0; mem++) {
        if (mem->flags & RV_MEMORY_SHOULD_FREE)
            free(mem->data);
    }

    free(builder->data);
    free(builder);
}

bool rv_memory_can_fit(rv_MemoryBuilder *builder, rv_UInt address, size_t size) {
    assert(size > 0);

    size_t address_end = address + size - 1;
    for (rv_MemoryDevice *mem = builder->data; mem->size != 0; mem++) {
        if (address <= mem->address + mem->size && address_end >= mem->address)
            return false;
    }

    return true;
}

rv_MemoryDevice *rv_memory_push(rv_MemoryBuilder *builder, rv_UInt address, size_t size) {
    if (!rv_memory_can_fit(builder, address, size))
        return NULL;

    if (!rv_memory_grow(builder, 1))
        return NULL;

    rv_MemoryDevice *mem = builder->data + builder->count;
    mem->address = address;
    mem->size = size;

    builder->count += 1;

    return mem;
}

rv_MemoryDevice *rv_memory_get_list(rv_MemoryBuilder *builder) {
    return builder->data;
}
