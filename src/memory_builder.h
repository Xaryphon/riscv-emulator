#pragma once

#include <stdbool.h>

#include "exec.h"

typedef struct rv_MemoryBuilder rv_MemoryBuilder;

rv_MemoryBuilder *rv_create_memory_builder(size_t initial_capacity);
void rv_memory_destroy(rv_MemoryBuilder *);
bool rv_memory_grow(rv_MemoryBuilder *builder, size_t by_at_least);
bool rv_memory_can_fit(rv_MemoryBuilder *builder, rv_UInt address, size_t size);
rv_MemoryDevice *rv_memory_push(rv_MemoryBuilder *, rv_UInt address, size_t size);
rv_MemoryDevice *rv_memory_get_list(rv_MemoryBuilder *);

