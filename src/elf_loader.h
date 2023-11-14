#pragma once

#include "memory_builder.h"

bool rv_load_elf(void *ptr, size_t size, rv_MemoryBuilder *builder, rv_UInt address, rv_UInt *entry);

