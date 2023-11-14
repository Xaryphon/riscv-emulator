#pragma once

#include <stdbool.h>

#include "environment.h"


typedef enum rv_Trap {
    RV_TRAP_SUCCESS,
    RV_TRAP_ILLEGAL_INSTRUCTION,
    RV_TRAP_PAGE_FAULT,
    RV_TRAP_UNIMPLEMENTED,
    RV_TRAP_EBREAK,
} rv_Trap;

rv_Trap rv_run(rv_Environment *, rv_Hart *);
rv_Trap rv_step(rv_Environment *, rv_Hart *);
bool rv_handle_trap(rv_Environment *, rv_Hart *, rv_Trap);

