#pragma once

#include <stdio.h>

#include "exec.h"

typedef struct rv_GDBServer rv_GDBServer;

rv_GDBServer *rv_create_gdb_server(rv_Environment *, rv_Hart *hart);
void rv_gdb_run_forever(rv_GDBServer *, FILE *in, FILE *out);
void rv_gdb_destroy(rv_GDBServer *);

