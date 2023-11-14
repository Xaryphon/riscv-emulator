#include "logger.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>

static const char level_chars[] = {
    [RV_ERROR] = 'E',
    [RV_WARN] = 'W',
    [RV_INFO] = 'I',
    [RV_DEBUG] = 'D',
};
static_assert(sizeof(level_chars) == RV_LOG_LEVELS, "enum rv_log_level changed");

void rv_log(enum rv_log_level lvl, const char *fmt, ...) {
    char lvl_char = lvl < RV_LOG_LEVELS ? level_chars[lvl] : '?';
    fprintf(stderr, "%c ", lvl_char);
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
}

