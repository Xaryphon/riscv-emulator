#pragma once

enum rv_log_level {
    RV_ERROR,
    RV_WARN,
    RV_INFO,
    RV_DEBUG,
    RV_LOG_LEVELS
};

void rv_log(enum rv_log_level, const char *fmt, ...)
__attribute__((format(printf, 2, 3)));

#define rv_error(...) rv_log(RV_ERROR, __VA_ARGS__)
#define rv_warn(...) rv_log(RV_WARN, __VA_ARGS__)
#define rv_info(...) rv_log(RV_INFO, __VA_ARGS__)
#define rv_debug(...) rv_log(RV_DEBUG, __VA_ARGS__)

