#pragma once

enum rv_log_level {
    RV_ERROR,
    RV_WARN,
    RV_INFO,
    RV_DEBUG,
    RV_LOG_LEVELS
};

void rv_log(enum rv_log_level, const char *func, const char *fmt, ...)
__attribute__((format(printf, 3, 4)));

#define rv_error(...) rv_log(RV_ERROR, __func__, __VA_ARGS__)
#define rv_warn(...) rv_log(RV_WARN, __func__, __VA_ARGS__)
#define rv_info(...) rv_log(RV_INFO, __func__, __VA_ARGS__)
#define rv_debug(...) rv_log(RV_DEBUG, __func__, __VA_ARGS__)

