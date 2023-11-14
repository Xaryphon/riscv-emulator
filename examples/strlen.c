int strlen(const char *str) {
    int i;
    for (i = 0; str[i] != '\0'; i++) {
    }
    return i;
}

void _start(const char *str) {
    strlen(str);
    asm volatile ("ebreak");
    __builtin_unreachable();
}

