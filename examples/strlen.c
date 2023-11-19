#define UART ((volatile char*)0x40000000)

void uart_putc(char c) {
    UART[0] = c;
}

void uart_puts(const char *str) {
    while (*str != '\0')
        uart_putc(*str++);
}

void uart_putx(int x_) {
    unsigned int x = x_;
    unsigned int i = sizeof(x) * 8;
    while (i > 0) {
        i -= 4;
        uart_putc("0123456789abcdef"[(x >> i) & 0xf]);
    }
}

int strlen(const char *str) {
    int i;
    for (i = 0; str[i] != '\0'; i++) {
    }
    return i;
}

void _start(const char *str) {
    int len = strlen(str);

    uart_puts("strlen(\"");
    uart_puts(str);
    uart_puts("\") => 0x");
    uart_putx(len);
    uart_putc('\n');

    asm volatile ("ebreak");
    __builtin_unreachable();
}

