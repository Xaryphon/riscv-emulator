#include "ns16550.h"

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "logger.h"

#define RV_DEV_UART_NS16550_BUFFER_SIZE 512
#define RV_DEV_UART_NS16550_MEMORY_SIZE 8

#define RV_NS16550_IER_RECEIVED_DATA_AVAILABLE 0x01
#define RV_NS16550_IER_TRANSMITTER_HOLDING_REGISTER_EMPTY 0x02
#define RV_NS16550_IER_RECEIVER_LINE_STATUS 0x04
#define RV_NS16550_IER_MODEM_STATUS 0x08

#define RV_NS16550_FCR_FIFO_ENABLE 0x01
#define RV_NS16550_FCR_RECEIVER_RESET 0x02
#define RV_NS16550_FCR_TRANSMIT_RESET 0x04
#define RV_NS16550_FCR_DMA_MODE_SELECT 0x08
#define RV_NS16550_FCR_RECEIVER_TRIGGER 0xc0

#define RV_NS16550_IIR_NO_INTERRUPT_PENDING 0x01
#define RV_NS16550_IIR_INTERRUPT_ID 0x0e
#define RV_NS16550_IIR_FIFO_ENABLED 0xc0

#define RV_NS16550_INTERRUPT_MODEM_STATUS 0x00
#define RV_NS16550_INTERRUPT_TRANSMITTER_HOLDING_REGISTER_EMPTY 0x02
#define RV_NS16550_INTERRUPT_RECEIVED_DATA_AVAILABLE 0x04
#define RV_NS16550_INTERRUPT_RECEIVER_LINE_STATUS 0x06
//#define RV_NS16550_INTERRUPT_TRIGGER_LEVEL_IDENTIFICATION 0xc0

#define RV_NS16550_LCR_WORD_LENGTH_SELECT 0x03
#define RV_NS16550_LCR_NUMBER_OF_STOP_BITS 0x04
#define RV_NS16550_LCR_PARITY_ENABLE 0x08
#define RV_NS16550_LCR_EVEN_PARITY_SELECT 0x10
#define RV_NS16550_LCR_STICK_PARITY 0x20
#define RV_NS16550_LCR_SET_BREAK 0x40
#define RV_NS16550_LCR_DIVISOR_LATCH_ACCESS_BIT 0x80

#define RV_NS16550_MCR_DATA_TERMINAL_READY 0x01
#define RV_NS16550_MCR_REQUEST_TO_SEND 0x02
#define RV_NS16550_MCR_OUT_1 0x04
#define RV_NS16550_MCR_OUT_2 0x08
#define RV_NS16550_MCR_LOOP_BACK_ENABLE 0x10

#define RV_NS16550_LSR_DATA_READY 0x01
#define RV_NS16550_LSR_OVERRUN_ERROR 0x02
#define RV_NS16550_LSR_PARITY_ERROR 0x04
#define RV_NS16550_LSR_FRAMING_ERROR 0x08
#define RV_NS16550_LSR_BREAK_INTERRUPT 0x10
#define RV_NS16550_LSR_TRANSMITTER_HOLDING_REGISTER_EMPTY 0x20
#define RV_NS16550_LSR_TRANSMITTER_EMPTY 0x40
#define RV_NS16550_LSR_ERROR_IN_RECEIVER_FIFO 0x80

#define RV_NS16550_MSR_DELTA_CLEAR_TO_SEND 0x01
#define RV_NS16550_MSR_DELTA_DATA_SET_READY 0x02
#define RV_NS16550_MSR_TRAILING_EDGE_RING_INDICATOR 0x04
#define RV_NS16550_MSR_DELTA_DATA_CARRIER_DETECT 0x08
#define RV_NS16550_MSR_CLEAR_TO_SEND 0x10
#define RV_NS16550_MSR_DATA_SET_READY 0x20
#define RV_NS16550_MSR_RING_INDICATOR 0x40
#define RV_NS16550_MSR_DATA_CARRIER_DETECT 0x80

typedef struct rv_dev_uart_ns16550 {
    uint8_t line_control;
    uint8_t scratch;
} rv_dev_uart_ns16550;

typedef enum rv_ns16550_Register {
    RV_NS16550_REGISTER_RECEIVER_BUFFER = 0, // DLAB=0 READ
    RV_NS16550_REGISTER_TRANSMITTER_HOLDING = 0, // DLAB=0 WRITE
    RV_NS16550_REGISTER_INTERRUPT_ENABLE = 1, // DLAB=0
    RV_NS16550_REGISTER_INTERRUPT_IDENTIFICATION = 2, // READ
    RV_NS16550_REGISTER_FIFO_CONTROL = 2, // WRITE
    RV_NS16550_REGISTER_LINE_CONTROL = 3,
    RV_NS16550_REGISTER_MODEM_CONTROL = 4,
    RV_NS16550_REGISTER_LINE_STATUS = 5,
    RV_NS16550_REGISTER_MODEM_STATUS = 6,
    RV_NS16550_REGISTER_SCRATCH = 7,
    RV_NS16550_REGISTER_DIVISOR_LATCH_LSB = 8, // DLAB=1
    RV_NS16550_REGISTER_DIVISOR_LATCH_MSB = 9, // DLAB=1
} rv_ns16550_Register;

static rv_ns16550_Register rv_ns16550_resolve(rv_dev_uart_ns16550 *state, rv_UInt index) {
    if (index < 2 && (state->line_control & RV_NS16550_LCR_DIVISOR_LATCH_ACCESS_BIT)) {
        return RV_NS16550_REGISTER_DIVISOR_LATCH_LSB + index;
    } else {
        return index;
    }
}

uint8_t rv_ns16550_read(rv_dev_uart_ns16550 *state, rv_ns16550_Register reg) {
    switch (reg) {
    case RV_NS16550_REGISTER_RECEIVER_BUFFER:
        break;
    case RV_NS16550_REGISTER_INTERRUPT_ENABLE:
        break;
    case RV_NS16550_REGISTER_INTERRUPT_IDENTIFICATION:
        break;
    case RV_NS16550_REGISTER_LINE_CONTROL:
        break;
    case RV_NS16550_REGISTER_MODEM_CONTROL:
        break;
    case RV_NS16550_REGISTER_LINE_STATUS:
        break;
    case RV_NS16550_REGISTER_MODEM_STATUS:
        break;
    case RV_NS16550_REGISTER_SCRATCH:
        return state->scratch;
    case RV_NS16550_REGISTER_DIVISOR_LATCH_LSB:
        break;
    case RV_NS16550_REGISTER_DIVISOR_LATCH_MSB:
        break;
    }
   return 0;
}

void rv_ns16550_write(rv_dev_uart_ns16550 *state, rv_ns16550_Register reg, uint8_t value) {
    switch (reg) {
    case RV_NS16550_REGISTER_TRANSMITTER_HOLDING:
        fputc(value, stderr);
        break;
    case RV_NS16550_REGISTER_INTERRUPT_ENABLE:
        break;
    case RV_NS16550_REGISTER_FIFO_CONTROL:
        break;
    case RV_NS16550_REGISTER_LINE_CONTROL:
        break;
    case RV_NS16550_REGISTER_MODEM_CONTROL:
        break;
    case RV_NS16550_REGISTER_LINE_STATUS:
        break;
    case RV_NS16550_REGISTER_MODEM_STATUS:
        break;
    case RV_NS16550_REGISTER_SCRATCH:
        state->scratch = value;
        break;
    case RV_NS16550_REGISTER_DIVISOR_LATCH_LSB:
        break;
    case RV_NS16550_REGISTER_DIVISOR_LATCH_MSB:
        break;
    }
}

bool rv_dev_uart_ns16550_callback(void *data, rv_UInt offset, void *dest_, size_t size, uint32_t flags) {
    assert(offset < 8);
    assert(size < 8 - offset);
    rv_dev_uart_ns16550 *state = data;
    uint8_t *dest = dest_;
    switch (flags) {
    case RV_MEMORY_CALLBACK_READ:
        for (rv_UInt i = 0; i < size; i++) {
            dest[i] = rv_ns16550_read(state, rv_ns16550_resolve(state, offset + i));
        }
        return true;
    case RV_MEMORY_CALLBACK_WRITE:
        for (rv_UInt i = 0; i < size; i++) {
            rv_ns16550_write(state, rv_ns16550_resolve(state, offset + i), dest[i]);
        }
        return true;
    }
    rv_debug("Unsupported operation 0x%08x", flags);
    return false;
}

bool rv_dev_uart_ns16550_init(rv_MemoryBuilder *builder, rv_UInt address) {
    rv_dev_uart_ns16550 *state = malloc(sizeof(*state) + RV_DEV_UART_NS16550_BUFFER_SIZE);
    if (state == NULL)
        return false;

    rv_MemoryDevice *mem = rv_memory_push(builder, address, RV_DEV_UART_NS16550_MEMORY_SIZE);
    if (mem == NULL) {
        free(state);
        return false;
    }

    memset(state, 0, sizeof(*state));
    mem->data = state;
    mem->flags = RV_MEMORY_SHOULD_FREE | RV_MEMORY_WRITE | RV_MEMORY_READ;
    mem->callback = rv_dev_uart_ns16550_callback;

    return true;
}

