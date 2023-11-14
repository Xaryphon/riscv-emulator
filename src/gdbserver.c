#include "gdbserver.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "logger.h"

#define RV_GDB_RECEIVE_BUFFER_SIZE 0x7fff

struct rv_GDBServer {
    rv_Environment *env;
    rv_Hart *hart;
    uint8_t *extractor;
    size_t packet_size;
    uint8_t packet_buf[RV_GDB_RECEIVE_BUFFER_SIZE];
};

rv_GDBServer *rv_create_gdb_server(rv_Environment *env, rv_Hart *hart) {
    rv_GDBServer *server = malloc(sizeof(*server));
    if (server == NULL)
        return NULL;
    memset(server, 0, sizeof(*server));
    server->env = env;
    server->hart = hart;
    return server;
}

static int rv_parse_xdigit(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    else if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1;
}

static char rv_to_xdigit(uint8_t v) {
    assert(v < 16);
    return v > 9 ? 'a' + (v - 10) : '0' + v;
}

typedef enum rv_GDBReadResult {
    RV_GDB_READ_SUCCESS,
    RV_GDB_READ_INVALID,
    RV_GDB_READ_ACK,
    RV_GDB_READ_NACK,
    RV_GDB_READ_ERROR,
} rv_GDBReadResult;

static rv_GDBReadResult rv_gdb_read_packet(rv_GDBServer *server, FILE *file) {
    uint8_t checksum = 0;
    int c;

    while ((c = getc(file)) != '$') {
        switch (c) {
        case EOF: return RV_GDB_READ_ERROR;
        case '+': return RV_GDB_READ_ACK;
        case '-': return RV_GDB_READ_NACK;
        default:  rv_debug("Expected $ got '%c' (0x%02x)", isprint(c) ? c : ' ', c);
        }
    }

    bool escape = false;
    size_t i = 0;
    while ((c = getc(file)) != EOF) {
        checksum += c;
        if (escape) {
            c ^= 0x20;
            escape = false;
        } else if (c == '}') {
            escape = true;
            continue;
        } else if (c == '#') {
            checksum += 256 - '#';
            server->packet_size = i;
            i = 2;
            while (i-- > 0) {
                c = getc(file);
                if (c == EOF)
                    return RV_GDB_READ_ERROR;
                int parsed = rv_parse_xdigit(c);
                if (parsed < 0)
                    return RV_GDB_READ_INVALID;
                assert(parsed < 0x10);
                checksum ^= (uint8_t)parsed << (i * 4);
            }
            if (server->packet_size >= RV_GDB_RECEIVE_BUFFER_SIZE)
                abort();
            server->packet_buf[server->packet_size] = '\0';
            server->extractor = server->packet_buf;
            return checksum == 0x00 ? RV_GDB_READ_SUCCESS : RV_GDB_READ_INVALID;
        }

        if (i >= RV_GDB_RECEIVE_BUFFER_SIZE)
            abort();

        server->packet_buf[i++] = c;
    }

    return RV_GDB_READ_ERROR;
}

static void rv_fwrite_all_or_abort(void *buffer, size_t size, FILE *file) {
    size_t wrote = fwrite(buffer, 1, size, file);
    if (wrote != size)
        abort();
    if (fflush(file))
        abort();
}

static bool rv_gdb_packet_is_inited(rv_GDBServer *server) {
    return server->packet_size > 0 && server->packet_buf[0] == '$';
}

static bool rv_gdb_packet_is_finalized(rv_GDBServer *server) {
    return server->packet_size >= 4 && server->packet_buf[server->packet_size - 3] == '#';
}

static void rv_gdb_packet_send(rv_GDBServer *server, FILE *out) {
    //rv_debug("Sending packet (0x%zx): %.*s", server->packet_size, (int)server->packet_size, server->packet_buf);

    assert(server->extractor == NULL);
    assert(rv_gdb_packet_is_inited(server));
    assert(rv_gdb_packet_is_finalized(server));

    rv_fwrite_all_or_abort(server->packet_buf, server->packet_size, out);
}

static void rv_gdb_packet_init(rv_GDBServer *server) {
    server->extractor = NULL;
    server->packet_buf[0] = '$';
    server->packet_size = 1;
}

static void rv_gdb_packet_push(rv_GDBServer *server, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void rv_gdb_packet_push(rv_GDBServer *server, const char *fmt, ...) {
    assert(server->extractor == NULL);
    assert(rv_gdb_packet_is_inited(server));
    assert(!rv_gdb_packet_is_finalized(server));

    uint8_t *head = server->packet_buf + server->packet_size;
    size_t writable = RV_GDB_RECEIVE_BUFFER_SIZE - server->packet_size;
    assert(writable > 0);
    va_list ap;
    va_start(ap, fmt);
    int wrote = vsnprintf((char*)head, writable, fmt, ap);
    va_end(ap);

    assert(wrote >= 0);
    assert((size_t)wrote < writable - 1);

    // FIXME: Escape response content
    for (size_t i = server->packet_size; i < server->packet_size + wrote; i++) {
        assert(strchr("#$*}", server->packet_buf[i]) == NULL);
    }

    server->packet_size += wrote;
}

static void rv_gdb_packet_finalize(rv_GDBServer *server) {
    assert(server->extractor == NULL);
    assert(rv_gdb_packet_is_inited(server));
    assert(!rv_gdb_packet_is_finalized(server));

    uint8_t *head = server->packet_buf + server->packet_size;
    size_t writable = RV_GDB_RECEIVE_BUFFER_SIZE - server->packet_size;
    assert(writable >= 3);

    uint8_t checksum = 0;
    for (uint8_t *ptr = server->packet_buf + 1; ptr != head; ptr++)
        checksum += *ptr;

    head[0] = '#';
    head[1] = rv_to_xdigit(checksum >> 4);
    head[2] = rv_to_xdigit(checksum & 0xf);
    server->packet_size += 3;
}

#define rv_gdb_packet_send_full(server, out, ...) \
    do { \
        rv_gdb_packet_init(server); \
        rv_gdb_packet_push(server, __VA_ARGS__); \
        rv_gdb_packet_finalize(server); \
        rv_gdb_packet_send(server, out); \
    } while (0)

#define rv_gdb_packet_send_empty(server, out) \
    do { \
        rv_gdb_packet_init(server); \
        rv_gdb_packet_finalize(server); \
        rv_gdb_packet_send(server, out); \
    } while (0)

#if RV_XLEN == 32
#define RV_XLEN_STR "32"
#elif RV_XLEN == 64
#define RV_XLEN_STR "64"
#else
#error "Unimplemented XLEN"
#endif

#define RV_GDB_TARGET_XML \
        "<target version=\"1.0\">" \
            "<architecture>riscv:rv32</architecture>" \
            "<feature name=\"org.gnu.gdb.riscv.cpu\">" \
                "<reg name=\"pc\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x0\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x1\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x2\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x3\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x4\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x5\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x6\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x7\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x8\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x9\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x10\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x11\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x12\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x13\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x14\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x15\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x16\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x17\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x18\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x19\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x20\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x21\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x22\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x23\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x24\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x25\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x26\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x27\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x28\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x29\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x30\" bitsize=\"" RV_XLEN_STR "\" />" \
                "<reg name=\"x31\" bitsize=\"" RV_XLEN_STR "\" />" \
            "</feature>" \
        "</target>"

#define RV_GDB_FORMAT_REGISTER_X "%0" RV_PRIx_PADDED

#define RV_GDB_EXTRACTOR_REWIND_BLOCK_SIZE (sizeof(char *))
typedef struct rv_GDBExtractorRewindData {
    char *pointer[RV_GDB_EXTRACTOR_REWIND_BLOCK_SIZE];
    char original[RV_GDB_EXTRACTOR_REWIND_BLOCK_SIZE];
    struct rv_GDBExtractorRewindData *next;
} rv_GDBExtractorRewindData;

static void rv_gdb_extractor_rewind_push(rv_GDBExtractorRewindData *data, char *pointer) {
    assert(pointer != NULL);

    while (data->next != NULL)
        data = data->next;

    for (size_t i = 0; i < RV_GDB_EXTRACTOR_REWIND_BLOCK_SIZE; i++) {
        if (data->pointer[i] == NULL) {
            data->pointer[i] = pointer;
            data->original[i] = *pointer;
            return;
        }
    }

    data = data->next = malloc(sizeof(*data));
    assert(data != NULL);
    memset(data, 0, sizeof(*data));
    data->pointer[0] = pointer;
    data->original[0] = *pointer;
}

static bool rv_gdb_packet_vextract(rv_GDBServer *server, const char *fmt, va_list ap) {
    assert(server->extractor);

    char *extractor = (void *)server->extractor;
    char *data_end = (void *)(server->packet_buf + server->packet_size);

    bool in_format = false;
    char size;

    // I chose the API now I get to live with it
    rv_GDBExtractorRewindData rewind = { 0 };
    bool ret = true;

    while (*fmt != '\0') {
        char fc = *fmt++;

        if (in_format) {
            if (fc == '%') {
                assert(size == '\0');
                goto match_literal;
            } else if (fc == 'z') {
                size = fc;
            } else if (fc == 'x') {
                #define RV_GDB_EXTRACTOR_PARSE_HEX(type) \
                    do { \
                        type parsed = 0; \
                        for (size_t i = 0; i < sizeof(parsed); i++) { \
                            if (extractor == data_end) { \
                                if (i == 0) \
                                    goto fail; \
                                break; \
                            } \
                            int x = rv_parse_xdigit(*extractor); \
                            if (x < 0) { \
                                if (i == 0) \
                                    goto fail; \
                                break; \
                            } else { \
                                extractor++; \
                                parsed = (parsed << 4) | x; \
                            } \
                        } \
                        *va_arg(ap, type *) = parsed; \
                    } while (0)
                in_format = false;
                if (size == 'z') {
                    RV_GDB_EXTRACTOR_PARSE_HEX(rv_UInt);
                } else {
                    abort();
                }
                #undef RV_GDB_EXTRACTOR_PARSE_HEX
            } else if (fc == 'u') {
                #define RV_GDB_EXTRACTOR_PARSE_UINT(type) \
                    do { \
                        type parsed = 0; \
                        for (size_t i = 0; i < sizeof(parsed); i++) { \
                            if (extractor == data_end || !isdigit(*extractor)) { \
                                if (i == 0) \
                                    goto fail; \
                                break; \
                            } else { \
                                parsed = (parsed * 10) + (*extractor++ - '0'); \
                            } \
                        } \
                        *va_arg(ap, type *) = parsed; \
                    } while (0)
                in_format = false;
                if (size == 'z') {
                    RV_GDB_EXTRACTOR_PARSE_UINT(size_t);
                } else {
                    abort();
                }
                #undef RV_GDB_EXTRACTOR_PARSE_UINT
            } else if (fc == 's') {
                in_format = false;
                *va_arg(ap, const char **) = extractor;
                while (extractor != data_end) {
                    if (*extractor == *fmt) {
                        rv_gdb_extractor_rewind_push(&rewind, extractor);
                        *extractor++ = '\0';
                        fmt++;
                        break;
                    }
                    extractor++;
                }
            } else {
                abort();
            }
        } else {
            if (fc == '%') {
                in_format = true;
                size = '\0';
            } else if (fc == '*') {
                while (*fmt != '\0') {
                    fc = *fmt++;
                    if (extractor == data_end)
                        goto success;
                    if (*extractor != fc)
                        goto fail;
                    extractor++;
                }
                goto success;
            } else {
            match_literal:
                if (extractor == data_end)
                    goto fail;
                if (*extractor++ != fc)
                    goto fail;
            }
        }
    }

    if (extractor != data_end)
        goto fail;

success:
    assert(in_format == false);
    server->extractor = (void *)extractor;
    goto cleanup;

fail:
    ret = false;
    for (rv_GDBExtractorRewindData *data = &rewind; data != NULL; data = data->next) {
        for (size_t i = 0; i < RV_GDB_EXTRACTOR_REWIND_BLOCK_SIZE; i++) {
            if (data->pointer[i] == NULL)
                break;
            *data->pointer[i] = data->original[i];
        }
    }

cleanup:
    while (rewind.next != NULL) {
        rv_GDBExtractorRewindData *data = rewind.next;
        rewind.next = data->next;
        free(data);
    }

    return ret;
}

static bool rv_gdb_packet_extract(rv_GDBServer *server, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    bool ret = rv_gdb_packet_vextract(server, fmt, ap);
    va_end(ap);
    return ret;
}

static void rv_gdb_handle_qxfer_read(rv_GDBServer *server, FILE *out, const char *object, const char *annex, size_t offset, size_t length) {
    if (strcmp(object, "features") == 0) {
        if (strcmp(annex, "target.xml") == 0) {
            if (offset >= sizeof(RV_GDB_TARGET_XML) - 1)
                rv_gdb_packet_send_full(server, out, "l");
            else
                rv_gdb_packet_send_full(server, out, "m%.*s", (int)length, (RV_GDB_TARGET_XML) + offset);
        } else {
            rv_gdb_packet_send_full(server, out, "E00");
        }
    } else {
        rv_gdb_packet_send_empty(server, out);
    }
}

unsigned int rv_gdb_map_trap_to_signal(rv_Trap trap) {
    // Signal numbers: https://sourceware.org/git/?p=binutils-gdb.git;a=blob;f=include/gdb/signals.def
    switch (trap) {
    case RV_TRAP_SUCCESS: return 0; // GDB_SIGNAL_0
    case RV_TRAP_ILLEGAL_INSTRUCTION: return 4; // GDB_SIGNAL_ILL
    case RV_TRAP_PAGE_FAULT: return 11; // GDB_SIGNAL_SEGV
    case RV_TRAP_UNIMPLEMENTED: return 6; // GDB_SIGNAL_ABRT
    case RV_TRAP_EBREAK: return 5; // GDB_SIGNAL_TRAP
    }
    return 143; // GDB_SIGNAL_UNKNOWN
}

void rv_gdb_run_forever(rv_GDBServer *server, FILE *in, FILE *out) {
    bool ack_packets = true;
    for (;;) {
        switch (rv_gdb_read_packet(server, in)) {
        case RV_GDB_READ_ACK:
            break;
        case RV_GDB_READ_NACK:
            rv_debug("Received NACK resending");
            rv_gdb_packet_send(server, out);
            break;
        case RV_GDB_READ_ERROR:
            rv_error("Failed to read packet");
            return;
        case RV_GDB_READ_INVALID:
            if (ack_packets)
                rv_fwrite_all_or_abort("-", 1, out);
            rv_gdb_packet_send_empty(server, out);
            break;
        case RV_GDB_READ_SUCCESS:
            if (ack_packets)
                rv_fwrite_all_or_abort("+", 1, out);

            // https://sourceware.org/gdb/current/onlinedocs/gdb.html/Packets.html
            if (rv_gdb_packet_extract(server, "?")) {
                rv_gdb_packet_send_full(server, out, "S05");
            } else if (rv_gdb_packet_extract(server, "c*")) {
                if (!rv_gdb_packet_extract(server, "")) {
                    rv_UInt address;
                    if (rv_gdb_packet_extract(server, "%zx", &address)) {
                        server->hart->pc = address;
                    } else {
                        rv_gdb_packet_send_empty(server, out);
                        break;
                    }
                }
                rv_Trap trap = rv_run(server->env, server->hart);
                rv_handle_trap(server->env, server->hart, trap); // FIXME: Do we loop until an unhandled trap?
                rv_gdb_packet_send_full(server, out, "S%02x", rv_gdb_map_trap_to_signal(trap));
            } else if (rv_gdb_packet_extract(server, "s*")) {
                if (!rv_gdb_packet_extract(server, "")) {
                    rv_UInt address;
                    if (rv_gdb_packet_extract(server, "%zx", &address)) {
                        server->hart->pc = address;
                    } else {
                        rv_gdb_packet_send_empty(server, out);
                        break;
                    }
                }
                rv_Trap trap = rv_step(server->env, server->hart);
                rv_handle_trap(server->env, server->hart, trap);
                rv_gdb_packet_send_full(server, out, "S%02x", rv_gdb_map_trap_to_signal(trap));
            } else if (rv_gdb_packet_extract(server, "g")) {
                rv_gdb_packet_init(server);
                rv_gdb_packet_push(server, RV_GDB_FORMAT_REGISTER_X, rv_swap_bytes(server->hart->pc));
                rv_gdb_packet_push(server, RV_GDB_FORMAT_REGISTER_X, (rv_UInt)0);
                for (size_t i = 0; i < sizeof(server->hart->x) / sizeof(*server->hart->x); i++) {
                    rv_gdb_packet_push(server, RV_GDB_FORMAT_REGISTER_X, rv_swap_bytes(server->hart->x[i]));
                }
                rv_gdb_packet_finalize(server);
                rv_gdb_packet_send(server, out);
            } else if (rv_gdb_packet_extract(server, "G*")) {
                rv_Hart *hart = server->hart;
                rv_UInt value;
                if (!rv_gdb_packet_extract(server, "%zx*", &value)) {
                    rv_gdb_packet_send_full(server, out, "Eff");
                    break;
                }
                hart->pc = rv_swap_bytes(value);
                if (!rv_gdb_packet_extract(server, "%zx*", &value)) {
                    rv_gdb_packet_send_full(server, out, "E00");
                    break;
                }
                // x0 = value;
                for (size_t i = 0; i < sizeof(hart->x) / sizeof(*hart->x); i++) {
                    if (!rv_gdb_packet_extract(server, "%zx*", &value)) {
                        rv_gdb_packet_send_full(server, out, "E%02zx", i + 1);
                        break;
                    }
                    hart->x[i] = rv_swap_bytes(value);
                }
                rv_gdb_packet_send_full(server, out, "OK");
            } else if (rv_gdb_packet_extract(server, "m*")) {
                rv_UInt address, length;
                if (!rv_gdb_packet_extract(server, "%zx,%zx", &address, &length)) {
                    rv_warn("Malformed packet received: %.*s", (int)server->packet_size, server->packet_buf);
                    rv_gdb_packet_send_full(server, out, "E00");
                    break;
                }
                rv_MemoryDevice *mem = rv_memory_resolve(server->env, address);
                if (mem == NULL || mem->callback != NULL) {
                    rv_gdb_packet_send_full(server, out, "E01");
                    break;
                }
                rv_gdb_packet_init(server);
                size_t readable = mem->address + mem->size - address;
                if (readable < length)
                    length = readable;
                size_t start = address - mem->address;
                size_t end = start + length;
                for (size_t i = start; i < end; i++) {
                    rv_gdb_packet_push(server, "%02x", ((uint8_t*)mem->data)[i]);
                }
                rv_gdb_packet_finalize(server);
                rv_gdb_packet_send(server, out);
            } else if (rv_gdb_packet_extract(server, "M*")) {
                rv_warn("TODO: Unimplemented packet: %.*s", (int)server->packet_size, server->packet_buf);
                rv_gdb_packet_send_full(server, out, "E00");
            } else if (rv_gdb_packet_extract(server, "qSupported*:")) {
                // TODO: Support qXfer:memory-map:read
                // TODO: Support multiprocess (for debugging S and H extensions)
                rv_gdb_packet_send_full(server, out, "PacketSize=%x;QStartNoAckMode+;qXfer:features:read+", RV_GDB_RECEIVE_BUFFER_SIZE);
            } else if (rv_gdb_packet_extract(server, "qXfer:*")) {
                const char *object;
                if (rv_gdb_packet_extract(server, "%s:read:*", &object)) {
                    const char *annex;
                    size_t offset, length;
                    if (rv_gdb_packet_extract(server, "%s:%zx,%zx", &annex, &offset, &length)) {
                        rv_gdb_handle_qxfer_read(server, out, object, annex, offset, length);
                    } else {
                        rv_gdb_packet_send_full(server, out, "E00");
                    }
                } else {
                    rv_gdb_packet_send_empty(server, out);
                }
            } else if (rv_gdb_packet_extract(server, "QStartNoAckMode")) {
                ack_packets = false;
                rv_gdb_packet_send_full(server, out, "OK");
            } else if (rv_gdb_packet_extract(server, "k")) {
                return;
            } else {
                rv_debug("Unimplemented packet: %.*s", (int)server->packet_size, server->packet_buf);
                rv_gdb_packet_send_empty(server, out);
            }
            break;
        }
    }
}

void rv_gdb_destroy(rv_GDBServer *server) {
    free(server);
}

