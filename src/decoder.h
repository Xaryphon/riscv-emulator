#pragma once

#include <stddef.h>
#include <stdint.h>

#include "environment.h"
#include "inst.h"

typedef enum rv_Inst rv_Inst;

typedef enum rv_DecodeStatus {
    RV_DECODE_STATUS_SUCCESS,
    RV_DECODE_STATUS_INVALID_OPCODE,
    RV_DECODE_STATUS_NEED_MORE_DATA,
    RV_DECODE_STATUS_INVALID_SIZE,
} rv_DecodeStatus;

#define RV_DECODE_FIELD_RD 0x1
#define RV_DECODE_FIELD_RS1 0x2
#define RV_DECODE_FIELD_RS2 0x4
#define RV_DECODE_FIELD_RS3 0x8
#define RV_DECODE_FIELD_IMM 0x10

typedef struct rv_DecodedInst {
    unsigned status : 2;
    unsigned length : 5;
    unsigned fields : 5;
    unsigned rd : 5;
    unsigned rs1 : 5;
    unsigned rs2 : 5;
    unsigned rs3 : 5;
    rv_UInt imm;
    rv_Inst opcode;
} rv_DecodedInst;

#define RV_DECODED_GET_STATUS(decoded) ((rv_DecodeStatus)(decoded)->status)
#define RV_DECODED_GET_OPCODE(decoded) ((decoded)->opcode)

#define RV_DECODED_GET_LENGTH_RAW(decoded) ((decoded)->length)
#define RV_DECODED_GET_LENGTH(decoded) (RV_DECODED_GET_LENGTH_RAW(decoded) + 1)
#define RV_DECODED_GET_LENGTH_BYTES(decoded) (2 * RV_DECODED_GET_LENGTH(decoded))
#define RV_DECODED_GET_LENGTH_BITS(decoded) (8 * RV_DECODED_GET_LENGTH_BYTES(decoded))

#define RV_DECODED_HAS_RD(decoded) ((decoded)->fields & RV_DECODE_FIELD_RD)
#define RV_DECODED_HAS_RS1(decoded) ((decoded)->fields & RV_DECODE_FIELD_RS1)
#define RV_DECODED_HAS_RS2(decoded) ((decoded)->fields & RV_DECODE_FIELD_RS2)
#define RV_DECODED_HAS_RS3(decoded) ((decoded)->fields & RV_DECODE_FIELD_RS3)
#define RV_DECODED_HAS_IMM(decoded) ((decoded)->fields & RV_DECODE_FIELD_IMM)

#define RV_DECODED_GET_RD(decoded) ((decoded)->rd)
#define RV_DECODED_GET_RS1(decoded) ((decoded)->rs1)
#define RV_DECODED_GET_RS2(decoded) ((decoded)->rs2)
#define RV_DECODED_GET_RS3(decoded) ((decoded)->rs3)
#define RV_DECODED_GET_IMM(decoded) ((decoded)->imm)

rv_DecodedInst rv_inst_decode(void *ptr, size_t max_length);

