#include "exec.h"

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "decoder.h"
#include "logger.h"

static void rv_dump_instruction(rv_DecodedInst inst) {
    assert(RV_DECODED_GET_STATUS(&inst) == RV_DECODE_STATUS_SUCCESS);
    rv_debug("%s %d-bits", rv_inst_names[RV_DECODED_GET_OPCODE(&inst)], RV_DECODED_GET_LENGTH_BITS(&inst));
    if (RV_DECODED_HAS_RD(&inst))
        rv_debug("    rd:  x%d %s", RV_DECODED_GET_RD(&inst), rv_register_names[RV_DECODED_GET_RD(&inst)]);
    if (RV_DECODED_HAS_RS1(&inst))
        rv_debug("    rs1: x%d %s", RV_DECODED_GET_RS1(&inst), rv_register_names[RV_DECODED_GET_RS1(&inst)]);
    if (RV_DECODED_HAS_RS2(&inst))
        rv_debug("    rs2: x%d %s", RV_DECODED_GET_RS2(&inst), rv_register_names[RV_DECODED_GET_RS2(&inst)]);
    if (RV_DECODED_HAS_RS3(&inst))
        rv_debug("    rs3: x%d %s", RV_DECODED_GET_RS3(&inst), rv_register_names[RV_DECODED_GET_RS3(&inst)]);
    if (RV_DECODED_HAS_IMM(&inst))
        rv_debug("    imm: %0" RV_PRIx_PADDED, inst.imm);
}

bool rv_handle_trap(rv_Environment *env, rv_Hart *hart, rv_Trap trap) {
    if (trap == RV_TRAP_SUCCESS)
        return true;
    return false;
}

rv_Trap rv_exec_inst(rv_Environment *, rv_Hart *, rv_DecodedInst);

rv_Trap rv_run(rv_Environment *env, rv_Hart *hart) {
    rv_Trap trap;
    do {
        trap = rv_step(env, hart);
    } while (trap == RV_TRAP_SUCCESS);
    return trap;
}

rv_Trap rv_step(rv_Environment *env, rv_Hart *hart) {
    rv_MemoryDevice *mem = rv_memory_resolve(env, hart->pc);
    if (mem == NULL) {
        rv_warn("Failed to resolve address 0x%0" RV_PRIx_PADDED, hart->pc);
        return RV_TRAP_PAGE_FAULT;
    }

    if (!(mem->flags & RV_MEMORY_EXECUTE)) {
        rv_warn("Address 0x%0" RV_PRIx_PADDED " not executable", hart->pc);
        return RV_TRAP_PAGE_FAULT;
    }

    size_t pc_offset = hart->pc - mem->address;
    rv_DecodedInst inst = rv_inst_decode((char*)mem->data + pc_offset, mem->size - pc_offset);
    assert(RV_DECODED_GET_STATUS(&inst) != RV_DECODE_STATUS_NEED_MORE_DATA);

    rv_Trap res = rv_exec_inst(env, hart, inst);
    switch (res) {
    case RV_TRAP_SUCCESS:
    case RV_TRAP_UNIMPLEMENTED:
        return res;
    case RV_TRAP_ILLEGAL_INSTRUCTION:
        rv_error("Illegal Instruction");
        return RV_TRAP_ILLEGAL_INSTRUCTION;
    case RV_TRAP_PAGE_FAULT:
        rv_error("Page Fault");
        rv_dump_instruction(inst);
        rv_dump_hart(hart);
        return RV_TRAP_PAGE_FAULT;
    case RV_TRAP_EBREAK:
        return RV_TRAP_EBREAK;
    }
    abort();
}

#define RV_SIGN_EXTEND_8(value) rv_sign_extend(value, 7)
#define RV_SIGN_EXTEND_16(value) rv_sign_extend(value, 15)
#if RV_XLEN >= 64
#define RV_SIGN_EXTEND_32(value) rv_sign_extend(value, 31)
#define RV_SIGN_EXTEND_64(value) (value)
#else
#define RV_SIGN_EXTEND_32(value) (value)
#endif

#define RV_LOW_32 (rv_UInt)0xffffffffu

#define RV_REGISTER_VAL(hart, reg) ((reg) == 0 ? (rv_UInt)0 : (hart)->x[(reg) - 1])
#define RV_REGISTER_REF(hart, reg) *((reg) == 0 ? &(rv_UInt){0} : &(hart)->x[(reg) - 1])

rv_Trap rv_exec_inst(rv_Environment *env, rv_Hart *hart, rv_DecodedInst inst) {
    switch (RV_DECODED_GET_STATUS(&inst)) {
    case RV_DECODE_STATUS_INVALID_OPCODE:
    case RV_DECODE_STATUS_INVALID_SIZE:
        return RV_TRAP_ILLEGAL_INSTRUCTION;
    case RV_DECODE_STATUS_NEED_MORE_DATA:
        abort(); // FIXME: Return an error instead of abort
    case RV_DECODE_STATUS_SUCCESS:
        break;
    }

#define RV_RD RV_REGISTER_REF(hart, RV_DECODED_GET_RD(&inst))
#define RV_RS1 RV_REGISTER_VAL(hart, RV_DECODED_GET_RS1(&inst))
#define RV_RS2 RV_REGISTER_VAL(hart, RV_DECODED_GET_RS2(&inst))
#define RV_IMM RV_DECODED_GET_IMM(&inst)

#define RV_LOAD(target, address, bytes) \
        do { \
            if (!rv_memory_access(env, &(target), (address), (bytes), RV_MEMORY_CALLBACK_READ)) \
                return RV_TRAP_PAGE_FAULT; \
        } while (0)
#define RV_LOAD_S(target, address, bytes, sign_extender) \
        do { \
            static_assert((bytes) <= sizeof(rv_UInt), #bytes " > sizeof(rv_UInt)"); \
            rv_UInt tmp; \
            RV_LOAD(tmp, (address), (bytes)); \
            (target) = sign_extender(tmp); \
        } while (0)
#define RV_LOAD_U(target, address, bytes) \
        do { \
            static_assert((bytes) <= sizeof(rv_UInt), #bytes " > sizeof(rv_UInt)"); \
            rv_UInt tmp; \
            RV_LOAD(tmp, (address), (bytes)); \
            (target) = tmp; \
        } while (0)

#define RV_LOAD_8_S(dst, src) RV_LOAD_S(dst, src, 1, RV_SIGN_EXTEND_8)
#define RV_LOAD_16_S(dst, src) RV_LOAD_S(dst, src, 2, RV_SIGN_EXTEND_16)
#define RV_LOAD_32_S(dst, src) RV_LOAD_S(dst, src, 4, RV_SIGN_EXTEND_32)
#define RV_LOAD_8_U(dst, src) RV_LOAD_U(dst, src, 1)
#define RV_LOAD_16_U(dst, src) RV_LOAD_U(dst, src, 2)

#define RV_LOAD_64_S(dst, src) RV_LOAD_S(dst, src, 8, RV_SIGN_EXTEND_64)
#define RV_LOAD_32_U(dst, src) RV_LOAD_U(dst, src, 4)

#define RV_STORE(address, value, bytes) \
        do { \
            static_assert(bytes <= sizeof(rv_UInt), #bytes " > sizeof(rv_UInt)"); \
            rv_UInt tmp = (value); \
            if (!rv_memory_access(env, &tmp, (address), (bytes), RV_MEMORY_CALLBACK_WRITE))\
                return RV_TRAP_PAGE_FAULT; \
        } while (0)

#define RV_STORE_8(address, value) RV_STORE(address, value, 1)
#define RV_STORE_16(address, value) RV_STORE(address, value, 2)
#define RV_STORE_32(address, value) RV_STORE(address, value, 4)
#define RV_STORE_64(address, value) RV_STORE(address, value, 8)

    bool jumped = false;
    // FIXME: Check for instruction-address-misaligned
#define RV_BRANCH(offset) \
        do { \
            hart->pc += (offset); \
            jumped = true; \
        } while (0)
#define RV_BRANCH_IF(cond, offset) \
        do { \
            if ((cond)) \
                RV_BRANCH(offset); \
        } while (0)
#define RV_JUMP(address, return_register) \
        do { \
            rv_UInt address_ = (address); \
            (return_register) = hart->pc + RV_DECODED_GET_LENGTH_BYTES(&inst); \
            hart->pc = address_ & ~1; \
            jumped = true; \
        } while (0)

    switch (RV_DECODED_GET_OPCODE(&inst)) {
    case RV_INST_ADDI: RV_RD = RV_RS1 + RV_IMM; break;
    case RV_INST_SLTI: RV_RD = rv_signed_less_than(RV_RS1, RV_IMM); break;
    case RV_INST_SLTIU: RV_RD = RV_RS1 < RV_IMM; break;
    case RV_INST_ANDI: RV_RD = RV_RS1 & RV_IMM; break;
    case RV_INST_ORI: RV_RD = RV_RS1 | RV_IMM; break;
    case RV_INST_XORI: RV_RD = RV_RS1 ^ RV_IMM; break;
    case RV_INST_SLLI: RV_RD = RV_RS1 << RV_IMM; break;
    case RV_INST_SRLI: RV_RD = RV_RS1 >> RV_IMM; break;
    case RV_INST_SRAI: RV_RD = rv_sign_extend(RV_RS1 >> RV_IMM, (RV_XLEN - 1) - RV_IMM); break;
    case RV_INST_LUI: RV_RD = RV_IMM; break;
    case RV_INST_AUIPC: RV_RD = hart->pc + RV_IMM; break;

    case RV_INST_ADD: RV_RD = RV_RS1 + RV_RS2; break;
    case RV_INST_SUB: RV_RD = RV_RS1 - RV_RS2; break;
    case RV_INST_SLT: RV_RD = rv_signed_less_than(RV_RS1, RV_RS2); break;
    case RV_INST_SLTU: RV_RD = RV_RS1 < RV_RS2; break;
    case RV_INST_AND: RV_RD = RV_RS1 & RV_RS2; break;
    case RV_INST_OR: RV_RD = RV_RS1 | RV_RS2; break;
    case RV_INST_XOR: RV_RD = RV_RS1 ^ RV_RS2; break;
    case RV_INST_SLL: RV_RD = RV_RS1 << (RV_RS2 & (RV_XLEN - 1)); break;
    case RV_INST_SRL: RV_RD = RV_RS1 >> (RV_RS2 & (RV_XLEN - 1)); break;
    case RV_INST_SRA: RV_RD = rv_sign_extend(RV_RS1 >> (RV_RS2 & (RV_XLEN - 1)), (RV_XLEN - 1) - (RV_RS2 & (RV_XLEN - 1))); break;

    case RV_INST_JAL:  RV_JUMP(hart->pc + RV_IMM, RV_RD); break;
    case RV_INST_JALR: RV_JUMP(RV_RS1 + RV_IMM, RV_RD); break;

    case RV_INST_BEQ: RV_BRANCH_IF(RV_RS1 == RV_RS2, RV_IMM); break;
    case RV_INST_BNE: RV_BRANCH_IF(RV_RS1 != RV_RS2, RV_IMM); break;
    case RV_INST_BLT: RV_BRANCH_IF(rv_signed_less_than(RV_RS1, RV_RS2), RV_IMM); break;
    case RV_INST_BLTU: RV_BRANCH_IF(RV_RS1 < RV_RS2, RV_IMM); break;
    case RV_INST_BGE: RV_BRANCH_IF(!rv_signed_less_than(RV_RS1, RV_RS2), RV_IMM); break;
    case RV_INST_BGEU: RV_BRANCH_IF(RV_RS1 >= RV_RS2, RV_IMM); break;

    case RV_INST_LB: RV_LOAD_8_S(RV_RD, RV_RS1 + RV_IMM); break;
    case RV_INST_LH: RV_LOAD_16_S(RV_RD, RV_RS1 + RV_IMM); break;
    case RV_INST_LW: RV_LOAD_32_S(RV_RD, RV_RS1 + RV_IMM); break;
    case RV_INST_LBU: RV_LOAD_8_U(RV_RD, RV_RS1 + RV_IMM); break;
    case RV_INST_LHU: RV_LOAD_16_U(RV_RD, RV_RS1 + RV_IMM); break;

    case RV_INST_SB: RV_STORE_8(RV_RS1 + RV_IMM, RV_RS2); break;
    case RV_INST_SH: RV_STORE_16(RV_RS1 + RV_IMM, RV_RS2); break;
    case RV_INST_SW: RV_STORE_32(RV_RS1 + RV_IMM, RV_RS2); break;

    case RV_INST_FENCE: rv_warn("FIXME: Implement FENCE"); break;

    case RV_INST_ECALL: rv_error("FIXME: Implement ECALL"); break;
    case RV_INST_EBREAK: return RV_TRAP_EBREAK;

#if RV_XLEN >= 64
    case RV_INST_ADDIW: RV_RD = RV_SIGN_EXTEND_32(RV_RS1 + RV_IMM); break;
    case RV_INST_SLLIW: RV_RD = RV_SIGN_EXTEND_32((RV_RS1 & RV_LOW_32) << RV_IMM); break;
    case RV_INST_SRLIW: RV_RD = RV_SIGN_EXTEND_32((RV_RS1 & RV_LOW_32) >> RV_IMM); break;
    case RV_INST_SRAIW: RV_RD = rv_sign_extend(RV_RS1 >> RV_IMM, 31 - RV_IMM); break;

    case RV_INST_ADDW: RV_RD = RV_SIGN_EXTEND_32(RV_RS1 + RV_RS2); break;
    case RV_INST_SUBW: RV_RD = RV_SIGN_EXTEND_32(RV_RS1 - RV_RS2); break;
    case RV_INST_SLLW: RV_RD = RV_SIGN_EXTEND_32(RV_RS1 << (RV_RS2 & 0x1f)); break;
    case RV_INST_SRLW: RV_RD = RV_SIGN_EXTEND_32(RV_RS1 >> (RV_RS2 & 0x1f)); break;
    case RV_INST_SRAW: RV_RD = rv_sign_extend(RV_RS1 >> (RV_RS2 & 0x1f), 31 - (RV_RS2 & 0x1f)); break;

    case RV_INST_LD: RV_LOAD_64_S(RV_RD, RV_RS1 + RV_IMM); break;
    case RV_INST_LWU: RV_LOAD_32_U(RV_RD, RV_RS1 + RV_IMM); break;

    case RV_INST_SD: RV_STORE_64(RV_RS1 + RV_IMM, RV_RS2); break;
#endif

#if 0
    default:
        rv_dump_instruction(inst);
        rv_error("TODO: Unimplemented instruction %s", rv_inst_names[RV_DECODED_GET_OPCODE(&inst)]);
        return RV_TRAP_UNIMPLEMENTED;
#endif
    }

    if (!jumped) {
        hart->pc += RV_DECODED_GET_LENGTH_BYTES(&inst);
    }
    return RV_TRAP_SUCCESS;
}

