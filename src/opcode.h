#include <assert.h>

#define RV_EXTRACT_OPCODE(inst) (((inst) & 0x7f) >> 2)

typedef enum rv_Opcode {
    RV_OPCODE_LOAD,
    RV_OPCODE_LOAD_FP,
    RV_OPCODE_CUSTOM_0,
    RV_OPCODE_MISC_MEM,
    RV_OPCODE_OP_IMM,
    RV_OPCODE_AUIPC,
    RV_OPCODE_OP_IMM_32,
    RV_OPCODE_B48_0,

    RV_OPCODE_STORE,
    RV_OCPDOE_STORE_FP,
    RV_OPCODE_CUSTOM_1,
    RV_OPCODE_AMO,
    RV_OPCODE_OP,
    RV_OPCODE_LUI,
    RV_OPCODE_OP_32,
    RV_OPCODE_B64,

    RV_OPCODE_MADD,
    RV_OPCODE_MSUB,
    RV_OPCODE_NMSUB,
    RV_OPCODE_NMADD,
    RV_OPCODE_OP_FP,
    RV_OPCODE_RESERVED_0,
    RV_OPCODE_CUSTOM_2, // NOTE: Reserved on RV128
    RV_OPCODE_B48_1,

    RV_OPCODE_BRANCH,
    RV_OPCODE_JALR,
    RV_OPCODE_RESERVED_1,
    RV_OPCODE_JAL,
    RV_OPCODE_SYSTEM,
    RV_OPCODE_RESERVED_2,
    RV_OPCODE_CUSTOM_3, // NOTE: Reserved on RV128
    RV_OPCODE_B80,

    RV_COUNT_OPCODES
} rv_Opcode;
static_assert(RV_COUNT_OPCODES == 32, "Invalid amount of values in rv_Opcode");

typedef enum rv_OpcodeLoad {
    RV_OPCODE_LOAD_FUNCT3_LB = 0,
    RV_OPCODE_LOAD_FUNCT3_LH = 1,
    RV_OPCODE_LOAD_FUNCT3_LW = 2,
    RV_OPCODE_LOAD_FUNCT3_LBU = 4,
    RV_OPCODE_LOAD_FUNCT3_LHU = 5,
} rv_OpcodeLoad;

typedef enum rv_OpcodeOpImm {
    RV_OPCODE_OP_IMM_FUNCT3_ADDI = 0,
    RV_OPCODE_OP_IMM_FUNCT3_SLTI = 2,
    RV_OPCODE_OP_IMM_FUNCT3_SLTIU = 3,
    RV_OPCODE_OP_IMM_FUNCT3_XORI = 4,
    RV_OPCODE_OP_IMM_FUNCT3_ORI = 6,
    RV_OPCODE_OP_IMM_FUNCT3_ANDI = 7,
} rv_OpcodeOpImm;

typedef enum rv_OpcodeStore {
    RV_OPCODE_STORE_FUNCT3_SB = 0,
    RV_OPCODE_STORE_FUNCT3_SH = 1,
    RV_OPCODE_STORE_FUNCT3_SW = 2,
} rv_OpcodeStore;

typedef enum rv_OpcodeOp {
    RV_OPCODE_OP_FUNCT3_ADD = 0,
    RV_OPCODE_OP_FUNCT3_SLL = 1,
    RV_OPCODE_OP_FUNCT3_SLT = 2,
    RV_OPCODE_OP_FUNCT3_SLTU = 3,
    RV_OPCODE_OP_FUNCT3_XOR = 4,
    RV_OPCODE_OP_FUNCT3_SRL = 5,
    RV_OPCODE_OP_FUNCT3_OR = 6,
    RV_OPCODE_OP_FUNCT3_AND = 7,
} rv_OpcodeOp;

typedef enum rv_OpcodeOpAdd {
    RV_OPCODE_OP_FUNCT3_ADD_FUNCT7_ADD = 0,
    RV_OPCODE_OP_FUNCT3_ADD_FUNCT7_SUB = 1 << 5,
} rv_OpcodeOpAdd;

typedef enum rv_OpcodeOpSrl {
    RV_OPCODE_OP_FUNCT3_SRL_FUNCT7_SRL = 0,
    RV_OPCODE_OP_FUNCT3_SRL_FUNCT7_SRA = 1 << 5,
} rv_OpcodeOpSrl;

typedef enum rv_OpcodeBranch {
    RV_OPCODE_BRANCH_FUNCT3_BEQ = 0,
    RV_OPCODE_BRANCH_FUNCT3_BNE = 1,
    RV_OPCODE_BRANCH_FUNCT3_BLT = 4,
    RV_OPCODE_BRANCH_FUNCT3_BGE = 5,
    RV_OPCODE_BRANCH_FUNCT3_BLTU = 6,
    RV_OPCODE_BRANCH_FUNCT3_BGEU = 7,
} rv_OpcodeBranch;

typedef enum rv_OpcodeJalr {
    RV_OPCODE_JALR_FUNCT3_JALR = 0,
} rv_OpcodeJalr;

