#!/bin/env python3

import argparse
import os
import sys
from pprint import pprint

def write_header(file, inst_table):
    print('#pragma once', file=file)
    print(file=file)
    print('enum rv_Inst {', file=file)
    inst_table = sorted(inst_table.items())
    for _, inst_list in inst_table:
        for inst in inst_list:
            print('  RV_INST_' + inst['name'].upper() + ',', file=file)
    print('};', file=file)
    print(file=file)
    print('extern const char *rv_inst_names[];', file=file)

FIELD_TARGETS = {
    'rd': (5, False),
    'rs1': (5, False),
    'rs2': (5, False),
    'imm': (32, True),
}

FIELD_TARGET_BITS = {
    'rd': 'rd',
    'rs1': 'rs1',
    'rs2': 'rs2',
    'imm20': ('imm', (31, 12)),
    'imm12': ('imm', (11, 0)),
    'imm12hi': ('imm', (11, 5)),
    'imm12lo': ('imm', (4, 0)),
    'bimm12hi': ('imm', 12, (10, 5)),
    'bimm12lo': ('imm', (4, 1), 11),
    'jimm20': ('imm', 20, (10, 1), 11, (19, 12)),
    'fm': ('imm', (11, 8), False),
    'pred': ('imm', (7, 4), False),
    'succ': ('imm', (3, 0), False),
    'shamtw': ('imm', (4, 0), False),
    'shamtd': ('imm', (5, 0), False),
}

def generate_field_table(arg_lut: dict) -> dict:
    def _extract(bits, offset = 0):
        offset = offset - bits[1]
        mask = (1 << (bits[0] + 1)) - 1
        mask &= ~((1 << bits[1]) - 1)
        if offset < 0:
            return f"(inst & 0x{mask:08x}) >> {-offset}"
        elif offset > 0:
            return f"(inst & 0x{mask:08x}) << {offset}"
        else:
            return f"(inst & 0x{mask:08x})"
    out = {}
    for source, target in FIELD_TARGET_BITS.items():
        source_bits = arg_lut[source]
        #print(f"{source} {source_bits} -> {target}")
        if isinstance(target, str):
            out[source] = {
                'target': target,
                'extractor': _extract(source_bits, 0),
                'target_mask': -1,
                'sign_extend': -1,
            }
        else:
            assert(isinstance(target, tuple))
            assert(len(target) > 1)
            extractors = []
            source_offset = 0
            target_mask = 0
            target_top_bit = 0
            sign_extend = None
            for target_bits in target[1:]:
                if isinstance(target_bits, bool):
                    assert(sign_extend is None or sign_extend == target_bits)
                    sign_extend = target_bits
                    continue
                if isinstance(target_bits, int):
                    target_bits = (target_bits, target_bits)

                if target_bits[0] > target_top_bit:
                    target_top_bit = target_bits[0]

                bit_count = 1 + target_bits[0] - target_bits[1]
                source_high = source_bits[0] - source_offset
                source_low = source_high - bit_count + 1
                extractors.append(_extract((source_high, source_low), target_bits[1]))
                source_offset += bit_count
                target_mask |= (1 << bit_count) - 1 << target_bits[1]
            assert(source_offset == 1 + source_bits[0] - source_bits[1])

            if sign_extend is None:
                sign_extend = FIELD_TARGETS[target[0]][1]
            out[source] = {
                'target': target[0],
                'extractor': ' | '.join(extractors),
                'target_mask': target_mask,
                'sign_extend': target_top_bit if sign_extend else -1,
            }
    return out

def _write_decoder(file, inst_list, field_table):
    for inst in inst_list:
        #pprint(inst)
        print(f'    if ((inst & {inst["mask"]}) == {inst["match"]})', file=file)
        masks = {'rd': 0, 'rs1': 0, 'rs2': 0, 'imm': 0}
        extractors = {key: [] for key in masks}
        extends = {key: None for key in masks}
        for field in inst['variable_fields']:
            target_info = field_table[field]
            target = target_info['target']
            mask = target_info['target_mask']
            assert((masks[target] & mask) == 0)
            masks[target] |= mask
            extractors[target].append(target_info['extractor'])
            extend = target_info['sign_extend']
            if extends[target] is None:
                extends[target] = extend
            elif extend < 0 or extends[target] < 0:
                assert(extend < 0)
                assert(extends[target] < 0)
            else:
                extends[target] = max(extend, extends[target])
        print(f'      return (rv_DecodedInst) {{ .status = RV_DECODE_STATUS_SUCCESS, .length = {len(inst["encoding"]) // 16 - 1},', file=file)
        fields = " | ".join(["RV_DECODE_FIELD_" + x.upper() for x, y in extractors.items() if y])
        if fields:
            print(f'                                .fields = {fields},', file=file)
        for field, extractor in extractors.items():
            if extractor:
                extractor = ' | '.join(extractor)
                if extends[field] >= 0:
                    extractor = f'((rv_UInt)({extractor}) ^ 0x{1 << extends[field]:x}) - 0x{1 << extends[field]:x}'
                print(f'                                .{field} = {extractor},', file=file)
        print(f'                                .opcode = RV_INST_{inst["name"].upper() } }};', file=file)

def write_source(file, inst_table, field_table):
    assert(32 in inst_table)
    print('#include <assert.h>', file=file)
    print('#include "decoder.h"', file=file)
    print('#include "inst.h"', file=file)
    print(file=file)
    print('const char *rv_inst_names[] = {', file=file)
    for inst_list in inst_table.values():
        for inst in inst_list:
            print(f'  [RV_INST_{inst["name"].upper()}] = "{inst["name"].upper().replace("_", ".")}",', file=file)
    print('};', file=file)
    print(file=file)
    print('rv_DecodedInst rv_inst_decode(void *ptr_, size_t max_length) {', file=file)
    print('  if (max_length < 2)', file=file)
    print('    return (rv_DecodedInst) { .status = RV_DECODE_STATUS_NEED_MORE_DATA, .length = 0 };', file=file)
    print('  uint8_t *ptr = ptr_;', file=file)
    print('  uint32_t inst = ptr[0] | ptr[1] << 8;', file=file)
    print('  if ((inst & 3) != 3) {', file=file)
    if 16 in inst_table:
        _write_decoder(file, inst_table[16], field_table)
    else:
        print('    return (rv_DecodedInst) { .status = RV_DECODE_STATUS_INVALID_OPCODE, .length = 0 };', file=file)
    print('  }', file=file)
    print(file=file)
    print('  if (max_length < 4)', file=file)
    print('    return (rv_DecodedInst) { .status = RV_DECODE_STATUS_NEED_MORE_DATA, .length = 1 };', file=file)
    print('  inst |= ptr[2] << 16 | (uint32_t)ptr[3] << 24;', file=file)
    print('  if ((inst & 0x1f) != 0x1f) {', file=file)
    _write_decoder(file, inst_table[32], field_table)
    print('  }', file=file)
    print(file=file)
    print('  if ((inst & 0x3f) == 0x1f)', file=file)
    print('    return (rv_DecodedInst) { .status = RV_DECODE_STATUS_INVALID_OPCODE, .length = 2 };', file=file)
    print('  if ((inst & 0x7f) == 0x3f)', file=file)
    print('    return (rv_DecodedInst) { .status = RV_DECODE_STATUS_INVALID_OPCODE, .length = 3 };', file=file)
    print('  if ((inst & 0x707f) != 0x707f)', file=file)
    print('    return (rv_DecodedInst) { .status = RV_DECODE_STATUS_INVALID_OPCODE, .length = 4 + ((inst & 0x7000) >> 12) };', file=file)
    print('  return (rv_DecodedInst) { .status = RV_DECODE_STATUS_INVALID_SIZE, .length = 11 };', file=file)
    print('}', file=file)

    for bits in inst_table:
        assert(bits in (16, 32))

def main():
    argp = argparse.ArgumentParser()
    argp.add_argument('-I', dest='xlen', metavar='XLEN', type=int, choices=(32, 64), default=32)
    argp.add_argument('-s', dest='source', metavar='OUTPUT_C', type=str)
    argp.add_argument('-i', dest='header', metavar='OUTPUT_H', type=str)
    argp.add_argument('-o', dest='opcodes_dir', metavar='RISCV_OPCODES', type=str, required=True)
    args = argp.parse_args()

    extensions = ['i']
    xlen = args.xlen
    RISCV_OPCODES_PATH = args.opcodes_dir

    # TODO: Support rv_x_y files?
    # TODO: unratified?
    ext_files = []
    for ext in extensions:
        ext_file = f'rv_{ext}'
        if not os.path.exists(os.path.join(RISCV_OPCODES_PATH, ext_file)):
            print(f"rv_{ext} not found")
            exit(1)
        ext_files.append(ext_file)
        ext_file = f'rv{xlen}_{ext}'
        if os.path.exists(os.path.join(RISCV_OPCODES_PATH, ext_file)):
            ext_files.append(ext_file)

    old_cwd = os.getcwd()
    os.chdir(RISCV_OPCODES_PATH)
    sys.path.insert(0, RISCV_OPCODES_PATH)
    import parse

    instr_dict = parse.create_inst_dict(ext_files, False)
    inst_table = {}
    for name, info in instr_dict.items():
        bits = len(info['encoding'])
        if bits not in inst_table:
            inst_table[bits] = []
        info['name'] = name
        inst_table[bits].append(info)

    field_table = generate_field_table(parse.arg_lut)

    os.chdir(old_cwd)

    if args.header:
        os.makedirs(os.path.dirname(args.header), exist_ok=True)
        with open(args.header, 'w') as header_file:
            write_header(header_file, inst_table)
    if args.source:
        os.makedirs(os.path.dirname(args.source), exist_ok=True)
        with open(args.source, 'w') as source_file:
            write_source(source_file, inst_table, field_table)

if __name__ == '__main__':
    main()

