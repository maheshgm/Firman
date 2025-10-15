import angr
import logging
import argparse
from capstone.arm import *
import struct
import sys
from .util import *

logger = logging.getLogger("mem_color")
logger.setLevel(logging.DEBUG)


def read_mem_val(proj, addr, size):
    b_state = proj.factory.blank_state()
    mem_val = b_state.memory.load(addr, size)
    mem_val = b_state.solver.eval(mem_val, cast_to=bytes)
    return int.from_bytes(mem_val, byteorder="little")


def check_global(addr, start, size):
    return addr > start and addr < start + size
    # return addr > 0x20070000 and addr < 0x20070000 + 0x40000


def check_mmio(addr):
    return addr > 0x4000_0000 and addr < 0x50000000


def write_addr(filename, addrs):
    with open(filename, "w") as file:
        for addr in addrs:
            file.write(hex(addr[0]) + ":" + hex(addr[1]))
    print(f"Addresses written to {filename}")


def extract_global_addrs(binary, info_file, start, size):
    proj = load_arm_project(binary)
    cfg = proj.analyses.CFGFast()
    global_addrs = []
    mmio_addrs = []
    # for func in cfg.kb.functions.values():
    # func = cfg.kb.functions['_start']

    for func in cfg.kb.functions.values():
        logger.info(f"Analyzing function at {hex(func.addr)}: {func.name}")
        for block in func.blocks:
            for insn in block.capstone.insns:
                if insn.id in [
                    ARM_INS_LDR,
                    ARM_INS_LDRB,
                    ARM_INS_LDRH,
                    ARM_INS_LDRSB,
                    ARM_INS_LDRSH,
                ]:
                    for op in insn.operands:
                        if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
                            offset = op.mem.disp
                            pc_value = insn.address + insn.size
                            addr = pc_value + offset - 1
                            # print(hex(pc_value), hex(offset), hex(global_addr), hex(insn.size))
                            target_addr = read_mem_val(proj, addr, 4)
                            if check_global(target_addr, start, size):
                                global_addrs.append((insn.address, target_addr))
                                logger.debug(
                                    "Found global address : " + hex(target_addr)
                                )
                            if check_mmio(target_addr):
                                mmio_addrs.append((insn.address, target_addr))
                                logger.debug("Found MMIO address : " + hex(target_addr))
        # break
    return sorted(global_addrs), sorted(mmio_addrs)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Parse a binary file and extract global or MMIO addresses."
    )

    parser.add_argument("binary", type=str, help="Path to the binary file")

    parser.add_argument(
        "-g",
        "--global",
        dest="global_addr",
        action="store_true",
        help="Extract global addresses from the binary",
    )
    parser.add_argument(
        "-m",
        "--mmio",
        dest="mmio_addr",
        action="store_true",
        help="Extract MMIO addresses from the binary",
    )
    parser.add_argument(
        "-f",
        "--save-file",
        type=str,
        dest="file_name",
        help="File to save the extracted addresses",
    )

    args = parser.parse_args()

    # if not args.global_addr and not args.mmio_addr:
    #     parser.error("At least one of --global or --mmio must be specified.")

    return args


if __name__ == "__main__":
    parser = parse_args()
    glob, mmio = extract_global_addrs(parser.binary, parser.file_name)
    if parser.global_addr:
        write_addr(parser.file_name, glob)
    elif parser.mmio_addr:
        write_addr(parser.file_name, mmio)
    else:
        pass
