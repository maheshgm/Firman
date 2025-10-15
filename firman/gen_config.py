from .util import *
from .mem_color import *
from .instr_tracker import *

import logging
import json
import os


logger = logging.getLogger("gen_config")
logger.setLevel(logging.DEBUG)


def find_base_addr_elf(elf):
    base_address = None
    for segment in elf.iter_segments():
        if segment["p_type"] == "PT_LOAD":
            vaddr = segment["p_vaddr"]
            if base_address is None or vaddr < base_address:
                base_address = vaddr

    return base_address



def recover_isr_table(filepath):
    proj = load_arm_project(filepath)
    cfg = proj.analyses.CFGFast()
    isr_table = {}
    func_db = cfg.kb.functions.items()
    func_db = sorted(func_db, key=lambda x: x[1].addr)
    end_addr = None
    for func in func_db:
        # check if the function starts with a push instruction
        first_instr = list(func[1].blocks)[0].capstone.insns[0]
        if first_instr.mnemonic == "push":
            end_addr = func[0]
            break

    base_addr = proj.loader.main_object.mapped_base
    for addr in range(base_addr, end_addr, 4):
        isr_table[addr] = bytes2int(proj.loader.memory.load(addr, 4))

    return isr_table


def write_addr(filename, addrs):
    with open(filename, "w") as file:
        for addr in addrs:
            file.write(hex(addr[0]) + ":" + hex(addr[1]) + "\n")
    logger.info(f"Addresses written to {filename}")


def gen_config(filepath):
    config = {
        "name": filepath,
        "base_dir": os.path.dirname(filepath),
    }
    if check_elf(filepath):
        with open(filepath, "rb") as f:
            elffile = ELFFile(f)
            config["base_addr"] = hex(find_base_addr_elf(elffile))
#            config["code_low"] = config["base_addr"]
#            config["code_high"] = hex(int(config["base_addr"], 16) + 0x200000)
            config["entry"] = hex(elffile.header.e_entry)
            #setup default interrupt trigger values
            
            config["bb_limit_intr"] = 2000
            config["bb_limit_systick"] = 5000
            
            #setup exits
            config["exits"] = []
    else:
        logger.info(f"ELF file not found!! Assuming bin file")
        base_addr = get_base_addr(filepath)
        logger.info(f"Found Base addresses: {base_addr}")
        logger.info(f"Choosing base address: {base_addr[0]}")
        config["base_addr"] = base_addr[0]
        config["entry"] = hex(get_entry(filepath)[0])

    config["code_low"] = config["base_addr"]
    config["code_high"] = hex(int(config["base_addr"], 16) + 0x200000)
    config["bb_limit_intr"] = 2000
    config["bb_limit_systick"] = 5000
    
    config["grammar_file"] = config["base_dir"] + "/" + os.path.basename(filepath).split(".")[0] + ".json"
    
    instr_track = InstructionTracker(filepath, config["grammar_file"])
    instr_track.build_mmio_ops()
    instr_track.write_to_file()
    
    config["unique_name"] = os.path.basename(filepath).split(".")[0]
    
    logger.info(f"Grammar file generated at {config['grammar_file']}")

    config["rules_file"] = (
        config["base_dir"] + "/" + os.path.basename(filepath).split(".")[0] + ".info"
    )
    global_addrs, mmio_addrs = extract_global_addrs(filepath, config["rules_file"], instr_track.glob_start, instr_track.glob_size)
    write_addr(config["rules_file"], global_addrs)
    isr_table = recover_isr_table(filepath)
    isr_numbers = []
    base_addr = int(config["base_addr"], 16)
    for addr in list(isr_table.keys())[16:]:
        if isr_table[addr] != 0:
            isr_numbers.append(hex((addr - base_addr) // 4))

    config["int_list"] = isr_numbers

    with open("config.json", "w") as f:
        json.dump(config, f, indent=4)
    logger.info(f"Config file generated")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate configuration for binary analysis"
    )
    parser.add_argument("filepath", type=str, help="Path to the binary file")
    args = parser.parse_args()

    if not os.path.exists(args.filepath):
        logger.error(f"File {args.filepath} does not exist.")
        exit(1)

    gen_config(args.filepath)
