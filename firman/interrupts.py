import argparse
from util import *
from summarizer import *

GLOB_DB = None

def rev_db(db):
    rev_db = {}
    for bb_addr in db:
        for mmio_access in db[bb_addr]:
            op, addr, val = mmio_access
            if addr in rev_db:
                rev_db[addr].append((bb_addr, op))
            else:
                rev_db[addr] = [(bb_addr, op)]
    return rev_db

def recover_isr_table(proj, cfg):
    ISR_TABLE = {}
    mem = proj.loader.memory
    base_addr = proj.loader.main_object.mapped_base
    for i in range(1, 496):
        isr_addr = int.from_bytes(
            proj.loader.memory.load(base_addr + i*4, 4),
            byteorder='little'
        )
        if isr_addr == 0 or (isr_addr) in cfg.kb.functions:
            ISR_TABLE[i] = isr_addr
        else:
            break
    return ISR_TABLE

def filter_ISRs(proj, cfg, global_db=None):
    ISR_TABLE = recover_isr_table(proj, cfg)
    
    global_kd_rev = rev_db(GLOB_DB)
    
    for func_addr in ISR_TABLE.values():
        if func_addr == 0:
            continue
        for bb in cfg.kb.functions[func_addr].blocks:
            if bb.addr in GLOB_DB:
                print("-"*10, hex(func_addr), " | ", hex(bb.addr), "-"*10)
                entry = GLOB_DB[bb.addr]
                rev_entry = global_kd_rev[entry[0][1]]
                print(entry,"\n", rev_entry)

    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Recover ISR table from binary")
    parser.add_argument("binary", help="Path to the binary file")
    args = parser.parse_args()

    # proj = load_arm_project(args.binary)  # Load the project using a suitable method, e.g., angr.Project(args.binary)
    # cfg = proj.analyses.CFGFast(normalize=True)
    
    
    # from pprint import pprint as print
    #isr_table = recover_isr_table(proj, cfg)
    
    summarizer = Summarizer(args.binary)
    summarizer.build_bb_action_kb()
    summarizer.build_arg_graph()
    summarizer.build_final_action_kb()
    summarizer.build_kb_from_action(build_global=False)
    summarizer.build_kb_from_action(build_global=True)

    GLOB_DB = summarizer.global_kb
    filter_ISRs(proj, cfg)
    
    