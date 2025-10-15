from .util import *
import angr
import archinfo


ARCH = archinfo.ArchARMCortexM()
PC = ARCH.registers['pc'][0]
LR = ARCH.registers['lr'][0]

def get_reg_value(reg):
    return ARCH.registers[reg][0]

def get_reg_values(actions):
    reg_values = {}
    for action in actions:
        if action.type == 'reg':
            reg_offset = action.offset
            if reg_offset == PC or reg_offset == LR:
                continue
            reg_value = action.data
            if reg_value.symbolic:
                continue
            reg_value = reg_value.ast.concrete_value
            op_type = action.action
            reg_values[reg_offset] = (op_type, reg_value, action.ins_addr)
    return reg_values
def get_mem_values(actions):
    mem_values = {}
    for action in actions:
        if action.type == 'mem':
            mem_offset = action.addr
            if mem_offset.symbolic:
                continue
            mem_offset = mem_offset.ast.concrete_value
            mem_value = action.data
            if mem_value.symbolic:
                continue
            mem_value = mem_value.ast.concrete_value
            op_type = action.action
            mem_values[mem_offset] = (op_type, mem_value, action.ins_addr)
    return mem_values

if __name__ == "__main__":
    import argparse
    import logging

    parser = argparse.ArgumentParser(description="Summarize function behavior in a binary.")
    parser.add_argument("project_path", help="Path to the project directory")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    proj = load_arm_project(args.project_path)
    cfg = proj.analyses.CFGFast()
    logger.info(f"Loaded project: {args.project_path}")
    
    state = proj.factory.blank_state(addr=0x99d, add_options = {
                angr.options.UNICORN,
                angr.options.UNICORN_SYM_REGS_SUPPORT,
                # angr.options.FAST_MEMORY,
                # angr.options.FAST_REGISTERS,
                angr.options.OPTIMIZE_IR,
                angr.options.CONCRETIZE,
                angr.options.LAZY_SOLVES,
                angr.options.EFFICIENT_STATE_MERGING,
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                angr.options.TRACK_MEMORY_ACTIONS,
                angr.options.TRACK_REGISTER_ACTIONS,
                angr.options.TRACK_ACTION_HISTORY
    })
    sm = proj.factory.simulation_manager(state)
    sm.step()
    active_state = sm.active[0]
    vals = get_mem_values(active_state.history.actions)
    for v in vals:
        print(f"Memory {hex(v)}: {vals[v]}")
    # for action in active_state.history.actions:
    #     print(action)
    #     print(action.__dict__)
    #     break