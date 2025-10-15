from .summarizer import *
import struct
from .stmt_parser import *
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
missed_funcs = []

class InstructionTracker:
    def __init__(self, firmware_path, grammar_file):
        self.summarizer = Summarizer(firmware_path)
        self.summarizer.build_summary()
        
        self.mmio_db = self.summarizer.mmio_db
        self.global_kb = self.summarizer.global_kb
        self.project = self.summarizer.project
        self.cfg = self.summarizer.cfg
        self.final_action_kb = self.summarizer.final_action_kb
        self.glob_ops = {}
        self.grammar_file = grammar_file
        self.mmio_ops = {}
        self.glob_start = 0x2000_0000
        self.glob_size = 0x10000
    
    def write_regs_to_state(self, state, regs):
        for reg in regs:
            if reg == None:
                continue
            if regs[reg] == None:
                continue
            value = regs[reg][1]
            if type(value) == float:
                try:
                    packed = struct.pack("<f", value)
                    int_val = struct.unpack("<I", packed)[0] 
                    value = claripy.BVV(int_val, 32)
                except Exception as e:
                    packed = struct.pack("<d", value)
                    int_val = struct.unpack("<Q", packed)[0]
                    value = claripy.BVV(int_val, 64)
                
            state.registers.store(reg, value)
        return state

    def build_tmp_kb(self, func_addr, bb_addr):
        if func_addr not in self.final_action_kb:
            missed_funcs.append(func_addr)
            return None
        logger.info(f"Processing func_addr {hex(func_addr)}")
        for context in self.final_action_kb[func_addr]:
            if bb_addr in self.final_action_kb[func_addr][context]:
                preds = self.cfg.model.get_any_node(bb_addr).predecessors
                for pred in preds:
                    pred_regs = self.final_action_kb[func_addr][context][bb_addr]["regs"]
                    
                    state = self.project.factory.blank_state(
                        addr=bb_addr,
                        add_options={
                            angr.options.TRACK_ACTION_HISTORY,
                            angr.options.TRACK_TMP_ACTIONS
                        }
                    )
                    state = self.write_regs_to_state(state, pred_regs)
                    state.inspect.b("expr", when=angr.BP_AFTER, action= self.parse_state_hook)
                    sm = self.project.factory.simgr(state)
                    sm.run(n=1)

    def parse_state_hook(self, state):
        # target = state.inspect.tmp_write_expr
        
        # if target == None:
        #     return     
        
        # # parse the children asts to 
        # if len(target.variables) != 0:
        #     for var in target.variables:
        #         ops = var.split("_")
        #         if len(ops) < 2:
        #             continue
        #         if ops[0] == "mem" and self.summarizer.check_mmio(int(ops[1], 16)): 
        #             mmio_addr = int(ops[1], 16)
        #             mask = None
        #             try:
        #                 mask = self.analyze_bitwise_effect(target)
        #                 if mmio_addr not in self.mmio_ops:
        #                     self.mmio_ops[mmio_addr] = {}
        #                 self.generate_bitfield(mmio_addr, state.addr, mask)
        #             except Exception as e:
        #                 pass
        #         if ops[0] == "mem" and self.summarizer.check_global_addr(int(ops[1], 16)):
        #             glob_addr = int(ops[1], 16)
        #             self.glob_ops[glob_addr] = target
        target = state.inspect.tmp_write_expr
        if target == None:
            return 
        if len(target.variables) != 0:
            for var in target.variables:
                ops = var.split("_")
                if len(ops) < 2:
                    continue
                if ops[0] == "mem" and self.summarizer.check_mmio(int(ops[1], 16)):
                    mmio_addr = int(ops[1], 16)
                    mask = None
                    try:
                        mask = self.analyze_bitwise_effect(target)
                        if mmio_addr not in self.mmio_ops:
                            self.mmio_ops[mmio_addr] = [4, {"BitField": mask}]
                    except Exception as e:
                        pass

    def generate_bitfield(self, mmio_addr, bb_addr, mask):
        self.mmio_ops[mmio_addr][bb_addr] = [4, {"BitField": mask}]
    
    def generate_pc_indexed(self, mmio_addr, mask):
        pass

    def generate_choice(self, mmio_addr, val):
        pass

    def generate_range(self, mmio_addr, low, high):
        pass
    
    def generate_composite(self):
        pass
    
    def analyze_bitwise_effect(self, expr):
        if expr.op not in ('__and__', '__or__'):
            raise ValueError("Only AND and OR operations are supported")

        # Identify the symbolic and constant arguments
        sym_arg = None
        const_arg = None
        for arg in expr.args:
            if isinstance(arg, claripy.ast.BV):
                if arg.symbolic:
                    sym_arg = arg
                elif arg.concrete:
                    const_arg = arg

        if sym_arg is None or const_arg is None:
            raise ValueError("Expression must contain one symbolic and one concrete operand")

        op = expr.op
        mask = const_arg.args[0]
        size = sym_arg.length

        pattern = ""
        for i in reversed(range(size)):
            bit = (mask >> i) & 1
            if op == '__and__':
                if bit == 0:
                    pattern += "0"  # force to 0
                else:
                    pattern += "x"  # unaffected
            elif op == '__or__':
                if bit == 1:
                    pattern += "1"  # force to 1
                else:
                    pattern += "x"  # unaffected
        return pattern
    
    def build_mmio_ops(self):
        for addr, mmio in self.mmio_db.items():
            func_addr = self.cfg.model.get_any_node(addr).function_address
            self.build_tmp_kb(func_addr, addr)
    
    def convert_sets(self, obj):
        if isinstance(obj, set):
            return list(obj)
        elif isinstance(obj, dict):
            return {k: self.convert_sets(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self.convert_sets(i) for i in obj]
        else:
            return obj
    def write_to_file(self):
        """
        Write the summary of actions to a json file.
        """
        import json
        output_file = self.grammar_file
        with open(output_file , 'w') as f:
            json.dump(self.convert_sets(self.mmio_ops), f, indent=4)
        logger.info(f"Summary written to {output_file}") 
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Summarize firmware functions.")
    parser.add_argument("project_path", help="Path to the firmware project file.")
    args = parser.parse_args()
    
    instr_track = InstructionTracker(args.project_path, "mmio_ops.json")
    instr_track.build_mmio_ops()
    instr_track.write_to_file()
    print(missed_funcs)
    import ipdb; ipdb.set_trace()
    