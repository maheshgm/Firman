import angr
import logging
from .util import *
import networkx as nx
from .action_util import *
import claripy
import struct

ops = []
class Summarizer:
    def __init__(self, project_path):
        self.disable_angr_logs()
        self.project = load_arm_project(project_path)
        self.cfg = self.project.analyses.CFGFast(
            normalize=True,
            resolve_indirect_jumps=True,
            data_references=True,     
            cross_references=True   
        )
        self.functions = self.project.analyses.CompleteCallingConventions(recover_variables=True, cfg=self.cfg)
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        self.bb_action_kb = dict()
        self.mmio_db = dict()
        self.global_kb = dict()
        self.arg_db = dict()
        self.final_action_kb = dict() 
        self.base_addr = self.project.loader.main_object.min_addr
        
        # self.sram_base, self.sram_size = self.find_sram_info(self.project)
        
    def main_component(self):
        self.reachable_main = nx.bfs_tree(self.cfg.kb.callgraph, self.project.entry).nodes()

    def find_sram_info(self, project):
        stack_start = int.from_bytes(project.loader.memory.load(self.base_addr, 4), byteorder='little')
        sram_base = stack_start
        sram_size = 0

    def disable_angr_logs(self):
        logging.getLogger("angr.analyses.cfg.cfg_base").setLevel(logging.CRITICAL)
        logging.getLogger("angr.analyses.variable_recovery.engine_vex.SimEngineVRVEX").setLevel(logging.CRITICAL)
        logging.getLogger("angr.analyses.variable_recovery.engine_base").setLevel(logging.CRITICAL)
        logging.getLogger("pyvex.lifting.gym.arm_spotter").setLevel(logging.CRITICAL)
        logging.getLogger("angr.analyses.propagator.engine_vex.SimEnginePropagatorVEX").setLevel(logging.CRITICAL)
        logging.getLogger("angr.analyses.calling_convention").setLevel(logging.CRITICAL)
        logging.getLogger("angr.storage.memory_mixins.default_filler_mixin").setLevel(logging.CRITICAL)
        logging.getLogger("angr.storage.memory_mixins.bvv_conversion_mixin").setLevel(logging.CRITICAL)
        logging.getLogger("angr.analyses.xrefs.SimEngineXRefsVEX").setLevel(logging.CRITICAL)
        logging.getLogger("angr.engines.successors").setLevel(logging.CRITICAL)
        
        
    def check_mmio(self, addr):
        """
        Check if the address range is MMIO.
        """
        if addr >= 0x40000000 and addr < 0x60000000:
            return True
        return False
    
    def check_global_addr(self, addr):
        """
        Check if the address is a global address.
        """
        if addr >= 0x20000000 and addr < 0x30000000:
            return True
        return False
    def perform_sym_exec(self, block_addr, regs=None, mem=None):
        """
        Perform symbolic execution on the given block address.
        """
        operations = {"regs":{}, "mem":{}}
        state = self.project.factory.blank_state(
            addr=block_addr, 
            add_options={
                angr.options.UNICORN,
                angr.options.UNICORN_SYM_REGS_SUPPORT,
                angr.options.OPTIMIZE_IR,
                angr.options.CONCRETIZE,
                angr.options.LAZY_SOLVES,
                angr.options.EFFICIENT_STATE_MERGING,
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                angr.options.TRACK_MEMORY_ACTIONS,
                angr.options.TRACK_REGISTER_ACTIONS,
                angr.options.TRACK_ACTION_HISTORY
            }
        )
        
        if regs:
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
        
        simgr = self.project.factory.simgr(state)
        try:
            simgr.step()
        except Exception as e:
            self.logger.error(f"Error during symbolic execution at block {block_addr:#x}: {e}")
            ops.append((block_addr, e))
            return operations
        if len(simgr.active) == 0:
            self.logger.warning(f"No active states after stepping through block {block_addr:#x}")
            return operations

        actions = simgr.active[0].history.actions
        operations["regs"] = get_reg_values(actions)
        operations["mem"] = get_mem_values(actions)
        
        
        return operations

    def compute_action_data(self):
        for func_addr, func_obj in self.cfg.kb.functions.items():
            # traverse the function graph using BFS and perform symbolic execution on each block
            for block in func_obj.blocks:
                bb_actions = self.perform_sym_exec(block.addr)
                self.bb_action_kb[block.addr] = self.perform_sym_exec(block.addr)

    def traverse_func_graph(self, func_addr):
        """
        Traverse the function graph starting from the given function address.
        """
        func_graph = self.cfg.kb.functions[func_addr].graph
        start_node = min(func_graph.nodes, key=lambda n: n.addr)
        visited = set()
        queue = [start_node]
        first_node = True
        target_kb = self.bb_action_kb
        while len(queue) > 0:
            current_node = queue.pop(0)
            if current_node.addr in visited:
                continue
            
            visited.add(current_node.addr)
            current_cfg_node = self.cfg.model.get_any_node(current_node.addr)
            
            # Perform symbolic execution on the current node
            if first_node:
                first_node = False  
                target_kb[current_node.addr] = self.perform_sym_exec(current_node.addr)
                # if current_node.addr == 134373435:
                #     print(ops)
                #     print(self.bb_action_kb[134373435])
                    
            else:
                preds = list(func_graph.predecessors(current_node))
                for pred in preds:
                    # if pred.addr > current_cfg_node.addr:
                    #     continue
                    if pred.addr in target_kb:
                        regs = target_kb[pred.addr]["regs"]
                        if regs:
                            target_kb[current_node.addr] = self.perform_sym_exec(current_node.addr, regs)
                
            # Add neighbors to the queue for further traversal
            for adj in func_graph.neighbors(current_node):
                if adj not in visited:
                    queue.append(adj)
            
        return visited
    def traverse_func_graph_with_args(self, func_addr, args, context):
        """
        Traverse the function graph starting from the given function address.
        """
        func_graph = self.cfg.kb.functions[func_addr].graph
        start_node = min(func_graph.nodes, key=lambda n: n.addr)
        visited = set()
        queue = [start_node]
        first_node = True
        target_kb = self.final_action_kb
        if func_addr not in target_kb:
            target_kb[func_addr] = {}
        if context not in target_kb[func_addr]:
            target_kb[func_addr][context] = {}
        while queue:
            current_node = queue.pop(0)
            if current_node in visited:
                continue
            
            visited.add(current_node)
            current_cfg_node = self.cfg.model.get_any_node(current_node.addr)
            
            if not current_cfg_node:
                continue
            # Perform symbolic execution on the current node
            if first_node:
                first_node = False  
                target_kb[func_addr][context][current_node.addr] = self.perform_sym_exec(current_node.addr, args)
            else:
                preds = list(func_graph.predecessors(current_node))
                # pred = max(preds, key=lambda p: len(list(filter(lambda x: x != None, target_kb[p.addr]["regs"]))))
                for pred in preds:
                    if pred.addr > current_cfg_node.addr:
                        continue
                    if pred.addr in target_kb[func_addr][context]:
                        regs = target_kb[func_addr][context][pred.addr]["regs"]
                        if regs:
                            target_kb[func_addr][context][current_node.addr] = self.perform_sym_exec(current_node.addr, regs)

            # Add neighbors to the queue for further traversal
            for adj in func_graph.neighbors(current_node):
                if adj not in visited:
                    queue.append(adj)

    def build_kb_from_action(self, build_global=False):
        """
        Check for MMIO addresses in the basic block actions.
        """
        check = self.check_mmio
        build_kb = self.mmio_db
        if build_global:
            check = self.check_global_addr
            build_kb = self.global_kb
        for addr, actions in self.bb_action_kb.items():
            for action_type, action_data in actions.items():
                if action_type == "mem":
                    for mem_addr, mem_value in action_data.items():
                        if check(mem_addr):
                            if addr not in build_kb:
                                build_kb[addr] = [(mem_value[0],mem_addr, mem_value[1])]
                            else:
                                build_kb[addr].append((mem_value[0],mem_addr, mem_value[1]))
        for func_addr, context in self.final_action_kb.items():
            for addr, action in context.items():
                for act_type, act_data in action.values():
                    if act_type == "mem":
                        for mem_addr, mem_val in act_data.items():
                            if check(mem_addr):
                                if addr not in build_kb:
                                    build_kb[addr] = [(mem_value[0], mem_addr, mem_value[1])]
                                else:
                                    build_kb[addr].append((mem_value[0],mem_addr, mem_value[1]))


    def build_bb_action_kb(self):
        """
        Build a knowledge base of basic block actions.
        """
        for func_addr, func_obj in self.cfg.kb.functions.items():
            self.logger.info(f"Processing function at address {func_addr:#x}")
            vis = self.traverse_func_graph(func_addr)
           
    def build_final_action_kb(self):
        """
        Build the final action knowledge base by traversing the function graph.
        """
        for func_addr, func_obj in self.cfg.kb.functions.items():
            for context in self.arg_db[func_addr]:
                self.traverse_func_graph_with_args(func_addr, self.arg_db[func_addr][context], context)
    
    def build_arg_graph(self):
        for func in self.cfg.kb.functions:
            callsites = self.cfg.model.get_any_node(func).predecessors
            func_args = self.cfg.kb.functions[func].arguments
            
            call_site_info = {}
            # if len(func_args) == 0:
            #     for callsite in callsites:
            #         call_addr = callsite.addr
            #         if call_addr in self.bb_action_kb:
            #             call_site_info[call_addr] = None
            #     self.arg_db[func] = call_site_info
            #     continue
            for callsite in callsites:
                call_addr = callsite.addr
                
                if call_addr in self.bb_action_kb:
                    args = {} if len(func_args) > 0 else None
                    for arg in func_args:
                        arg_name, arg_value,arg_val  = None,None,None
                        if type(arg) == angr.calling_conventions.SimStructArg:
                            continue
                        if type(arg) != angr.calling_conventions.SimStackArg :
                            arg_name = arg.reg_name
                            arg_val = get_reg_value(arg_name)
                            arg_value = self.bb_action_kb[call_addr]["regs"].get(arg_val, None)
                        else:
                            initial_sp = 0x7fff0000
                            arg_offset = arg.stack_offset
                            arg_value = self.bb_action_kb[call_addr]["mem"].get(initial_sp - arg_offset, None)                        
                        if arg_value:
                            args[arg_val] = (arg_name, arg_value[1])
                        else:
                            args[arg_val] = None
                call_site_info[call_addr] = args
            self.arg_db[func] = call_site_info
        
    def build_summary(self):
        self.build_bb_action_kb()
        self.build_arg_graph()
        self.build_final_action_kb()
        self.build_kb_from_action(build_global=False)
        self.build_kb_from_action(build_global=True)
        
        self.logger.info("Summary built successfully.")
    
    def write_summary(self, output_file):
        """
        Write the summary of actions to a json file.
        """
        import json
        with open(output_file , 'w') as f:
            json.dump(self.mmio_db, f, indent=4)
        self.logger.info(f"Summary written to {output_file}")

    # --------------------Interrupt related-----------------------
    def rev_db(self, db):
        rev_db = {}
        for bb_addr in db:
            for mmio_access in db[bb_addr]:
                op, addr, val = mmio_access
                if addr in rev_db:
                    rev_db[addr].append((bb_addr, op))
                else:
                    rev_db[addr] = [(bb_addr, op)]
        return rev_db

    def recover_isr_table(self, proj, cfg):
        ISR_TABLE = {}
        mem = self.project.loader.memory
        base_addr = self.project.loader.main_object.mapped_base
        for i in range(1, 496):
            isr_addr = int.from_bytes(
                self.project.loader.memory.load(base_addr + i*4, 4),
                byteorder='little'
            )
            if isr_addr == 0 or (isr_addr) in cfg.kb.functions:
                ISR_TABLE[i] = isr_addr
            else:
                break
        return ISR_TABLE

    def filter_ISRs(self, proj, cfg, global_db=None):
        ISR_TABLE = self.recover_isr_table(proj, cfg)
        
        GLOB_DB = self.global_kb
        global_kd_rev = self.rev_db(GLOB_DB)
        
        ISRs = []
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
    import argparse

    parser = argparse.ArgumentParser(description="Summarize firmware functions.")
    parser.add_argument("project_path", help="Path to the firmware project file.")
    args = parser.parse_args()

    summarizer = Summarizer(args.project_path)
    func_addr = 0x802a9e4 | 1
    # actions = summarizer.perform_sym_exec(func_addr)
    
    summarizer.build_bb_action_kb()
 
    summarizer.build_arg_graph()

    summarizer.build_final_action_kb()
    summarizer.build_kb_from_action(build_global=False)
    summarizer.build_kb_from_action(build_global=True)
    # summarizer.write_summary("mmio_summary.json")
    # print(ops)
    import ipdb; ipdb.set_trace()
    
    state = summarizer.project.factory.call_state(func_addr)
    state.inspect.b("expr", when=angr.BP_AFTER, action=track_ops)
    sm = summarizer.project.factory.simgr(state)
    print("Startig SimEx")
    sm.run(n=1)
    print(sm.active)
    
    # summarizer.write_summary("summary_final.json")
    # for mmio in summarizer.arg_db:
    #     print(f"Function {mmio:#x} arguments:")
    #     for call_site, args in summarizer.arg_db[mmio].items():
    #         print(f"  Call site {call_site:#x}:")
    #         for arg_name, arg_value in args.items():
    #             if arg_value is not None:
    #                 print(f"    {arg_name}: {arg_value[1]}")
    #             else:
    #                 print(f"    {arg_name}: None")

