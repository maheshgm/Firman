import argparse
import angr
import json
import sys
import logging
import networkx as nx
import pyvex
import archinfo
from collections import deque

from .util import *

GENERAL_REGS = ['r0','r1','r2','r3','r4','r5','r6','r7','r8','r9','r10','r11','r12', 'lr', 'sp']
FLOATING_REGS = ['d0','d1','d2','d3','d4','d5','d6','d7','d8','d9','d10','d11','d12', 'd13', 'd14', 'd15']
STATE_REGS = ['cc_op', 'cc_dep1', 'cc_dep2', 'cc_ndep', 'itstate']

def disable_angr_logs():
        logging.getLogger("angr.analyses.cfg.cfg_base").setLevel(logging.CRITICAL)
        logging.getLogger("angr.analyses.variable_recovery.engine_vex.SimEngineVRVEX").setLevel(logging.CRITICAL)
        logging.getLogger("angr.analyses.variable_recovery.engine_base").setLevel(logging.CRITICAL)
        logging.getLogger("pyvex.lifting.gym.arm_spotter").setLevel(logging.CRITICAL)
        logging.getLogger("angr.analyses.propagator.engine_vex.SimEnginePropagatorVEX").setLevel(logging.CRITICAL)
        logging.getLogger("angr.analyses.calling_convention").setLevel(logging.CRITICAL)
        logging.getLogger("angr.storage.memory_mixins.default_filler_mixin").setLevel(logging.CRITICAL)
def filter_unused(cfg):
    
    call_g = cfg.kb.callgraph
    wc_comps = nx.weakly_connected_components(call_g)
    # print(self._cfg.project.entry in max(wc_comps, key = len))
    #get the weakly connected componet starting from entry point
    for component in wc_comps:
        if cfg.project.entry in component:
            con_comp = component
            return 
    raise Exception("EntryNotFound: No connected component found with Entry Point addr")

    return con_comp

def get_tmp(stmt):
    return stmt.tmp

def get_reg(stmt):
    offset = stmt.offset
    irsb = pyvex.IRSB(b"\x00", 0x00, archinfo.ArchARMCortexM())
    return irsb.arch.translate_register_name(offset)

def get_const(stmt):
    return stmt.con.value

def parse_expression(expr):
    """Helper function to parse various expression types"""
    if isinstance(expr, pyvex.expr.RdTmp):
        return get_tmp(expr)
    elif isinstance(expr, pyvex.expr.Const):
        return get_const(expr)
    elif isinstance(expr, pyvex.expr.Get):
        return get_reg(expr)
    else:
        return str(expr)

def parse_stmt(stmt):
    """
    Parse VEX statements and return tuple (op_type, input_reg, output_reg)
    Returns None if statement type is not handled
    """
    op = None
    inp_reg = None
    out_reg = None
    children = list(stmt.child_expressions)
    
    # Skip instruction markers
    if isinstance(stmt, pyvex.stmt.IMark):
        return ("IMark", stmt.addr)
        
    
    # AbiHint statements (calling convention hints)
    if isinstance(stmt, pyvex.stmt.AbiHint):
        return None
    
    # No-operation statements
    if isinstance(stmt, pyvex.stmt.NoOp):
        return None
    
    # Memory barrier/fence statements
    if isinstance(stmt, pyvex.stmt.MBE):
        op = 'MemoryBarrier'
        return (op, None, None)
    
    # Conditional/guarded load operations
    if isinstance(stmt, pyvex.stmt.LoadG):
        op = 'LoadG'
        if type(stmt.addr) == pyvex.expr.Const:
            inp_reg = get_const(children[0])
        else:
            inp_reg = get_tmp(children[0])
        out_reg = 't'+str(stmt.dst)
    
    # Register write operations
    elif isinstance(stmt, pyvex.stmt.Put):
        op = 'Put'
        if isinstance(children[0], pyvex.expr.Const):
            inp_reg = get_const(children[0])
        else:
            inp_reg = get_tmp(children[0])
        out_reg = get_reg(stmt)
    
    # Indexed register write (e.g., for vector registers)
    elif isinstance(stmt, pyvex.stmt.PutI):
        op = 'PutI'
        inp_reg = []
        if len(children) >= 1:
            inp_reg.append(parse_expression(children[0]))  # index
        if len(children) >= 2:
            inp_reg.append(parse_expression(children[1]))  # value
        out_reg = f"reg_array[{stmt.descr.base}:{stmt.descr.nElems}]"
    
    # Memory store operations
    elif isinstance(stmt, pyvex.stmt.Store) or isinstance(stmt, pyvex.stmt.StoreG):
        op = 'Store' if isinstance(stmt, pyvex.stmt.Store) else 'StoreG'
        inp_reg = []
        # Address
        if len(children) >= 1:
            inp_reg.append(parse_expression(children[0]))
        # Data to store
        if len(children) >= 2:
            inp_reg.append(parse_expression(children[1]))
        out_reg = inp_reg[0]
        inp_reg = inp_reg[1]
        
    
    # Conditional store operations
    elif isinstance(stmt, pyvex.stmt.CAS):
        op = 'CompareAndSwap'
        inp_reg = []
        if hasattr(stmt, 'addr'):
            inp_reg.append(parse_expression(stmt.addr))
        if hasattr(stmt, 'expdHi') and stmt.expdHi is not None:
            inp_reg.append(get_tmp(stmt.expdHi))
        if hasattr(stmt, 'expdLo'):
            inp_reg.append(get_tmp(stmt.expdLo))
        if hasattr(stmt, 'dataHi') and stmt.dataHi is not None:
            inp_reg.append(get_tmp(stmt.dataHi))
        if hasattr(stmt, 'dataLo'):
            inp_reg.append(get_tmp(stmt.dataLo))
        out_reg = []
        if hasattr(stmt, 'oldHi') and stmt.oldHi != -1:
            out_reg.append('t' + str(stmt.oldHi))
        if hasattr(stmt, 'oldLo') and stmt.oldLo != -1:
            out_reg.append('t' + str(stmt.oldLo))
    
    # Temporary variable assignments
    elif isinstance(stmt, pyvex.stmt.WrTmp):
        out_reg = get_tmp(stmt)
        
        if isinstance(children[0], pyvex.expr.Get):
            op = 'Get'
            inp_reg = get_reg(children[0])
        
        elif isinstance(children[0], pyvex.expr.GetI):
            op = 'GetI'
            inp_reg = []
            inp_reg.append(f"reg_array[{children[0].descr.base}:{children[0].descr.nElems}]")
            if len(children) >= 2:
                inp_reg.append(parse_expression(children[1]))  # index
        
        elif isinstance(children[0], pyvex.expr.Load):
            op = 'Load'
            if len(children) >= 2:
                inp_reg = parse_expression(children[1])
            else:
                inp_reg = 'unknown_addr'
        
        elif isinstance(children[0], pyvex.expr.Const):
            op = 'Const'
            inp_reg = get_const(children[0])
        
        elif isinstance(children[0], pyvex.expr.Binop):
            op = children[0].op
            inp_reg = []
            for r in children[1:]:
                inp_reg.append(parse_expression(r))
        
        elif isinstance(children[0], pyvex.expr.Unop):
            op = children[0].op
            inp_reg = []
            for r in children[1:]:
                inp_reg.append(parse_expression(r))
        
        elif isinstance(children[0], pyvex.expr.Triop):
            op = children[0].op
            inp_reg = []
            for r in children[1:]:
                inp_reg.append(parse_expression(r))
        
        elif isinstance(children[0], pyvex.expr.Qop):
            op = children[0].op
            inp_reg = []
            for r in children[1:]:
                inp_reg.append(parse_expression(r))
        
        elif isinstance(children[0], pyvex.expr.ITE):
            op = 'ITE'  # If-Then-Else
            inp_reg = []
            if len(children) >= 4:
                inp_reg.append(parse_expression(children[1]))  # condition
                inp_reg.append(parse_expression(children[2]))  # then value
                inp_reg.append(parse_expression(children[3]))  # else value
        
        elif isinstance(children[0], pyvex.expr.CCall):
            op = f'CCall_{children[0].cee.name}'
            inp_reg = []
            for r in children[1:]:
                inp_reg.append(parse_expression(r))
    
    # Exit statements (conditional jumps)
    elif isinstance(stmt, pyvex.stmt.Exit):
        op = 'Exit'
        inp_reg = []
        if hasattr(stmt, 'guard') and stmt.guard is not None:
            inp_reg.append(parse_expression(stmt.guard))
        if hasattr(stmt, 'dst'):
            if isinstance(stmt.dst, pyvex.expr.Const):
                inp_reg.append(get_const(stmt.dst))
            else:
                inp_reg.append(str(stmt.dst))
        out_reg = 'pc'  # Program counter
    
    # Dirty calls (architecture-specific operations)
    elif isinstance(stmt, pyvex.stmt.Dirty):
        op = f'Dirty_{stmt.cee.name}' if hasattr(stmt, 'cee') else 'Dirty'
        inp_reg = []
        for arg in stmt.args:
            inp_reg.append(parse_expression(arg))
        out_reg = None
        if hasattr(stmt, 'tmp') and stmt.tmp != -1:
            out_reg = 't' + str(stmt.tmp)
    
    # LLSC (Load-Link/Store-Conditional) operations
    elif isinstance(stmt, pyvex.stmt.LLSC):
        if stmt.storedata is None:
            op = 'LoadLinked'
            inp_reg = parse_expression(stmt.addr)
            out_reg = 't' + str(stmt.result)
        else:
            op = 'StoreConditional'
            inp_reg = [parse_expression(stmt.addr), parse_expression(stmt.storedata)]
            out_reg = 't' + str(stmt.result)
    
    # Handle common comparison operations specifically
    if op and ('Cmp' in op or 'cmp' in op.lower()):
        # This is a comparison operation
        op_type = 'Compare'
        if op.startswith('Iop_Cmp'):
            # Extract comparison type (e.g., CmpEQ32, CmpNE64, etc.)
            cmp_type = op.replace('Iop_', '')
            op = f'Compare_{cmp_type}'
    
    return (op, inp_reg, out_reg)

def get_instrs_for_block(block):
    stmts = {}
    stmt_addr = None
    for stmt in block.vex.statements:
        parsed_stmt = parse_stmt(stmt)
        if parsed_stmt[0] == "IMark":
            
            stmt_addr = parsed_stmt[1]
            print(f"Processed statement with addr {stmt_addr}", "-"*20)
            continue
        print(parsed_stmt)
        if stmt_addr not in stmts:
            stmts[stmt_addr] = [parsed_stmt]
        else:
            stmts[stmt_addr].append(parsed_stmt)
    return stmts

if __name__ == '__main__':
    sys.setrecursionlimit(1500)
    # disable_angr_logs()
    config = {
        "file": "/home/mahesh/ssd/final/FlashFuzz/FlashFuzz/firman/firmwares/Console/Console.elf",
        "base_addr" : 0x0000000,
        "mmio_start" : 0x40000000,
        "mmio_size" : 0x20000000,
        "ram_start" : 0x20000000,
        "ram_size": 0x100000    
    }
    
    proj = load_arm_project(config['file'])
    # res = open("results.csv", "w")
    cfg = proj.analyses.CFGFast()
    functions = proj.analyses.CompleteCallingConventions(recover_variables=True, cfg=cfg)

    # f = cfg.kb.functions['HAL_GPIO_Init']
    
    
    block = cfg.model.get_any_node(0xe5d)
    
    print(get_instrs_for_block(block.block))
    
    block.block.vex.pp()
    # for b in f.blocks:
    #     #print("block size :", b.size)
    #     #b.pp()
    #     print('-'*20, 'Block Address:', hex(b.addr),'-'*20)
    #     blk = cfg.model.get_any_node(b.addr)
    # for stmt in block.block.vex.statements:
    #     pstmt = parse_stmt(stmt)
        
    #     print(pstmt)
        
    
    # for block in f.blocks:
    #     gen_IN(block)

    # res.close()


'''
List of stmt types

{(pyvex.expr.Binop, pyvex.expr.Const, pyvex.expr.RdTmp),
 (pyvex.expr.Binop, pyvex.expr.RdTmp, pyvex.expr.Const),
 (pyvex.expr.Binop, pyvex.expr.RdTmp, pyvex.expr.RdTmp),
 (pyvex.expr.CCall,
  pyvex.expr.Const,
  pyvex.expr.RdTmp,
  pyvex.expr.Const,
  pyvex.expr.Const),
 (pyvex.expr.CCall,
  pyvex.expr.Const,
  pyvex.expr.RdTmp,
  pyvex.expr.Const,
  pyvex.expr.RdTmp),
 (pyvex.expr.CCall,
  pyvex.expr.Const,
  pyvex.expr.RdTmp,
  pyvex.expr.RdTmp,
  pyvex.expr.Const),
 (pyvex.expr.CCall,
  pyvex.expr.Const,
  pyvex.expr.RdTmp,
  pyvex.expr.RdTmp,
  pyvex.expr.RdTmp),
 (pyvex.expr.CCall,
  pyvex.expr.RdTmp,
  pyvex.expr.RdTmp,
  pyvex.expr.RdTmp,
  pyvex.expr.RdTmp),
 (pyvex.expr.Get,),
 (pyvex.expr.ITE, pyvex.expr.RdTmp, pyvex.expr.Const, pyvex.expr.RdTmp),
 (pyvex.expr.ITE, pyvex.expr.RdTmp, pyvex.expr.RdTmp, pyvex.expr.Const),
 (pyvex.expr.ITE, pyvex.expr.RdTmp, pyvex.expr.RdTmp, pyvex.expr.RdTmp),
 (pyvex.expr.Load, pyvex.expr.Const),
 (pyvex.expr.Load, pyvex.expr.RdTmp),
 (pyvex.expr.RdTmp,),
 (pyvex.expr.Unop, pyvex.expr.RdTmp),
 pyvex.stmt.Exit,
 >pyvex.stmt.IMark,
 >pyvex.stmt.LoadG,
 pyvex.stmt.MBE,
 >pyvex.stmt.Put,
 >pyvex.stmt.Store,
 >pyvex.stmt.StoreG}

'''