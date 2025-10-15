from util import *
import argparse 
import networkx as nx

def collect_bbs(func, cfg):
    visited = set()
    worklist = [func.addr]

    while worklist:
        addr = worklist.pop()
        if addr in visited:
            continue
        visited.add(addr)

        try:
            block = proj.factory.block(addr)
        except Exception:
            continue

        node = cfg.model.get_any_node(addr)
        if node:
            for succ in node.successors:
                if succ.addr not in visited:
                    worklist.append(succ.addr)
    return visited

def find_connected_components(cfg):
    callgraph = cfg.kb.callgraph
    # Implement logic to find connected components in the callgraph
    weakly_cc = list(nx.weakly_connected_components(callgraph))
    strongly_cc = list(nx.strongly_connected_components(callgraph))

    entry = cfg.project.entry
    entry_component = None
    
    for component in weakly_cc:
        if entry in component:
            entry_component = component
            break
    
    bbs_entry_comp = set()
    for comp in entry_component:
        bbs_entry_comp = bbs_entry_comp.union(find_bbs(cfg, comp))
    
    print(f"Basic Blocks in Entry Componet : {len(bbs_entry_comp)}")

    recursive_bbs = collect_bbs(cfg.kb.functions[entry], cfg)
    
    
    print(f"Recursive Basic Blocks : {len(recursive_bbs)}")
    
    import ipdb; ipdb.set_trace()
    
    other_bbs = set()
    for comp in weakly_cc:
        if comp != entry_component:
            for func in comp:
                other_bbs = other_bbs.union(find_bbs(cfg, func))
    print(f"Basic Blocks in Other Components : {len(other_bbs)}")

def find_bbs(cfg, func_addr):
    return set(list(cfg.kb.functions[func_addr].blocks))

def find_total_bbs(cfg):
    total_bbs = set()
    for func in cfg.functions.values():
        total_bbs = total_bbs.union(find_bbs(cfg, func.addr))
    return total_bbs

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Find basic blocks in ARM assembly code")
    parser.add_argument("filename", help="Path to the ARM assembly file")
    args = parser.parse_args()

    proj = load_arm_project(args.filename)
    cfg = proj.analyses.CFGFast(normalize=True, force_complete_scan=True)

    total_bbs = find_total_bbs(cfg)
    print(f"Total basic blocks found: {len(total_bbs)}")
    find_connected_components(cfg)