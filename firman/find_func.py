import binascii
import difflib
import json
from util import *

def hamming_similarity(b1: bytes, b2: bytes) -> float:
    if len(b1) != len(b2):
        # Pad shorter one with 0s
        max_len = max(len(b1), len(b2))
        b1 = b1.ljust(max_len, b'\x00')
        b2 = b2.ljust(max_len, b'\x00')
    
    diff_bits = sum(bin(x ^ y).count('1') for x, y in zip(b1, b2))
    total_bits = 8 * len(b1)
    return 100 * (1 - diff_bits / total_bits)



def get_func_binary(cfg, func_name):
    """
    Returns the binary representation of a function name.
    """
    address = cfg.kb.functions[func_name].addr
    size = cfg.kb.functions[func_name].size
    return cfg.project.loader.memory.load(address, size)

def get_matching_score(func_bin, str_bin):
    """
    Returns a matching score between the function binary and the string binary.
    """
    seq_matcher = difflib.SequenceMatcher(None, func_bin, str_bin)
    return seq_matcher.ratio() * 100

def generate_matches(cfg):
    matches = {}
    str_fun_db = json.load(open("str_calls.json"))
    for str_func in str_fun_db.keys():
        for bin_rep in str_fun_db[str_func]:
            matches[str_func] = []
            
            for func in cfg.kb.functions.values():
                matching_score = []
                func_bin = get_func_binary(proj, func.name)
                str_bin = binascii.unhexlify(bin_rep.replace(" ", ""))
                score = get_matching_score(func_bin, str_bin) 
                
                matches[str_func].append((score, func, len(func_bin), len(str_bin)))
    for func in matches:
        print(func, max(matches[func], key=lambda x: x[0]))

    return matches
if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python find_func.py <file1> ")
        sys.exit(1)

    proj = load_arm_project(sys.argv[1], blob=True)
    cfg = proj.analyses.CFG()
    functions = cfg.project.analyses.CompleteCallingConventions(recover_variables=True, cfg=cfg)

    matches = {}
    str_fun_db = json.load(open("str_calls.json"))
    for str_func in str_fun_db.keys():
        for bin_rep in str_fun_db[str_func]:
            matches[str_func] = []
            
            for func in cfg.kb.functions.values():
                matching_score = []
                func_bin = get_func_binary(cfg, func.name)
                str_bin = binascii.unhexlify(bin_rep.replace(" ", ""))
                score = get_matching_score(func_bin, str_bin) 
                
                matches[str_func].append((score, func, len(func_bin), len(str_bin)))
    for func in matches:
        print(func, max(matches[func], key=lambda x: x[0]))
