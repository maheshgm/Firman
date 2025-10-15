import struct
import angr
import pyvex
import logging
from elftools.elf.elffile import ELFFile

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("util")

def get_entry(file_name):
    with open(file_name, "rb") as f:
        initial_sp = bytes2int(f.read(4))
        entry_point = bytes2int(f.read(4))
        initial_sp = initial_sp
        
        return entry_point, initial_sp

def check_elf(filepath):
    try:
        with open(filepath, 'rb') as f:
            magic = f.read(4)
            return magic == b'\x7fELF'
    except Exception as e:
        logger.error(f"Error reading file {filepath}: {e}")
        return False

def load_arm_project(file_name, base_addr=0):
    
    if not (check_elf(file_name)):
        base = get_base_addr(file_name)
        logger.info("Possible base addresses: ", base, "\nChoosing ", base[0])
        base_addr = int(base[0], 16)
        entry = get_entry(file_name)[0]
        proj = angr.Project(file_name, arch="ARMCortexM", main_opts={'backend': 'blob', 'base_addr': base_addr, 'entry_point': entry|1})
    else:
        proj = angr.Project(file_name)
    return proj

def get_base_addr(binary):
    import subprocess
    import re
    command = "binbloom " + binary
    output = subprocess.check_output(command, shell=True, text=True)
    base_addr = re.findall(r'\b0[xX][0-9a-fA-F]+\b', output)
    if len(base_addr) == 0:
        print("Not able to detect base address")
    return base_addr

def read_mem_val(proj, addr, size):
    b_state = proj.factory.blank_state()
    mem_val = b_state.memory.load(addr, size)
    mem_val = b_state.solver.eval(mem_val, cast_to=bytes)
    return int.from_bytes(mem_val, byteorder='little')

def trace_loads(func):
    blocks = list(func.blocks)
    for block in range(len(blocks)):
        for stmt in block.vex.statements:
            if isinstance(stmt, pyvex.stmt.LoadG):
                tmp = stmt.dst

def check_global(addr, ram_start=0x20000000, ram_size=0x1000):
    return (addr > ram_start and addr < ram_start + ram_size) 

def check_mmio(addr):
    return (addr > 0x4000_0000 and addr < 0x50000000)

def bytes2int(bs):
    if len(bs) == 4:
        return struct.unpack("<I", bs)[0]
    if len(bs) == 2:
        return struct.unpack("<H", bs)[0]
    if len(bs) == 1:
        return struct.unpack("<B", bs)[0]
    if len(bs) == 8:
        return struct.unpack("<Q", bs)[0]

