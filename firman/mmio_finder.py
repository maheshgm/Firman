import angr
import argparse
import csv
import sys
from collections import defaultdict
from util import *

# ARM Cortex-M Memory Map Ranges
PERIPHERAL_BASE = 0x40000000
PERIPHERAL_END = 0x5FFFFFFF
PRIVATE_PERIPHERAL_BASE = 0xE0000000
PRIVATE_PERIPHERAL_END = 0xE00FFFFF

# Common peripheral base addresses for STM32F4, NXP, Nordic, etc.
PERIPHERAL_MAP = {
    # STM32F4 Series
    0x40020000: "GPIOA",
    0x40020400: "GPIOB", 
    0x40020800: "GPIOC",
    0x40020C00: "GPIOD",
    0x40021000: "GPIOE",
    0x40021400: "GPIOF",
    0x40021800: "GPIOG",
    0x40021C00: "GPIOH",
    0x40022000: "GPIOI",
    0x40023800: "RCC",
    0x40013800: "USART1",
    0x40004400: "USART2",
    0x40004800: "USART3",
    0x40004C00: "UART4",
    0x40005000: "UART5",
    0x40011400: "USART6",
    0x40007800: "UART7",
    0x40007C00: "UART8",
    0x40012C00: "SPI1",
    0x40003800: "SPI2",
    0x40003C00: "SPI3",
    0x40013000: "SPI4",
    0x40015000: "SPI5",
    0x40015400: "SPI6",
    0x40005400: "I2C1",
    0x40005800: "I2C2",
    0x40005C00: "I2C3",
    0x40010000: "TIM1",
    0x40000000: "TIM2",
    0x40000400: "TIM3",
    0x40000800: "TIM4",
    0x40000C00: "TIM5",
    0x40001000: "TIM6",
    0x40001400: "TIM7",
    0x40010400: "TIM8",
    0x40014000: "TIM9",
    0x40014400: "TIM10",
    0x40014800: "TIM11",
    0x40001800: "TIM12",
    0x40001C00: "TIM13",
    0x40002000: "TIM14",

    # ARM Cortex-M System Control Block
    0xE000E000: "SCB",
    0xE000E100: "NVIC",
    0xE000E400: "NVIC_STIR",
    0xE000ED00: "SCB_CPUID",
    0xE000ED10: "SCB_SHCSR",
    0xE000ED20: "SCB_CFSR",
    0xE000ED24: "SCB_HFSR",
    0xE000ED28: "SCB_DFSR",
    0xE000ED2C: "SCB_MMFAR",
    0xE000ED30: "SCB_BFAR",
    0xE000ED34: "SCB_AFSR",
    0xE000E010: "SysTick",

    # NXP LPC Series (common ones)
    0x50000000: "GPIO0",
    0x50010000: "GPIO1",
    0x50020000: "GPIO2",
    0x50030000: "GPIO3",
    0x50040000: "GPIO4",
    0x400FC000: "SCU",
    0x40080000: "CCU1",
    0x400C0000: "CCU2",

    # Nordic nRF52 Series
    0x40000000: "POWER_CLOCK",
    0x40001000: "RADIO",
    0x40002000: "UART0",
    0x40003000: "SPI0_TWI0",
    0x40004000: "SPI1_TWI1",
    0x40006000: "GPIOTE",
    0x40007000: "ADC",
    0x40008000: "TIMER0",
    0x40009000: "TIMER1",
    0x4000A000: "TIMER2",
    0x4000B000: "RTC0",
    0x4000C000: "TEMP",
    0x4000D000: "RNG",
    0x4000E000: "ECB",
    0x4000F000: "CCM_AAR",
    0x40010000: "WDT",
    0x40011000: "RTC1",
    0x40012000: "QDEC",
    0x40013000: "LPCOMP",
    0x40014000: "SWI0",
    0x40015000: "SWI1",
    0x40016000: "SWI2",
    0x40017000: "SWI3",
    0x40018000: "SWI4",
    0x40019000: "SWI5",
}

class MMIOAnalyzer:
    def __init__(self, binary_path, base_address, arch='ARMEL', thumb_mode=True):
        self.binary_path = binary_path
        self.base_address = base_address
        self.arch = arch
        self.thumb_mode = thumb_mode
        self.mmio_accesses = []
        self.constants = {}  # For constant propagation

    def load_project(self):
        """Load the firmware binary into angr project"""
        try:
            print(f"[+] Loading binary: {self.binary_path} with base address 0x{self.base_address:08x}")
            self.project = load_arm_project(self.binary_path)
            print("Done loading project")
            if self.thumb_mode and 'ARM' in self.arch:
                initial_state = self.project.factory.entry_state()
                initial_state.options.add(angr.options.USE_THUMB)

            print(f"[+] Loaded binary: {self.binary_path}")
            print(f"[+] Base address: 0x{self.base_address:08x}")
            print(f"[+] Architecture: {self.arch}")
            return True

        except Exception as e:
            print(f"[-] Error loading project: {e}")
            return False

    def build_cfg(self):
        """Build Control Flow Graph using CFGFast"""
        try:
            print("[+] Building CFG...")
            self.cfg = self.project.analyses.CFGFast(
                normalize=True,
                data_references=True
            )
            print(f"[+] CFG built with {len(self.cfg.graph.nodes())} nodes")
            return True

        except Exception as e:
            print(f"[-] Error building CFG: {e}")
            return False

    def is_peripheral_address(self, addr):
        """Check if address is in peripheral memory ranges"""
        return ((PERIPHERAL_BASE <= addr <= PERIPHERAL_END) or 
                (PRIVATE_PERIPHERAL_BASE <= addr <= PRIVATE_PERIPHERAL_END))

    def get_peripheral_name(self, addr):
        """Get human-readable peripheral name if known"""
        # Exact match
        if addr in PERIPHERAL_MAP:
            return PERIPHERAL_MAP[addr]

        # Find closest base address with offset
        for base_addr, name in PERIPHERAL_MAP.items():
            if base_addr <= addr < (base_addr + 0x400):  # Typical peripheral size
                offset = addr - base_addr
                return f"{name}+0x{offset:x}"

        # Generic peripheral region
        if PERIPHERAL_BASE <= addr <= PERIPHERAL_END:
            return "PERIPHERAL"
        elif PRIVATE_PERIPHERAL_BASE <= addr <= PRIVATE_PERIPHERAL_END:
            return "PRIVATE_PERIPHERAL"

        return "UNKNOWN"

    def analyze_vex_expression(self, expr, stmt_addr):
        """Analyze VEX expression for constant values"""
        if hasattr(expr, 'tag'):
            if expr.tag == 'Iex_Const':
                # Direct constant
                return expr.con.value
            elif expr.tag == 'Iex_RdTmp':
                # Read from temporary variable
                tmp_id = expr.tmp
                if tmp_id in self.constants:
                    return self.constants[tmp_id]
            elif expr.tag == 'Iex_Get':
                # Read from register - could be constant
                offset = expr.offset
                if offset in self.constants:
                    return self.constants[offset]
            elif expr.tag == 'Iex_Binop':
                # Binary operation - try to resolve if operands are constants
                left = self.analyze_vex_expression(expr.args[0], stmt_addr)
                right = self.analyze_vex_expression(expr.args[1], stmt_addr)

                if left is not None and right is not None:
                    op = expr.op
                    if 'Add' in op:
                        return left + right
                    elif 'Sub' in op:
                        return left - right
                    elif 'Mul' in op:
                        return left * right
                    elif 'And' in op:
                        return left & right
                    elif 'Or' in op:
                        return left | right
                    elif 'Xor' in op:
                        return left ^ right

        return None

    def analyze_block(self, block):
        """Analyze a basic block for MMIO accesses"""
        if block.size < 4:  # Skip very small blocks (likely literal pools)
            return

        try:
            # Get VEX IR for the block
            vex_block = self.project.factory.block(block.addr, size=block.size).vex

            # Track constants in this block
            block_constants = {}

            for stmt in vex_block.statements:
                if hasattr(stmt, 'tag'):
                    # Track constant assignments
                    if stmt.tag == 'Ist_WrTmp':
                        tmp_id = stmt.tmp
                        value = self.analyze_vex_expression(stmt.data, block.addr)
                        if value is not None:
                            block_constants[tmp_id] = value

                    elif stmt.tag == 'Ist_Put':
                        # Register write
                        offset = stmt.offset
                        value = self.analyze_vex_expression(stmt.data, block.addr)
                        if value is not None:
                            block_constants[offset] = value

                    elif stmt.tag == 'Ist_Store':
                        # Memory store - check if it's MMIO
                        addr_expr = stmt.addr
                        data_expr = stmt.data

                        # Try to resolve address
                        addr = self.analyze_vex_expression(addr_expr, block.addr)
                        if addr is not None and self.is_peripheral_address(addr):
                            peripheral_name = self.get_peripheral_name(addr)
                            size = stmt.data.result_size(vex_block.tyenv) // 8

                            # Find corresponding PC
                            pc = block.addr  # Approximate PC
                            print("Found a MMIO load address at 0x{:08x} for peripheral {}".format(addr, peripheral_name))
                            self.mmio_accesses.append({
                                'pc': pc,
                                'access': 'store',
                                'size': size,
                                'address': addr,
                                'peripheral': peripheral_name
                            })

                    elif stmt.tag == 'Ist_LoadG' or stmt.tag == 'Ist_LLSC':
                        # Memory load - check if it's MMIO
                        if hasattr(stmt, 'addr'):
                            addr = self.analyze_vex_expression(stmt.addr, block.addr)
                            if addr is not None and self.is_peripheral_address(addr):
                                peripheral_name = self.get_peripheral_name(addr)
                                size = 4  # Default size
                                if hasattr(stmt, 'result'):
                                    size = vex_block.tyenv.lookup(stmt.result).size // 8

                                pc = block.addr
                                self.mmio_accesses.append({
                                    'pc': pc,
                                    'access': 'load',
                                    'size': size,
                                    'address': addr,
                                    'peripheral': peripheral_name
                                })

            # Update global constants
            self.constants.update(block_constants)

        except Exception as e:
            print(f"[!] Error analyzing block at 0x{block.addr:08x}: {e}")

    def analyze_mmio(self):
        """Main analysis function to find MMIO accesses"""
        print("[+] Analyzing MMIO accesses...")

        analyzed_blocks = 0
        for node in self.cfg.graph.nodes():
            if hasattr(node, 'block') and node.block is not None:
                self.analyze_block(node.block)
                analyzed_blocks += 1

                if analyzed_blocks % 100 == 0:
                    print(f"[+] Analyzed {analyzed_blocks} blocks...")

        print(f"[+] Analysis complete. Found {len(self.mmio_accesses)} MMIO accesses")
        return self.mmio_accesses

    def save_results(self, output_file="mmio_results.csv"):
        """Save results to CSV file"""
        if not self.mmio_accesses:
            print("[-] No MMIO accesses found to save")
            return

        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = ['PC', 'Access', 'Size', 'MMIO Addr', 'Peripheral']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for access in self.mmio_accesses:
                writer.writerow({
                    'PC': f"0x{access['pc']:08x}",
                    'Access': access['access'],
                    'Size': access['size'],
                    'MMIO Addr': f"0x{access['address']:08x}",
                    'Peripheral': access['peripheral']
                })

        print(f"[+] Results saved to {output_file}")

    def print_results(self):
        """Print results in a formatted table"""
        if not self.mmio_accesses:
            print("[-] No MMIO accesses found")
            return

        print("\n" + "="*80)
        print("MMIO ACCESS ANALYSIS RESULTS")
        print("="*80)
        print(f"{'PC':<12} {'Access':<8} {'Size':<6} {'MMIO Addr':<12} {'Peripheral'}")
        print("-" * 80)

        for access in sorted(self.mmio_accesses, key=lambda x: x['pc']):
            print(f"0x{access['pc']:08x}  {access['access']:<8} {access['size']:<6} "
                  f"0x{access['address']:08x}  {access['peripheral']}")

def main():
    parser = argparse.ArgumentParser(
        description="MMIO Finder - Static Analysis Tool for ARM Cortex-M Firmware"
    )
    parser.add_argument('--bin', required=True, help='Firmware binary file')
    parser.add_argument('--base', required=True, type=lambda x: int(x, 0), 
                       help='Base address for firmware loading (e.g., 0x08000000)')
    parser.add_argument('--thumb', action='store_true', default=True,
                       help='Use Thumb mode (default: True)')
    parser.add_argument('--arm', action='store_true',
                       help='Use ARM mode instead of Thumb')
    parser.add_argument('--output', '-o', default='mmio_results.csv',
                       help='Output CSV file (default: mmio_results.csv)')
    parser.add_argument('--header', help='Custom CSV file with peripheral definitions')
    parser.add_argument('--html', action='store_true',
                       help='Generate HTML report (not implemented)')

    args = parser.parse_args()

    # Determine execution mode
    thumb_mode = args.thumb and not args.arm

    print("MMIO Finder - ARM Cortex-M Firmware Analysis Tool")
    print("=" * 50)

    # Create analyzer
    analyzer = MMIOAnalyzer(
        binary_path=args.bin,
        base_address=args.base,
        arch='ARMCortexM',
        thumb_mode=thumb_mode
    )

    # Load project
    if not analyzer.load_project():
        return 1

    # Build CFG
    if not analyzer.build_cfg():
        return 1

    # Analyze MMIO
    analyzer.analyze_mmio()

    # Print results
    analyzer.print_results()

    # Save results
    analyzer.save_results(args.output)

    return 0

if __name__ == "__main__":
    sys.exit(main())