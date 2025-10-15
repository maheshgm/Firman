import angr
import sys


def dump_functions_bbs(p, cfg):
    count = 0
    for key in cfg.kb.functions:
        for bb in cfg.kb.functions[key].blocks:
            print("%s: %s" % (hex(bb.addr), hex(bb.size)))
            count += 1
    print(count)


def main(argv):
    if (len(argv) < 2):
        print("Usage %s <BIN>" % argv[0])
        return 1
    path_to_binary = argv[1]
    p = angr.Project(path_to_binary, load_options={'auto_load_libs': False}, main_opts={
                     'backend': 'blob', 'arch': 'ARMCortexM (LE)'})
    cfg = p.analyses.CFGFast()
    dump_functions_bbs(p, cfg)

    return 0


if __name__ == '__main__':
    main(sys.argv)
