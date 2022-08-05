from .register import RegisterView
from .utils import check_arch, find_jump_addr, get_func_addr_from_addr, get_last_inst_addr_in_func, get_last_inst_addr_in_blk
from .super_loop import SuperLoop

import angr


def load(bin_path, dispatch_addr=None, arch=None):
    '''
    load binary and preprocess:
        - build cfg
        - collect all loops and attach to each function
        - a dict mapping from inst address to disasm inst
        - a dict mapping from inst address to vex stmts
    '''

    # Init proj
    #   1. base_addr: offset to align with Ghidra
    #   2. try-except: fix decoding error
    print("Loading binary")
    try:
        if arch == 'arm' or arch is None:
            proj = angr.Project(bin_path, main_opts={'base_addr': 0x10000})
            proj.bit = 32

        elif arch == 'x86':
            proj = angr.Project(bin_path, main_opts={'base_addr': 0x100000})
            proj.bit = 64

        elif arch == 'aarch64':
            proj = angr.Project(bin_path, main_opts={'arch': 'AARCH64'})
            proj.bit = 64

        else:
            print("arch not supported")
            assert (False)
    except Exception as e:
        print(e)
        proj = angr.Project(bin_path,
                            main_opts={
                                'base_addr': 0x10000,
                                'arch': 'thumb'
                            })

    print("Building CFG")
    proj.cfg = proj.analyses.CFGFast(normalize=True)
    proj.funcs = proj.cfg.kb.functions

    # map from addr to block
    proj.block_map = {}
    for func in proj.funcs.values():
        for blk in func.blocks:
            proj.block_map[blk.addr] = blk

    # init function arg register
    proj.func_calling_regs = {}

    # handle entry function (dispatcher)
    if dispatch_addr is not None:
        assert (dispatch_addr in proj.funcs)
        # collect analysis_funcs
        proj.analysis_funcs = [
            func.addr
            for func in list(proj.funcs[dispatch_addr].functions_called())
        ]
        proj.analysis_funcs.append(dispatch_addr)

        # propagate function arguments
        # prop_func_arg(proj, dispatch_addr)
    else:
        proj.analysis_funcs = [
            f_addr for f_addr in proj.funcs
            if 'sub' not in proj.funcs[f_addr].name
            and '$' not in proj.funcs[f_addr].name
        ]

    loop_finder = proj.cfg.project.analyses.LoopFinder(kb=proj.cfg.kb)
    proj.loops_hierarchy = loop_finder.loops_hierarchy

    # collect debug mapping
    collect_dbg_data(proj, loop_finder)

    # an operator function can be called multiple time, with
    # differnt aruguments
    '''
    temp_func_calling_regs = {}
    for addr in proj.func_calling_regs:
        dis = proj.dis_inst_map[addr]
        jump_addr = find_jump_addr(proj, dis)
        # print("jump addr", jump_addr)
        temp_func_calling_regs[jump_addr] = proj.func_calling_regs[addr]
    proj.func_calling_regs = temp_func_calling_regs
    '''

    # collect outer loops
    print("Construct outer loop")
    proj.outer_loops = {}
    for f_addr in proj.funcs:
        if f_addr not in proj.analysis_funcs:
            continue
        if f_addr not in loop_finder.loops_hierarchy:
            continue
        proj.outer_loops[f_addr] = get_outer_loops(
            loop_finder.loops_hierarchy[f_addr], proj.funcs[f_addr])

    # substitute subloops in outer_loops[1] with initiated superLoops
    for f_addr in proj.outer_loops:
        for loop_idx in range(len(proj.outer_loops[f_addr])):
            for l in proj.outer_loops[f_addr][loop_idx][1]:
                l.subloops = [
                    find_loop(sub_l, proj.outer_loops[f_addr][loop_idx][1])
                    for sub_l in l.subloops
                ]

    # TODO: it does not work because stack pointer changes
    # We collect prologue for every analysis_func
    # print("Prologue summary")
    func_prologue_analysis(proj)

    # init mem_write and mem_read dict
    proj.mem_read_dict = {}
    proj.mem_write_dict = {}

    # init mem_write_llft_dict
    proj.mem_write_lift_dict = {}

    return proj


def collect_dbg_data(proj, loop_finder):
    # map from addr to disasm inst
    proj.dis_inst_map = {}
    for f_addr in proj.funcs:
        if f_addr not in proj.analysis_funcs:
            continue
        if f_addr not in loop_finder.loops_hierarchy:
            continue
        func = proj.funcs[f_addr]
        for block in func.blocks:
            for inst in block.disassembly.insns:
                proj.dis_inst_map[inst.address] = inst

    # map from addr to vex stmts
    proj.vex_stmt_map = {}
    for f_addr in proj.funcs:
        if f_addr not in proj.analysis_funcs:
            continue
        if f_addr not in loop_finder.loops_hierarchy:
            continue
        func = proj.funcs[f_addr]
        for block in func.blocks:
            inst_addrs = block.instruction_addrs
            inst_idx = -1

            #first stmt should be IMark
            assert (block.vex.statements[0].tag == "Ist_IMark")

            for stmt in block.vex.statements:
                if stmt.tag == "Ist_IMark":
                    inst_idx += 1
                    proj.vex_stmt_map[inst_addrs[inst_idx]] = []
                    continue

                proj.vex_stmt_map[inst_addrs[inst_idx]].append(stmt)


def get_children_loops(l, func):
    '''
    return the list of itself and its chidlren loop
    '''
    ret = []
    worklist = [SuperLoop(l, func)]

    while worklist:
        item = worklist[0]
        worklist.remove(item)
        assert (item not in worklist)
        ret.append(item)
        for subloop in item.subloops:
            worklist.append(SuperLoop(subloop, func))

    return ret


def get_outer_loops(loops, func):
    '''
    Return: [(outer_loop, itself and all the subloops)]
    Caveat: outer_loop[0] != outer_loop[1][0]
    '''

    outer_loops = [(SuperLoop(l, func), get_children_loops(l, func))
                   for l in loops]

    outer_loops.sort(key=lambda item: item[0].entry.addr)

    return outer_loops


def find_loop(sub_loop, loops):
    '''
    Used to substitute loop with superloop 
    '''

    for l in loops:
        if l.entry.addr == sub_loop.entry.addr:
            return l


def save_state_registers(state):
    '''
    Save the state's register, so we have the value of arguments
    '''

    check_arch(state.project.arch)

    state.project.func_calling_regs[state.addr] = RegisterView(state)


def prop_func_arg(proj, dispatch_addr):
    '''
    Propagate region address from dispatcher to operators
    '''

    # locate dispatcher caller
    dispatch_caller_addr = None
    for f_addr in proj.funcs:
        if dispatch_addr in [
                func.addr
                for func in list(proj.funcs[f_addr].functions_called())
        ] and proj.funcs[f_addr].has_return:
            dispatch_caller_addr = f_addr
            break
    assert (dispatch_caller_addr is not None)

    # calculate all the calling sites
    blk_addr_list = list(proj.funcs[dispatch_addr].get_call_sites())
    blk_list = [
        proj.funcs[dispatch_addr]._local_blocks[addr] for addr in blk_addr_list
    ]
    last_inst_addr_list = [
        get_last_inst_addr_in_blk(proj.funcs[dispatch_addr], blk)
        for blk in blk_list
    ]

    # hook all function calling in dispatcher
    for addr in last_inst_addr_list:
        # TODO: assume it's 4 bytes
        proj.hook(addr, save_state_registers, length=4)
        # print("hook ", hex(addr))

    # init simgr
    entry_state = proj.factory.blank_state(addr=dispatch_caller_addr)
    simgr = proj.factory.simgr(entry_state)
    end_inst_addr = get_last_inst_addr_in_func(proj.funcs[dispatch_addr])

    # run dispatcher caller
    while True:
        simgr.step(num_inst=1)

        state = simgr.active[0]

        if state.addr == end_inst_addr:
            break


def func_prologue_analysis(proj):
    proj.func_prologue_summary = {}
    proj.func_prologue_end_addr = {}
    for func_addr in proj.analysis_funcs:
        # print(hex(func_addr))
        try:
            proj.func_prologue_end_addr[func_addr] = proj.outer_loops[
                func_addr][0][0].entry.addr
        except:
            print(hex(func_addr), " not found")
            pass
        # proj.func_prologue_end_addr[func_addr] = get_last_inst_addr_in_blk(
        #    proj.funcs[func_addr], next(proj.funcs[func_addr].blocks))
        # prepare_prologue(proj, func_addr)


def prologue_mem_write_bp(state):
    func_addr = get_func_addr_from_addr(state.project, state.addr)
    write_expr = state.inspect.mem_write_expr
    write_addr = state.inspect.mem_write_address

    if func_addr not in state.project.func_prologue_summary:
        state.project.func_prologue_summary[func_addr] = {}

    state.project.func_prologue_summary[func_addr][write_addr] = write_expr


def prepare_prologue(proj, func_addr):
    '''
    Return a dict of what prologue push on the stack
    '''
    prologue_end_addr = get_last_inst_addr_in_blk(
        proj.funcs[func_addr], next(proj.funcs[func_addr].blocks))

    # init simgr
    entry_state = proj.factory.blank_state(addr=func_addr)
    simgr = proj.factory.simgr(entry_state)

    entry_state.inspect.b('mem_write',
                          when=angr.BP_AFTER,
                          action=prologue_mem_write_bp)

    while True:
        simgr.step(num_inst=1)
        state = simgr.active[0]
        if state.addr > prologue_end_addr:
            break
