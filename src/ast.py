from .utils import check_in_func, find_reroll_loop_candidate, get_func_addr_from_addr, reset_mem_dict

from .ast_bp import ast_address_concretization_bp, ast_constraints_bp, ast_fork_bp, ast_mem_read_bp, ast_reg_write_bp_iv_simplify
from .ast_bp import ast_mem_write_bp
from .ast_bp import ast_reg_write_bp_iv_init
# from .ast_bp import handle_inst

from .constant import weight_mem_start
from .constant import io_mem_start
from .constant import act_mem_start

from .dbg import StatefulDebug, address_concretization_debug, constraints_debug, mem_read_debug, state_debug_post, state_debug_pre

from .locals import SimStateLocals

from .branch_type import Branch

import angr


def tvmallocate(state):
    print("allocate bypass")
    state.regs.r2 = state.solver.BVS('allocate_addr', 32)


def extract_ast(proj, func_addr, outer_loop_idx, timeout=500):
    '''
    1. We collect all the addr with mem_write
    2. We mark all ivs with sym var and symbolic execute the nested loop. We keep forcing 
        break edge until all mem_write is met

    FIXME: we dont connect different loops/layers now
    FIXME: assume conditional inst, otherwise state explosion could happen
    '''

    assert (func_addr in proj.funcs)
    assert (outer_loop_idx in range(len(proj.outer_loops[func_addr])))

    outer_loop = proj.outer_loops[func_addr][outer_loop_idx]

    # init options
    add_options = set()
    add_options.add(angr.sim_options.CONSTRAINT_TRACKING_IN_SOLVER)
    remove_options = set()
    # remove_options.add(angr.sim_options.LAZY_SOLVES)
    # https://github.com/angr/angr/issues/2321
    # remove_options.add(angr.sim_options.COMPOSITE_SOLVER)

    # init entry_state
    entry_addr = outer_loop[0].entry_edge_src_blk_addr
    prologue_end_addr = proj.func_prologue_end_addr[func_addr]
    entry_state = proj.factory.blank_state(addr=func_addr,
                                           add_options=add_options,
                                           remove_options=remove_options)
    entry_state.solver._solver.timeout = timeout
    '''
    # weird that range will cause unsat issue (related to added constraints),
    # when we dont disable addr concretization
    assert (isinstance(entry_state.memory.read_strategies.pop(0), 
                       angr.concretization_strategies.range.SimConcretizationStrategyRange))
    '''

    outer_loop_end_addr = outer_loop[0].break_edge_dest_blk_addr

    # set outer_loop to state
    entry_state.globals["outer_loop"] = outer_loop

    # bookkeep iv var
    entry_state.globals["iv_dict"] = {}

    # flag
    entry_state.globals['flag'] = {}
    entry_state.globals['flag']['cond'] = False

    # registerlocals plugin:
    # dont use globals plugin because that's global (shallow-copy dict)
    entry_state.register_plugin('locals', SimStateLocals())

    # entered_loops -- see comments below
    entry_state.locals["entered_loops"] = {}
    for l in outer_loop[1]:
        entry_state.locals["entered_loops"][l.entry.addr] = False

    # completed_loops -- the loops that have been completed
    entry_state.locals["completed_loops"] = {}
    for l in outer_loop[1]:
        entry_state.locals["completed_loops"][l.entry.addr] = False

    # init the arg-init IV before registering bp
    for iv in outer_loop[0]._iv_dict.values():
        if iv.from_arg:
            assert (hasattr(entry_state.regs, iv.reg))
            arg_iv_sym = entry_state.solver.BVS(iv.name, proj.bit)
            setattr(entry_state.regs, iv.reg, arg_iv_sym)

    # hack to bypass tvm allocate
    # proj.hook(0x10391, tvmallocate, 4)

    # set the mem_read bp to annotate the memory read address
    # It is when the read_addr_sym is concretized and read_expr is loaded,
    # but register not written, since it is on VEX IR level.
    entry_state.inspect.b('mem_read',
                          when=angr.BP_AFTER,
                          action=ast_mem_read_bp)

    # collect the ast of memory write
    entry_state.inspect.b('mem_write',
                          when=angr.BP_AFTER,
                          action=ast_mem_write_bp)

    # reg_write bp to make entry block symbolic and register in dict
    entry_state.inspect.b('reg_write',
                          when=angr.BP_BEFORE,
                          action=ast_reg_write_bp_iv_init)

    # reg_write bp to simplify iv-related expr
    entry_state.inspect.b('reg_write',
                          when=angr.BP_BEFORE,
                          action=ast_reg_write_bp_iv_simplify)

    # disable adding constraints when concretizing IV-related addr
    entry_state.inspect.b('address_concretization',
                          when=angr.BP_AFTER,
                          action=ast_address_concretization_bp)
    '''
    entry_state.inspect.b('constraints',
                          when=angr.BP_BEFORE,
                          action=ast_constraints_bp)
    # for debug
    entry_state.inspect.b('constraints',
                          when=angr.BP_AFTER,
                          action=constraints_debug)
    entry_state.inspect.b('address_concretization',
                          when=angr.BP_AFTER,
                          action=address_concretization_debug)
    # not working
    entry_state.inspect.b('fork',
                          when=angr.BP_BEFORE,
                          action=ast_fork_bp)
    '''

    loop_func = proj.funcs[get_func_addr_from_addr(proj, entry_addr)]

    simgr = proj.factory.simgr(entry_state)

    while True:

        # for debugging
        assert (len(simgr.active) == 1)
        state = simgr.active[0]
        # debugger.debug(state)
        # print(hex(state.addr))
        # state_debug_pre(state)
        # print(simgr.stashed)
        # print(simgr.unsat)
        # print()

        # handle prologue
        if outer_loop_idx != 0 and state.addr == prologue_end_addr:
            print("prologue jumping from ", state.regs.pc, " to ", entry_addr)
            state.regs.pc = entry_addr
        print(simgr.active)

        '''
        # step debug
        bp = [0x100392, 0x100421, 0x100310, 0x100314, 0x100318]
        if state.addr in bp:
            from IPython import embed
            embed()
        '''

        '''
        # constraint debug
        debug_iv_addr = 0x130ff 
        if debug_iv_addr in state.globals['iv_dict']:
            debug_iv = state.globals['iv_dict'][debug_iv_addr]
            try:
                state.solver.eval_atleast(debug_iv, 2)
            except:
                print("Not satisfy:", hex(state.addr))
                from IPython import embed
                # embed()
                # assert (False)
        '''

        simgr.step(num_inst=1)

        # no unsupported irop
        if simgr.errored:
            print(simgr.errored)
            assert (False)

        # debug
        # state = simgr.active[0]
        # state_debug_post(state)
        # print(simgr.active)

        if len(simgr.active) > 1:

            assert (len(simgr.active) == 2)

            # match to the loop in outer_loop
            finished_loop = None
            branch_type = Branch.NON_LOOP
            addr_pair = (simgr.active[0].addr, simgr.active[1].addr)
            for loop in outer_loop[1]:
                branch_type = loop.match_branch(addr_pair)
                if branch_type != Branch.NON_LOOP:
                    finished_loop = loop
                    break

            # if-else branch
            if finished_loop is None:
                assert (branch_type == Branch.NON_LOOP)
                state.globals['flag']['cond'] = True
                stashed_addr = simgr.active[1].addr
                print("move if-else to stashed @ ", hex(stashed_addr))
                simgr.move(from_stash='active',
                           to_stash='stashed',
                           filter_func=lambda state: True
                           if state.addr == stashed_addr else False)

            # We are handling with several types of loop branch,
            # assuming that no ast logic between branches
            else:
                if branch_type == Branch.BREAK_CONT:
                    # drop the continue state
                    continue_addr = finished_loop.branch_continue_dest_addr
                    assert (continue_addr in addr_pair)
                    print("eliminate continue @ ", hex(continue_addr))
                    simgr.drop(filter_func=lambda state: True
                               if state.addr == continue_addr else False)

                    # to mark completed_loops, you have to retrieve another state
                    assert (len(simgr.active) == 1)
                    state = simgr.active[0]
                    assert (finished_loop.entry.addr
                            in state.locals["completed_loops"])
                    assert (not state.locals["completed_loops"][
                        finished_loop.entry.addr])
                    state.locals["completed_loops"][
                        finished_loop.entry.addr] = True

                # we dont follow break edge since there are more logic ahead
                elif branch_type == Branch.BREAK:
                    # drop the (fake) break state
                    break_addr = finished_loop.break_edge_dest_blk_addr
                    assert (break_addr in addr_pair)
                    print("eliminate break @ ", hex(break_addr))
                    simgr.drop(filter_func=lambda state: True
                               if state.addr == break_addr else False)

                else:
                    assert (False)

        # handle return-as-break situation
        elif len(simgr.active) == 1 and len(simgr.unconstrained):
            assert (simgr.active[0].history.addr ==
                    simgr.unconstrained[0].history.addr)
            branch_addr = simgr.active[0].history.addr
            finished_loop = None
            for loop in outer_loop[1]:
                if branch_addr in loop.branch_addr:
                    finished_loop = loop
                    break
            assert (finished_loop is not None)
            # drop the continue state
            continue_addr = finished_loop.branch_continue_dest_addr
            assert (continue_addr == simgr.active[0].addr)
            print("eliminate continue @ ", hex(continue_addr))
            simgr.drop(filter_func=lambda state: True
                       if state.addr == continue_addr else False)

        if simgr.active:
            assert (len(simgr.active) == 1)
            state = simgr.active[0]  # important to use the latest state

            # Because of constraints added by if-else branch,
            # break edge might not be satisfiable.
            # So here we check if current addr is a visited continue addr,
            # if yes, we drop this state
            # FIXME: assumption here is memory write is inside loop
            for loop in outer_loop[1]:
                if state.addr == loop.branch_continue_dest_addr:
                    assert (loop.entry.addr in state.locals['entered_loops'])
                    if state.locals['entered_loops'][loop.entry.addr] == False:
                        state.locals['entered_loops'][loop.entry.addr] = True
                    else:
                        simgr.move(from_stash='active',
                                   to_stash='deadended',
                                   filter_func=lambda state: True)
                        print("end of visited loop @ ", hex(state.addr))

            # end of the outer loop
            if state.addr == outer_loop_end_addr or not check_in_func(
                    loop_func, state.addr):
                simgr.move(from_stash='active',
                           to_stash='deadended',
                           filter_func=lambda state: True)
                print("end of outer loop @ ", hex(state.addr))

        if not simgr.active and not simgr.stashed:
            break

        # state can be pruned because of unsat or just being moved to deadended
        if not simgr.active and simgr.stashed:
            # let's pop from the end
            # there could serveral stashed state with the same addr
            stashed_state_addr = simgr.stashed[-1].addr
            stashed_state_id = id(simgr.stashed[-1])
            print("move stash to active @ ", hex(stashed_state_addr))
            # by checking id, we essentially execute every possible path,
            # which is time-consuming
            simgr.move(from_stash='stashed',
                       to_stash='active',
                       filter_func=lambda state: True
                       if id(state) == stashed_state_id else False)

    # refresh the proj, for processing next op
    mem_read_dict = proj.mem_read_dict
    mem_write_dict = proj.mem_write_dict
    reset_mem_dict(proj)

    # get the right solver
    solver = None
    if simgr.unconstrained:
        solver = simgr.unconstrained[0].solver
    elif simgr.deadended:
        # choose one that can work (not garbage collected)
        solver = simgr.deadended[0].solver
    assert (solver is not None)

    return simgr, solver, mem_read_dict, mem_write_dict
