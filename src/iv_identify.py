from pickle import FALSE
from .iv_dict import IVDict

from .iv_bp import iv_entry_reg_write_bp
from .iv_bp import iv_exit_bp
from .iv_bp import iv_mem_read_bp
from .iv_bp import iv_mem_write_bp

from .iv_estimate import _estimate_iv

from .utils import check_in_func, get_func_addr_from_addr, get_idx_from_loop_list

from .dbg import address_concretization_debug, constraints_debug, state_debug_pre

from .constant import unknown_ret_addr

from .branch_type import Branch

import angr
import archinfo


def _identify_iv(proj,
                 outer_loop,
                 iv_dict=None,
                 aux_iv_dict=None,
                 timeout=1000,
                 all_branch=True):
    '''
    Given a outer loop, this function returns IVDict.
    outer_loop: (outer_loop, subloops)
    iv_dict: the identified iv

    We execute the input nested loop, set var in entry block as symbolic, 
    by assuming that IVs initialization only happens in entry block. 
    Once we are at continue edge, we decide IV based on:
        1. 
            1.1 it is increased/decreased by a constant in loop body
            or
            1.2 it is set as a constant (it happens for some reasons)
        2. branch edge dependency
        3. memory is indexed with it
    Each of the above condition is checked via breakpoint.

    To handle if-else inside nested loop:
    e.g. 2nd loop of conv2d_f_2 of glow_mnist_8_ARM_M4
    When we see if-else branch, we stash one of the branch to 'stashed' and continue. 
    After the active state reach to end, we put one of the stashed branch back to active until no stashed state.
    This should work fine assuming IV constant step will not occur in if-else. 

    To handle init-as-sym:
    We find it in iv_exit_bp(), when is too late to symbolize.
    Thus we can not gracefully force the loop to break (because of constraints).
    Our solution is find the iv, reboot the _identify_iv. 

    '''
    # config
    add_options = set()
    add_options.add(angr.sim_options.CONSTRAINT_TRACKING_IN_SOLVER)
    add_options.add(angr.sim_options.TRACK_CONSTRAINTS)
    add_options.add(angr.sim_options.TRACK_CONSTRAINT_ACTIONS)
    add_options.add(angr.sim_options.TRACK_ACTION_HISTORY)
    remove_options = set()
    remove_options.add(angr.sim_options.LAZY_SOLVES)

    # init state
    outer_loop_start_addr = outer_loop[0].entry_edge_src_blk_addr
    outer_loop_end_addr = outer_loop[0].break_edge_dest_blk_addr
    entry_state = proj.factory.blank_state(addr=outer_loop_start_addr,
                                           add_options=add_options,
                                           remove_options=remove_options)
    # prevent stucking
    entry_state.solver._solver.timeout = timeout

    # init loop
    entry_state.globals["loops"] = outer_loop[1]

    # init iv_cand, which stores candidate IV
    entry_state.globals["iv_cand"] = IVDict()

    # init iv_filtered, which stores IV have been filtered
    entry_state.globals["iv_filtered"] = IVDict()

    # init iv_dict, which are already decided
    if iv_dict is None:
        iv_dict = IVDict()
    else:
        assert (isinstance(iv_dict, IVDict))
    entry_state.globals["iv_dict"] = iv_dict

    # the auxiliary iv where symbolized is necessary (ending IV)
    if aux_iv_dict is None:
        aux_iv_dict = IVDict()
    else:
        assert (isinstance(aux_iv_dict, IVDict))
    entry_state.globals["aux_iv_dict"] = aux_iv_dict

    # reboot flag (weird when using global)
    # entry_state.globals["reboot"] = False
    proj._reboot = False

    # init the arg-init IV before registering bp
    for iv in iv_dict.values():
        if iv.from_arg:
            assert (hasattr(entry_state.regs, iv.reg))
            arg_iv_sym = entry_state.solver.BVS(iv.name, proj.bit)
            setattr(entry_state.regs, iv.reg, arg_iv_sym)

    # set lr to handle break ret edge (make sure it is before bp)
    # assert (proj.arch, archinfo.arch_arm.ArchARMEL)
    if isinstance(proj.arch, archinfo.arch_arm.ArchARMEL):
        entry_state.regs.lr = unknown_ret_addr

    # reg_write bp to make entry block symbolic and register in dict
    entry_state.inspect.b('reg_write',
                          when=angr.BP_BEFORE,
                          action=iv_entry_reg_write_bp)

    # exit bp to find IV increment/decrement (1) and loop edge dependency (2)
    entry_state.inspect.b('exit', when=angr.BP_BEFORE, action=iv_exit_bp)

    # to help check indexed_mem_write
    entry_state.inspect.b('mem_read',
                          when=angr.BP_AFTER,
                          action=iv_mem_read_bp)

    # check indexed_mem_write
    entry_state.inspect.b('mem_write',
                          when=angr.BP_BEFORE,
                          action=iv_mem_write_bp)
    
    '''
    # for debugging
    entry_state.inspect.b('constraints',
                          when=angr.BP_AFTER,
                          action=constraints_debug)
    entry_state.inspect.b('address_concretization',
                          when=angr.BP_AFTER,
                          action=address_concretization_debug)
    '''

    loop_func = proj.funcs[get_func_addr_from_addr(proj,
                                                   outer_loop_start_addr)]

    simgr = proj.factory.simgr(entry_state)

    iv_var = None

    while True:
        # state = simgr.active[0]
        # print(hex(state.addr))
        # state_debug_pre(state)

        assert (len(simgr.active) == 1)
        state = simgr.active[0]

        print(simgr.active)
        if iv_var is not None:
            print('MIN: ', state.solver.min(iv_var))
        print()

        if state.addr == 0x100241 and iv_var is None:
            iv_var = state.regs.rax

        '''
        if state.addr == 0x100290:
            from IPython import embed
            embed()
        '''

        check_before_stepping(simgr)

        print("before stepping:", simgr.active)

        simgr.step(num_inst=1)

        check_after_stepping(simgr, outer_loop)

        print("after stepping:", simgr.active)

        # check reboot flag
        if proj._reboot:
            print("\nREBOOT\n")
            _filter_iv(state)
            return state.globals['iv_dict'], state.globals[
                'aux_iv_dict'], state.globals['iv_filtered'], False

        if len(simgr.active) > 1:
            assert (len(simgr.active) == 2)
            # print(simgr.active)

            # match to the loop in outer_loop[1]
            finished_loop = None
            loop_type = Branch.NON_LOOP
            addr_pair = (simgr.active[0].addr, simgr.active[1].addr)
            for loop in outer_loop[1]:
                loop_type = loop.match_branch(addr_pair)
                if loop_type != Branch.NON_LOOP:
                    finished_loop = loop
                    break

            # for normal if-else branch, currently we just choose one path
            # assuming IV will not be increased/decreased inside of if-else
            if finished_loop is None:
                assert (loop_type == Branch.NON_LOOP)
                stashed_addr = simgr.active[1].addr
                if all_branch:
                    print("move if-else to stashed @ ", hex(stashed_addr))
                    # simgr.drop(filter_func=lambda state: True if state.addr == drop_addr else False)
                    simgr.move(from_stash='active',
                            to_stash='stashed',
                            filter_func=lambda state: True
                            if state.addr == stashed_addr else False)
                else:
                    print("drop if-else @ ", hex(stashed_addr))
                    simgr.drop(filter_func=lambda state: True if state.addr == stashed_addr else False)

            # several types of loop branch we will handle with
            else:
                # for BREAK_CONT, force execute the break edge
                # FIXME: we assume we are out of this loop here
                if loop_type == Branch.BREAK_CONT:
                    # drop the continue state
                    continue_addr = finished_loop.branch_continue_dest_addr
                    print("eliminate continue @ ", hex(continue_addr))
                    simgr.drop(filter_func=lambda state: True
                               if state.addr == continue_addr else False)

                # we dont follow break edge since there are more logic ahead
                elif loop_type == Branch.BREAK:
                    # drop the (fake) break state
                    break_addr = finished_loop.break_edge_dest_blk_addr
                    assert (break_addr in addr_pair)
                    print("eliminate break @ ", hex(break_addr))
                    simgr.drop(filter_func=lambda state: True
                               if state.addr == break_addr else False)

                else:
                    assert (False)

        # print(simgr.active)

        if simgr.active:
            assert (len(simgr.active) == 1)
            state = simgr.active[0]  # important to use the latest state
            # state_debug_post(state)
            # the state reaches the end of outer loop
            if state.addr == outer_loop_end_addr or not check_in_func(
                    loop_func, state.addr):
                print("end of outer loop @ ", hex(state.addr))
                simgr.move(from_stash='active',
                           to_stash='deadended',
                           filter_func=lambda state: True)

        # if no state in 'active' and 'stashed' stash, that's the end
        if not simgr.active and not simgr.stashed:
            _filter_iv(state)
            return state.globals['iv_dict'], state.globals[
                'aux_iv_dict'], state.globals['iv_filtered'], True

        # state can be pruned because of unsat or just being moved to deadended
        if not simgr.active and simgr.stashed:
            # there could serveral stashed state with the same addr
            stashed_state_addr = simgr.stashed[0].addr
            stashed_state_id = id(simgr.stashed[0])
            print("move stash to active @ ", hex(stashed_state_addr))
            # by checking id, we essentially execute every possible path, which is time-consuming
            simgr.move(from_stash='stashed',
                       to_stash='active',
                       filter_func=lambda state: True
                       if id(state) == stashed_state_id else False)


def check_before_stepping(simgr):
    '''
    in x86, a normal if-else might introduce unsat path for breaking the loop.
    however, instead of being "unsat", its symvar has very large MIN value.
    we manually test such condition
    '''
    for state in simgr.active:
        unsat_flag = False
        for iv_cand in state.globals['iv_cand']:
            iv_cand_var = state.globals['iv_cand'][iv_cand].iv_var
            if state.solver.min(iv_cand_var) > 0xFFFFFF:
                unsat_flag = True
                break

        if unsat_flag:
            # move the current state to unsat 
            print("move to unsat: ", hex(state.addr))
            state_id = id(state)
            simgr.move(from_stash='active',
                        to_stash='unsat',
                        filter_func=lambda s: True
                        if id(s)== state_id else False)


def check_after_stepping(simgr, outer_loop):
    '''
    check:
        1. unsupported irop
        2. an unsat state does not fork
    '''
    # 1. no unsupported irop
    if simgr.errored:
        print(simgr.errored)
        from IPython import embed
        embed()
        assert (False)

    # 2. an unsat state does not fork
    if len(simgr.active) == 1:
        state = simgr.active[0]
        for loop in outer_loop[1]:
            if loop.branch_continue_dest_addr == state.addr:
                if loop.branch_continue_src_addr == state.history.addr: 
                    # this state follows continue edges without forking, 
                    # so we discard it
                    print("move to unsat: ", hex(state.addr))
                    state_id = id(state)
                    simgr.move(from_stash='active',
                                to_stash='unsat',
                                filter_func=lambda s: True
                                if id(s)== state_id else False)
                    return



def _filter_iv(state):
    '''
    In the end, we filter out the iv 
        1. without increment or 
        2. no branch depends on it
        3. no indexed_mem_write
    We filter here because of multiple break edges, some of them happen
    before increment
    '''
    to_remove = set()

    for iv_addr in state.globals['iv_cand']:
        iv = state.globals['iv_cand'][iv_addr]
        assert (iv.init_sym == False)
        if iv.increment is None:
            to_remove.add(iv_addr)
        if iv.exit_condition is None:
            to_remove.add(iv_addr)

        # TODO: identify something here
        if len(iv.indexed_mem_write) == 0:
            # commented for avg pooling
            # to_remove.add(iv_addr)
            pass

    for iv_addr in to_remove:
        # print("[iv_exit_bp @", hex(state.addr), "] remove iv: ", state.globals['iv_cand'][iv_addr])
        popped_iv = state.globals['iv_cand'].pop(iv_addr)
        assert (iv_addr not in state.globals['iv_filtered'])
        state.globals['iv_filtered'][iv_addr] = popped_iv

    for iv_addr, iv in state.globals['iv_cand'].items():
        assert (iv_addr not in state.globals['iv_dict'])
        state.globals['iv_dict'][iv_addr] = iv


def _check_iv(outer_loop, iv_dict):
    '''
    check if all ivs of loops in outer_loop are extracted in iv_dict 
    '''
    for l in outer_loop[1]:
        if not iv_dict.lookup_loop(l):
            return False

    if len(outer_loop[1]) != len(iv_dict):
        return False

    return True


def _assign_iv(outer_loop, iv_dict, iv_aux):
    outer_loop[0].set_iv_dict(iv_dict)
    outer_loop[0].set_aux_iv_dict(iv_aux)

    for iv_addr in iv_dict:
        iv_loop = iv_dict[iv_addr].loop
        assert (iv_loop in outer_loop[1])
        idx = outer_loop[1].index(iv_loop)
        outer_loop[1][idx].set_iv(iv_dict[iv_addr])

    for iv_addr in iv_aux:
        iv_loop = iv_dict[iv_addr].loop
        assert (iv_loop in outer_loop[1])
        idx = outer_loop[1].index(iv_loop)
        outer_loop[1][idx].set_iv(iv_dict[iv_addr])


def identify_iv(proj, func_addr, outer_loop_idx, all_branch=True):
    '''
    Wrapper for _identify_iv.
    
    Try timeout = 500 first and check iv, if fail, set timeout = 2000 and try again 
    Also call estimate_iv() to estimate each iv's loop count value
    '''

    assert (func_addr in proj.funcs)
    assert (outer_loop_idx in range(len(proj.outer_loops[func_addr])))

    outer_loop = proj.outer_loops[func_addr][outer_loop_idx]

    iv_dict, iv_aux, iv_filtered, finish = _identify_iv(proj,
                                                        outer_loop,
                                                        timeout=1000,
                                                        all_branch=all_branch)

    while not finish:
        iv_d, iv_a, iv_f, finish = _identify_iv(proj,
                                                outer_loop,
                                                iv_dict=iv_dict,
                                                aux_iv_dict=iv_aux,
                                                all_branch=all_branch)
        iv_dict = iv_d
        iv_aux = iv_a

        assert (len(iv_dict) <= len(outer_loop[1]))
        if len(iv_dict) == len(outer_loop[1]):
            break

    if not _check_iv(outer_loop, iv_dict):
        print("[identify_iv]: not pass check")
        from IPython import embed
        embed()

    _estimate_iv(proj, iv_dict, iv_filtered)

    # renaming
    for iv in iv_dict.values():
        iv.name = iv.name.replace("CAND_", "")

    _assign_iv(outer_loop, iv_dict, iv_aux)

    print(iv_dict)

    return iv_dict, iv_aux
