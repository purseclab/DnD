from .iv import IV

from .utils import check_in_block, get_iv_anno, get_iv_expr, get_num_leaf_asts, retrieve_from_addition_expr, get_outer_iv_expr, flatten_add_expr, simplify_and_sort
from .utils import get_reg_name
from .utils import check_regular_register
from .utils import retrieve_iv_var

from .anno import IVAnnotation, MemReadAnnotation

from .dbg import exit_debug, mem_read_debug, mem_write_debug, reg_write_debug, print_anno

import claripy

import math


def _reg_write_handle_found_iv(state, found_iv, reg_name):
    print("[_reg_write_handle_found_iv] @ %s: %s" %
          (hex(state.addr), found_iv))
    # print(state.inspect.reg_write_expr)
    assert (found_iv.reg == reg_name)
    if not state.inspect.reg_write_expr.concrete:
        # it is a iv-init-as-sym
        assert (found_iv.init_sym == True)
        found_iv.init_val = state.inspect.reg_write_expr
        sym_name = "IV_" + str(hex(state.addr))
        iv_cand_sym = state.solver.BVS(sym_name, state.project.bit)
        found_iv.set_iv_var(iv_cand_sym)
        state.inspect.reg_write_expr = iv_cand_sym
    else:
        assert (found_iv.init_sym == False)
        constant = state.solver.eval(state.inspect.reg_write_expr)
        assert (found_iv.init_val == constant)
        sym_name = "IV_" + str(hex(state.addr))
        iv_cand_sym = state.solver.BVS(sym_name, state.project.bit)
        found_iv.set_iv_var(iv_cand_sym)
        state.inspect.reg_write_expr = iv_cand_sym


def iv_entry_reg_write_bp(state):
    '''
    reg_write_bp for IV identification.
    For every register write with constant in loop entry block, 
    we replace it with symbolic val and register in the state.globals.IV_cand.
    '''

    # reg_write_debug(state)

    # get written reg name
    reg_offset = state.inspect.reg_write_offset
    if isinstance(reg_offset, claripy.ast.bv.BV):
        assert (reg_offset.concrete)
        reg_offset = state.solver.eval(reg_offset)
    reg_size = state.inspect.reg_write_length
    # print(state.inspect.reg_write_length)
    reg_name = get_reg_name(state.project.arch, reg_offset, reg_size)

    # print("REG NAME @ ", hex(state.addr), " ", reg_name)
    '''
    if reg_name == 'rax':
        from IPython import embed
        embed()
        assert (False)
    '''

    # if not regular register, return
    if not check_regular_register(state.project.arch, reg_name):
        return

    # reg_write_debug(state)

    # If this loop IV has been found, we only continue with the found IV
    # Note that for this case, IV might not be in the entry blk
    found_iv_list = [
        iv for iv in state.globals['iv_dict'].values() if iv.addr == state.addr
    ]
    assert (len(found_iv_list) == 0 or len(found_iv_list) == 1)
    if len(found_iv_list) == 1:
        _reg_write_handle_found_iv(state, found_iv_list[0], reg_name)
        # print("[iv_entry_reg_write_bp] found_iv")
        return

    # If auxilary IV is here, we make it symbolic and continue
    aux_iv_list = [
        iv for iv in state.globals['aux_iv_dict'].values()
        if iv.addr == state.addr
    ]
    assert (len(aux_iv_list) == 0 or len(aux_iv_list) == 1)
    if len(aux_iv_list) == 1:
        aux_iv = aux_iv_list[0]
        if aux_iv.reg == reg_name:
            sym_name = "IV_CAND_" + str(hex(state.addr))
            iv_cand_sym = state.solver.BVS(sym_name, state.project.bit)
            aux_iv.set_iv_var(iv_cand_sym)
            state.inspect.reg_write_expr = iv_cand_sym.annotate(
                IVAnnotation(addr=state.addr, reg=reg_name))
            # print("[iv_entry_reg_write_bp] aux_iv")
            return

    # if state.addr not in any entry block, just return
    loop = None
    entry_blk_list = []
    for l in state.globals['loops']:
        for b in l.entry_edge_src_blk:
            entry_blk_list.append((b, l))

    for (ent_blk, l) in entry_blk_list:
        if check_in_block(ent_blk, state.addr):
            loop = l
            break
    if not loop:
        # print("[iv_entry_reg_write_bp] not in entry")
        return

    if not state.inspect.reg_write_expr.concrete:
        # if written expr not constant, we annotate it and return
        print("[iv_entry_reg_write_bp] symbolic written @ ", hex(state.addr),
              "with ", state.inspect.reg_write_expr)
        state.inspect.reg_write_expr = state.inspect.reg_write_expr.annotate(
            IVAnnotation(addr=state.addr, reg=reg_name))
        return

    constant = state.solver.eval(state.inspect.reg_write_expr)

    # if the constant is too big, it might be a stack offset
    if constant > 0xffffff:
        return

    # if constant, we take as an IV candidate
    sym_name = "IV_CAND_" + str(hex(state.addr))
    iv_cand_sym = state.solver.BVS(sym_name, state.project.bit)
    state.inspect.reg_write_expr = iv_cand_sym

    # bookkeep in state.globals
    iv = IV(addr=state.addr,
            reg=reg_name,
            name=sym_name,
            loop=loop,
            init_val=constant)
    iv.set_iv_var(iv_cand_sym)
    state.globals["iv_cand"][state.addr] = iv
    print("[iv_entry_reg_write_bp @", hex(state.addr), "] create iv cand: ",
          iv)


def _exit_bp_handle_iv_sym_init(state, loop):
    '''
    Helper func for iv_exit_bp to handle case where iv init as sym
    '''

    iv_expr_list = list(get_outer_iv_expr(state.inspect.exit_guard))
    assert (len(iv_expr_list) == 2 or len(iv_expr_list) == 1)

    # One sym var: passed-in reg and the ending var
    if len(iv_expr_list) == 1:
        e0 = iv_expr_list[0]
        assert (e0.op == '__add__')

        # create argument IV
        reg_var = e0.args[0] if e0.args[1].op == 'BVV' else e0.args[1]
        reg_offset = int(reg_var.__str__().split('_')[1], 16)
        reg_size = int(reg_var.__str__().split('_')[-1].split('{')[0]) // 4
        reg_name = get_reg_name(state.project.arch, reg_offset, reg_size)
        start_arg_sym_name = "IV_ARG_-" + str(hex(state.addr))
        start_arg_iv = IV(addr=-state.addr,
                          reg=reg_name,
                          name=start_arg_sym_name,
                          loop=loop,
                          init_sym=False,
                          from_arg=True)
        state.globals["iv_dict"][-state.addr] = start_arg_iv

        # create aux argument IV
        assert (len(get_iv_anno(e0)) == 1)
        aux_iv_anno = get_iv_anno(e0)[0]
        aux_iv_addr = aux_iv_anno.addr
        aux_iv_reg = aux_iv_anno.reg
        end_aux_sym_name = "IV_AUX_" + str(hex(aux_iv_addr))
        end_aux_arg_iv = IV(addr=aux_iv_addr,
                            reg=aux_iv_reg,
                            name=end_aux_sym_name,
                            loop=loop,
                            init_sym=False,
                            from_arg=True,
                            is_aux=True)
        print("[_exit_bp_handle_iv_sym_init] passed-in", hex(aux_iv_addr))
        # TODO: the address here could be wrong
        state.globals["aux_iv_dict"][aux_iv_addr] = end_aux_arg_iv

        # decide iv increment and loop_count
        reg_expr = getattr(state.regs, start_arg_iv.reg)
        reg_expr_con, reg_expr_sym = retrieve_from_addition_expr(reg_expr)
        assert (reg_expr_sym.structurally_match(reg_var))
        start_arg_iv.increment = state.solver.eval(reg_expr_con)

        e0_con, e0_sym = retrieve_from_addition_expr(e0)
        start_arg_iv.loop_count = math.ceil(
            state.solver.eval(e0_con) / start_arg_iv.increment)

        # let's reboot
        state.project._reboot = True

    # Two sym variable: IV def and loop ending var
    elif len(iv_expr_list) == 2:

        # iv_expr_list.sort(key=get_num_leaf_asts)
        iv_expr_list = simplify_and_sort(iv_expr_list, state.solver)
        e0, e1 = iv_expr_list[0], iv_expr_list[1]

        assert (e1.op == '__add__' or e1.op == '__sub__')

        if not e0.structurally_match(e1.args[0]) and not e0.structurally_match(
                e1.args[1]):
            print("[_exit_bp_handle_iv_sym_init] does not match")

        # create start IV
        assert (len(get_iv_anno(e0)) == 1)
        start_iv_anno = get_iv_anno(e0)[0]
        start_iv_addr = start_iv_anno.addr
        start_iv_reg = start_iv_anno.reg
        start_sym_name = "IV_" + str(hex(start_iv_addr))
        start_iv = IV(addr=start_iv_addr,
                      reg=start_iv_reg,
                      name=start_sym_name,
                      loop=loop,
                      init_sym=True)
        state.globals["iv_dict"][start_iv_addr] = start_iv

        # create end IV (ending must be derived from start IV)
        assert (len(get_iv_anno(e1)) == 1)
        end_iv_anno = get_iv_anno(e1)[0]
        end_iv_addr = end_iv_anno.addr
        end_iv_reg = end_iv_anno.reg
        end_sym_name = "IV_AUX_" + str(hex(end_iv_addr))
        end_iv = IV(addr=end_iv_addr,
                    reg=end_iv_reg,
                    name=end_sym_name,
                    loop=loop,
                    init_sym=True,
                    is_aux=True)
        print("[_exit_bp_handle_iv_sym_init] two-sym", hex(start_iv_addr))
        state.globals["aux_iv_dict"][start_iv_addr] = end_iv

        # decide the increment and the loop_count
        reg_expr = getattr(state.regs, start_iv.reg)
        reg_expr_con, reg_expr_sym = retrieve_from_addition_expr(reg_expr)
        # it's not true because of the simplication
        # assert (reg_expr_sym.structurally_match(e0))
        start_iv.increment = state.solver.eval(reg_expr_con)

        e1_con, e1_sym = retrieve_from_addition_expr(e1)
        start_iv.loop_count = math.ceil(
            state.solver.eval(e1_con) / start_iv.increment)

        # it is for checking if loop count is calculated correctly if __sub__
        if e1.op != '__add__':
            from IPython import embed
            embed()

        # let's reboot
        state.project._reboot = True

    else:
        assert (False)


def iv_exit_bp(state):
    '''
    For every loop break_edge/continue_edge, we check all related IVs.

    Two things about Vex IR:
        1. there are branches which only jump to next instruction
        2. for the loop branch instruction, iv_exit_bp will be triggered twice 

    We can know an IV is init as sym when we check exit_condition
    '''

    # exit_debug(state)

    # since we dont check if it is the last inst of the block, we check the condition
    if state.inspect.exit_guard.concrete:
        return

    # check found iv
    found_iv_addr_list = state.globals['iv_dict'].lookup_branch(state.addr)
    assert (len(found_iv_addr_list) == 0 or len(found_iv_addr_list) == 1)
    if len(found_iv_addr_list) == 1:
        found_iv = state.globals['iv_dict'][found_iv_addr_list[0]]
    else:
        found_iv = None

    # check if the state is in branch block, collect all the corresponding iv
    # it is because if-else branch happpens inside of loop
    loop = None
    for l in state.globals['loops']:
        if state.addr in l.branch_addr:
            loop = l
            break
    if loop is None:
        return

    # Two iv_exit_bp() are triggered for one branch,
    # we only handle with break edge since we want to collect exit_condition
    # FIXME: here, we might not handle some cases, since condition can be in continue
    # TODO: assert something here
    # FIXME: should be from the iv_addr_list?
    assert (state.inspect.exit_target.concrete)
    exit_target = state.solver.eval(state.inspect.exit_target)
    exit_target_flag = False
    for l in state.globals['loops']:
        if l.check_break_edge_dest(exit_target):
            exit_target_flag = True
            break
    if not exit_target_flag:
        return

    exit_debug(state)

    # whether related IV is in exit_guard
    iv_in_cand_iv_addr = False
    # the iv_addr list we will do pattern matching to derive inc
    check_inc_list = []
    exit_guard_variables = [
        v for v in state.inspect.exit_guard.variables if 'IV' in v
    ]

    # handle with the found_iv first
    if found_iv is not None:
        print("[found iv]: ", found_iv)
        # iv_addr_list could contain elements, since IV can be init in previous blk
        # assert (len(iv_addr_list) == 0)
        # print(exit_guard_variables)
        # print(found_iv.name)
        if not (any([found_iv.name in v for v in exit_guard_variables])):
            from IPython import embed
            embed()
        found_iv.exit_condition = state.inspect.exit_guard
        return

    '''
    if state.addr == 0x100260:
        from IPython import embed
        embed()
    '''

    # if related cand iv in the exit_guard, we append condition to iv.exit_condition
    cand_iv_addr_list = state.globals['iv_cand'].lookup_branch(state.addr)
    for iv_addr in cand_iv_addr_list:
        iv = state.globals['iv_cand'][iv_addr]
        if any([iv.name in v for v in exit_guard_variables]):
            iv_in_cand_iv_addr = True
            # FIXME: currently we only support one
            if iv.exit_condition != None:
                if not iv.exit_condition.structurally_match(
                        state.inspect.exit_guard):
                    # assert (iv.exit_condition == state.inspect.exit_guard)
                    pass
            iv.exit_condition = state.inspect.exit_guard
            check_inc_list.append(iv_addr)
            print("[append iv exit_guard @ %s] append" % hex(state.addr),
                  state.inspect.exit_guard, "to ", iv.name)

    # if no iv (in iv_addr) in the exit_guard, but other iv in,
    # we know it could be "iv init as sym" case
    if not iv_in_cand_iv_addr:
        _exit_bp_handle_iv_sym_init(state, loop)
        return

    '''
    if state.addr == 0x10085f:
        from IPython import embed
        embed()
    '''

    # If we have the pre-defined IV, we check if the reg is incremented by a constant
    for iv_addr in check_inc_list:
        iv = state.globals['iv_cand'][iv_addr]
        reg_expr = getattr(state.regs, iv.reg)
        if reg_expr.op == '__add__' and len(reg_expr.args) == 2:
            # arg 0 is constant
            if reg_expr.args[0].concrete and reg_expr.args[
                    0].op == 'BVV' and reg_expr.args[1].op == 'BVS':
                iv.increment = state.solver.eval(reg_expr.args[0])
            # arg 1 is constant
            elif reg_expr.args[1].concrete and reg_expr.args[
                    1].op == 'BVV' and reg_expr.args[0].op == 'BVS':
                iv.increment = state.solver.eval(reg_expr.args[1])
        if reg_expr.op == '__sub__' and len(reg_expr.args) == 2:
            if reg_expr.args[0].op == 'BVS' and reg_expr.args[
                    1].concrete and reg_expr.args[1].op == 'BVV':
                iv.increment = 0 - state.solver.eval(reg_expr.args[1])
        if reg_expr.op == 'BVV':
            if state.solver.eval(reg_expr) != 0:
                iv.increment = 0
    
    '''
    if state.addr == 0x100803:
        from IPython import embed
        embed()
    '''

    # exit_debug(state)


def iv_mem_read_bp(state):
    '''
    For collecting iv's indexed_mem_write, we need to 
    replace mem_read_expr with mem_read_address
    '''

    # mem_read_debug(state)

    src_addr = state.inspect.mem_read_address

    # return if concrete
    if src_addr.concrete:
        return

    # put annotated addr to register
    state.inspect.mem_read_expr = src_addr.annotate(
        MemReadAnnotation(state.addr))


def iv_mem_write_bp(state):
    '''
    Just collect iv's indexed_mem_write
    '''

    # mem_write_debug(state)

    write_expr = state.inspect.mem_write_expr
    write_addr = state.inspect.mem_write_address

    # write_addr must be symbolic to filter stack writing
    if write_expr.symbolic and write_addr.symbolic:
        for iv in state.globals['iv_cand'].values():
            for v in write_expr.variables:
                if iv.name in v:
                    iv.indexed_mem_write.append(state.addr)

    # constant writing to symbolic mem
    if write_addr.symbolic:
        for iv in state.globals['iv_cand'].values():
            for v in write_addr.variables:
                if iv.name in v:
                    iv.indexed_mem_write.append(state.addr)
