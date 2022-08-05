from copy import copy

from .dbg import mem_read_debug

from .mem_record import MemRecord
from .anno import IVAnnotation, IncrementAnnotation, MemReadAnnotation

from .utils import get_iv_anno, get_num_leaf_asts, get_reg_name, replace_64_to_32, retrieve_iv_var, check_iv, check_iv_expr

import claripy


def ast_reg_write_bp_iv_init(state):
    '''
    If we are at one loop's iv addr, we assign with symbolic iv
    '''

    if state.addr in state.globals['outer_loop'][0]._iv_dict:
        iv = state.globals['outer_loop'][0]._iv_dict[state.addr]
        iv_sym_name = "IV_" + str(hex(state.addr))
    elif state.addr in state.globals['outer_loop'][0]._aux_iv_dict:
        iv = state.globals['outer_loop'][0]._aux_iv_dict[state.addr]
        iv_sym_name = "IV_AUX_" + str(hex(state.addr))
    else:
        return

    # get reg name
    reg_offset = state.inspect.reg_write_offset
    if isinstance(reg_offset, claripy.ast.bv.BV):
        assert (reg_offset.concrete)
        reg_offset = state.solver.eval(reg_offset)
    reg_size = state.inspect.reg_write_length
    reg_name = get_reg_name(state.project.arch, reg_offset, reg_size)

    # return if not iv_reg
    if reg_name != iv.reg:
        return

    # init iv_sym
    iv_sym = state.solver.BVS(iv_sym_name, state.project.bit).annotate(
        IVAnnotation(state.addr))
    iv.set_iv_var(iv_sym)
    print("[ast_reg_write_bp_iv_init] @ ", hex(state.addr), " init ", iv_sym)

    state.inspect.reg_write_expr = iv_sym

    # We dont add constraints for aux iv
    if iv.is_aux:
        return

    # book keep
    state.globals['iv_dict'][state.addr] = iv_sym

    # it is bad because it rules out many possibilities
    # state.add_constraints(iv_sym == iv.init_val)

    # we add lb/ub contraints to iv
    lb, ub, type = iv.get_constraints()
    if type == 'increase':
        state.add_constraints(iv_sym >= lb)
        state.add_constraints(iv_sym <= ub)
    elif type == 'decrease':
        # FIXME: not sure, especially the lb condition
        state.add_constraints(iv_sym > lb)
        state.add_constraints(iv_sym <= ub)
        assert (False)
    else:
        # we dont have the type = 'set' right now
        pass
        # assert (False)

    # FIXME
    # we also add the modulo constraints
    pass


def ast_reg_write_bp_iv_simplify(state):
    expr = state.inspect.reg_write_expr

    if not check_iv_expr(expr):
        return
    if expr.op == 'BVS':
        return

    # handle or
    if expr.op == '__or__':
        if not check_iv_expr(expr.args[0]):
            return
        if not expr.args[1].concrete:
            return

        # the iv var
        iv_list = retrieve_iv_var(expr)

        # TODO: we should prove "orr | 1 == add 1"
        pass

        ret = (expr.args[0] +
               expr.args[1].annotate(IncrementAnnotation(state.addr)))
        iv_anno_list = get_iv_anno(expr.args[0])
        ret = ret.annotate(*iv_anno_list)
        state.inspect.reg_write_expr = ret
        return

    # handle add
    if expr.op == '__add__':
        if not check_iv(expr.args[0]):
            return
        if not expr.args[1].concrete:
            return

        ret = (expr.args[0] +
               expr.args[1].annotate(IncrementAnnotation(state.addr)))
        iv_anno_list = get_iv_anno(expr.args[0])
        state.inspect.reg_write_expr = ret.annotate(*iv_anno_list)
        return

    # handle simplified or
    # this should be deprecated after we annotate the IV at init
    if expr.op == 'Concat':
        if expr.args[0].op != 'Extract':
            return
        if not check_iv(expr.args[0].args[2]):
            return

        # the iv var
        iv_list = retrieve_iv_var(expr)
        assert (len(iv_list) == 1)
        iv = iv_list[0]

        # now we extract the "offset"
        offset = 0
        for arg in expr.args[1:]:
            if arg.concrete:
                offset = offset << arg.size()
                offset += state.solver.eval(arg)
            else:
                # here we assume the sym is 0, we will prove later
                offset = offset << arg.size()

        # FIXME: use solver to prove we are right
        pass

        ret = (iv + offset)
        iv_anno_list = get_iv_anno(expr.args[0])
        ret = ret.annotate(*iv_anno_list)
        state.inspect.reg_write_expr = ret
        return


def ast_mem_read_bp(state):
    '''
    When memory read, we use the annotated address as the expr
    '''
    src_addr = state.inspect.mem_read_address

    # return if concrete
    if src_addr.concrete:
        return

    # mem_read_debug(state)

    # there could be no iv in src_addr
    iv_list = []
    for v in src_addr.variables:
        if "IV" in v:
            iv_list.append(v)
    

    # handle the mismatch between 64-bit address and 32-bit data
    # it is an issue when manipulating the data, which should be a 32-bit symvar
    # now we truncate src_addr to 32 bits, with an annotation indicating such case
    if src_addr.size() == 64:
        src_addr = replace_64_to_32(state, src_addr)
    
    '''
    if src_addr.size() == 64 and get_num_leaf_asts(src_addr) != 1:
        from IPython import embed
        embed()
    if src_addr.size() == 64:
        name = '_'.join(src_addr.__str__().split(' ')[1].split('_')[:2])
        src_addr = claripy.BVS(name, 32)
    '''

    # put annotated addr to register
    state.inspect.mem_read_expr = src_addr.annotate(
        MemReadAnnotation(state.addr))

    state.project.mem_read_dict[state.addr] = MemRecord(
        state.inspect.mem_read_address, state.inspect.mem_read_expr,
        state.inspect.mem_read_condition)


def check_additional_constraints(state):
    '''
    check if additional constraints imposed to iv[i] + iv[j]
    '''
    cond = []

    iv_list = list(state.globals['iv_dict'].values())
    for i in range(len(iv_list)):
        for j in range(i, len(iv_list)):
            min = state.solver.min(iv_list[i] + iv_list[j])
            ori_min = state.solver.min(iv_list[i]) + state.solver.min(
                iv_list[j])

            max = state.solver.max(iv_list[i] + iv_list[j])
            ori_max = state.solver.max(iv_list[i]) + state.solver.max(
                iv_list[j])

            # TODO: theorectically it should 'and'
            if min != ori_min or max != ori_max:
                '''
                print(iv_list[i], " and ", iv_list[j])
                print("origin min: ", ori_min, " min: ", min)
                print()
                '''
                assert (ori_min < min or max < ori_max)
                cond.append((iv_list[i], iv_list[j]))

    return cond


def ast_mem_write_bp(state):
    '''
    Collect ast from memory write, only when write_addr is symbolic.
    If cond_flag is on, we put processed constraints into MemRecord.cond
    '''
    write_expr = state.inspect.mem_write_expr
    write_addr = state.inspect.mem_write_address

    # return if concrete
    if write_addr.concrete:
        return

    # collect (un)completed_loop_entry
    completed_loop_entry = [
        key for key, value in state.locals['completed_loops'].items() if value
    ]
    ongoing_loop_entry = [
        key for key, value in state.locals['completed_loops'].items()
        if not value
    ]

    cond = []
    if state.globals['flag']['cond']:
        cond = check_additional_constraints(state)

    # what is it?
    assert (state.inspect.mem_write_condition is None)

    record = MemRecord(state.inspect.mem_write_address,
                       state.inspect.mem_write_expr,
                       cond=cond,
                       completed_loop_entry=completed_loop_entry,
                       ongoing_loop_entry=ongoing_loop_entry,
                       outer_loop=state.globals['outer_loop'])

    print("[ast_mem_write_bp] mem_write @ ", hex(state.addr))

    if state.addr not in state.project.mem_write_dict:
        state.project.mem_write_dict[state.addr] = [record]
    else:
        state.project.mem_write_dict[state.addr].append(record)


def ast_address_concretization_bp(state):
    '''
    Dont add constraints when concretizing addr with IV
    '''
    addr_expr = state.inspect.address_concretization_expr
    # print("[ast_address_concretization_bp @ ", hex(state.addr), "addr_expr: ",
    #      addr_expr)
    if check_iv_expr(addr_expr):
        print("[ast_address_concretization_bp @ ", hex(state.addr),
              " disable adding constraints")
        state.inspect.address_concretization_add_constraints = False


def ast_constraints_bp(state):
    '''
    '''
    print(
        "[ast_constraints_bp] @ ",
        hex(state.addr),
    )
    for cst in state.inspect.added_constraints:
        if check_iv_expr(cst):
            print(cst)
    # print(state.solver.constraints)
    print()


def ast_fork_bp(state):
    from IPython import embed
    embed()
    assert (False)
