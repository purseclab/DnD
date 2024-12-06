from copy import copy

from .dbg import mem_read_debug, print_anno

from .mem_record import MemRecord
from .anno import IVAnnotation, IncrementAnnotation, MemReadAnnotation

from .utils import (
    get_iv_anno,
    get_num_leaf_asts,
    get_reg_name,
    replace_64_to_32,
    retrieve_iv_var,
    check_iv,
    check_iv_expr,
)

import claripy


def ast_reg_write_bp_iv_init(state):
    """
    If we are at the definition point of a IV, we assign the reg with a symbolic variable
    """
    # print("[ast_reg_write_bp_iv_init] @ ", hex(state.addr))
    # print_anno(state.inspect.reg_write_expr)
    # print("expr id: ", id(state.inspect.reg_write_expr))

    if state.addr in state.globals["outer_loop"][0]._iv_dict:
        iv = state.globals["outer_loop"][0]._iv_dict[state.addr]
        iv_sym_name = "IV_" + str(hex(state.addr))
    elif state.addr in state.globals["outer_loop"][0]._aux_iv_dict:
        iv = state.globals["outer_loop"][0]._aux_iv_dict[state.addr]
        iv_sym_name = "IV_AUX_" + str(hex(state.addr))
    else:
        return

    # get reg name
    reg_offset = state.inspect.reg_write_offset
    if isinstance(reg_offset, claripy.ast.bv.BV):
        assert reg_offset.concrete
        reg_offset = state.solver.eval(reg_offset)
    reg_size = state.inspect.reg_write_length
    reg_name = get_reg_name(state.project.arch, reg_offset, reg_size)

    # return if not iv_reg
    if reg_name != iv.reg:
        return

    # init iv_sym
    iv_sym = state.solver.BVS(iv_sym_name, state.project.bit).annotate(
        IVAnnotation(state.addr)
    )
    iv.set_iv_var(iv_sym)
    print("[ast_reg_write_bp_iv_init] @ ", hex(state.addr), " init ", iv_sym)

    state.inspect.reg_write_expr = iv_sym

    # We dont add constraints for aux iv
    if iv.is_aux:
        return

    # book keep
    state.globals["iv_dict"][state.addr] = iv_sym

    # it is bad because it rules out many possibilities
    # state.add_constraints(iv_sym == iv.init_val)

    # we add lb/ub contraints to iv
    lb, ub, type = iv.get_constraints()
    if type == "increase":
        state.add_constraints(iv_sym >= lb)
        state.add_constraints(iv_sym <= ub)
    elif type == "decrease":
        # FIXME: not sure, especially the lb condition
        state.add_constraints(iv_sym > lb)
        state.add_constraints(iv_sym <= ub)
        assert False
    else:
        # we dont have the type = 'set' right now
        pass
        # assert (False)

    # FIXME
    # we also add the modulo constraints


def ast_reg_write_bp_iv_simplify(state):
    """
    Some heuristic to simplify the symbolic expression that contains IV symvar
    """
    expr = state.inspect.reg_write_expr
    # print("[ast_reg_write_bp_iv_simplify] @ ", hex(state.addr))
    # print("[ast_reg_write_bp_iv_simplify] expr: ", expr)
    # print("expr id: ", id(state.inspect.reg_write_expr))
    # print_anno(expr)

    if not check_iv_expr(expr):
        return
    if expr.op == "BVS":
        return

    # handle or
    if expr.op == "__or__":
        if not check_iv_expr(expr.args[0]):
            return
        if not expr.args[1].concrete:
            return

        print("[ast_reg_write_bp_iv_simplify] handling or @ ", hex(state.addr))

        # the iv var
        iv_list = retrieve_iv_var(expr)

        # TODO: we should prove "orr | 1 == add 1"
        pass

        ret = expr.args[0] + expr.args[1].annotate(IncrementAnnotation(state.addr))
        iv_anno_list = get_iv_anno(expr.args[0])
        ret = ret.annotate(*iv_anno_list)
        state.inspect.reg_write_expr = ret
        return

    # handle add
    if expr.op == "__add__":
        if not check_iv(expr.args[0]):
            return
        if not expr.args[1].concrete:
            return

        print("[ast_reg_write_bp_iv_simplify] handling add @ ", hex(state.addr))

        ret = expr.args[0] + expr.args[1].annotate(IncrementAnnotation(state.addr))
        iv_anno_list = get_iv_anno(expr.args[0])
        state.inspect.reg_write_expr = ret.annotate(*iv_anno_list)
        return

    # handle simplified or
    # this should be deprecated after we annotate the IV at init
    if expr.op == "Concat":
        if expr.args[0].op != "Extract":
            return
        if not check_iv(expr.args[0].args[2]):
            return

        print("[ast_reg_write_bp_iv_simplify] handling concat @ ", hex(state.addr))

        # the iv var
        iv_list = retrieve_iv_var(expr)
        assert len(iv_list) == 1
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

        ret = iv + offset
        iv_anno_list = get_iv_anno(expr.args[0])
        ret = ret.annotate(*iv_anno_list)
        state.inspect.reg_write_expr = ret
        return


def ast_mem_read_bp(state):
    """
    When memory read, we use the annotated address as the expr
    i.e., the return val is the address expression rather than value expression
    """
    print("[ast_mem_read_bp] @ ", hex(state.addr))
    print("read_addr: ", state.inspect.mem_read_address)

    src_addr = state.inspect.mem_read_address

    # if state.addr == 0x600060c5:
    #     from IPython import embed
    #     embed()
    #     assert False

    # return if concrete
    # TODO: This is record the bias of convolution (loaded in the first nested loop). A better way is to annotate or symbolize the value so that we know it when later it is accumulated. Here we assume sequantial read.
    if src_addr.concrete:
        expr = state.inspect.mem_read_expr
        if (
            expr.concrete
            and expr.args[0] != 0
            and abs(src_addr.args[0] - state.regs.sp.args[0]) > 0x100
        ):
            print("push to constant_read_list: ", expr)
            state.project.constant_read_list.append(expr)
            state.project.constant_read_mem_list.append(src_addr)
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

    # if src_addr.size() == 64 and get_num_leaf_asts(src_addr) != 1:
    #     from IPython import embed
    #     embed()
    # if src_addr.size() == 64:
    #     name = '_'.join(src_addr.__str__().split(' ')[1].split('_')[:2])
    #     src_addr = claripy.BVS(name, 32)

    # put annotated addr to register
    state.inspect.mem_read_expr = src_addr.annotate(MemReadAnnotation(state.addr))

    state.project.mem_read_dict[state.addr] = MemRecord(
        state.inspect.mem_read_address,
        state.inspect.mem_read_expr,
        state.inspect.mem_read_condition,
        op_addr=state.addr,
    )


def check_additional_constraints(state):
    """
    check if additional constraints imposed to iv[i] + iv[j]
    """
    cond = []

    iv_list = list(state.globals["iv_dict"].values())
    for i in range(len(iv_list)):
        for j in range(i, len(iv_list)):
            min = state.solver.min(iv_list[i] + iv_list[j])
            ori_min = state.solver.min(iv_list[i]) + state.solver.min(iv_list[j])

            max = state.solver.max(iv_list[i] + iv_list[j])
            ori_max = state.solver.max(iv_list[i]) + state.solver.max(iv_list[j])

            # TODO: theorectically it should 'and'
            if min != ori_min or max != ori_max:
                """
                print(iv_list[i], " and ", iv_list[j])
                print("origin min: ", ori_min, " min: ", min)
                print()
                """
                assert ori_min < min or max < ori_max
                cond.append((iv_list[i], iv_list[j]))

    return cond


def ast_mem_write_bp(state):
    """
    Collect ast from memory write, only when write_addr is symbolic.
    If cond_flag is on (indicating the mem write is conditioned on some constraint), we put processed constraints into MemRecord.cond
    """
    # print("[ast_mem_write_bp] @ ", hex(state.addr))
    # print("write_addr: ", state.inspect.mem_write_address)
    # print("write_expr: ", state.inspect.mem_write_expr)

    write_expr = state.inspect.mem_write_expr
    write_addr = state.inspect.mem_write_address

    # return if concrete
    if write_addr.concrete:
        return

    # collect (un)completed_loop_entry
    completed_loop_entry = [
        key for key, value in state.locals["completed_loops"].items() if value
    ]
    ongoing_loop_entry = [
        key for key, value in state.locals["completed_loops"].items() if not value
    ]

    cond = []
    if state.globals["flag"]["cond"]:
        cond = check_additional_constraints(state)

    # what is it?
    # assert state.inspect.mem_write_condition is None

    record = MemRecord(
        state.inspect.mem_write_address,
        state.inspect.mem_write_expr,
        cond=cond,
        completed_loop_entry=completed_loop_entry,
        ongoing_loop_entry=ongoing_loop_entry,
        outer_loop=state.globals["outer_loop"],
        op_addr=state.addr,
    )

    print("[ast_mem_write_bp] mem_write @ ", hex(state.addr))

    if state.addr not in state.project.mem_write_dict:
        state.project.mem_write_dict[state.addr] = [record]
    else:
        state.project.mem_write_dict[state.addr].append(record)

    # before mem_write, we also check if there has been value stored in it.
    # original_addr = None
    # for arg in write_addr.args:
    #     if hasattr(arg, "op") and arg.concrete:
    #         original_addr = arg
    #         break
    # if original_addr is None:
    #     return
    # original_val = state.memory.load(
    #     original_addr, 4, disable_actions=True, inspect=False
    # )
    # if state.addr in state.project.constant_dict:
    #     state.project.constant_dict[state.addr].append(original_val)
    # else:
    #     state.project.constant_dict[state.addr] = [original_val]


def ast_address_concretization_bp(state):
    """
    Dont add constraints when concretizing addr with IV
    """
    addr_expr = state.inspect.address_concretization_expr
    # print("[ast_address_concretization_bp @ ", hex(state.addr), "addr_expr: ",
    #      addr_expr)
    if check_iv_expr(addr_expr):
        print(
            "[ast_address_concretization_bp @ ",
            hex(state.addr),
            " disable adding constraints",
        )
        state.inspect.address_concretization_add_constraints = False


def ast_constraints_bp(state):
    """ """
    print(
        "[ast_constraints_bp] @ ",
        hex(state.addr),
    )
    for cst in state.inspect.added_constraints:
        if check_iv_expr(cst):
            print(cst)
    # print(state.solver.constraints)
    print()
