from math import e
from .iv import IV
from .anno import MemReadAnnotation, isMemRead, isIV
from .lifted_ast import LiftedAST, LiftedIV, AST_OP
from .utils import (
    is_arm_arch,
    is_x86,
    iv_to_iv_addr,
    iv_to_iv_name,
    retrieve_iv_var,
    expr_list_diff,
    check_ITE_in_expr,
    get_num_children_asts,
)
from .op import Mul, Sum

from functools import cmp_to_key
from copy import copy


def construct_lifted_ast(lifted_mr, all_ivs, solver):
    # construct iv_var_set
    iv_var_set = lifted_mr.expr.get_iv_vars_set()
    for addr_iv_var in retrieve_iv_var(lifted_mr.addr):
        iv_var_set.add(addr_iv_var)

    # construct lifted iv_dict
    ivs_dict = construct_lifted_iv_dict(iv_var_set, all_ivs)

    # return lifted AST
    return LiftedAST(lifted_mr.addr, lifted_mr.expr, ivs_dict, solver)


def construct_lifted_iv_dict(iv_var_set, all_ivs):
    """
    iv_var_set: all used iv_var in lifted_ast
    all_ivs: the dict of all ivs' info
    """
    ivs_dict = {}
    for iv_var in iv_var_set:
        iv_var_name = iv_to_iv_name(iv_var)
        iv_var_addr = int(iv_to_iv_addr(iv_var), 16)
        if iv_var_name not in ivs_dict:
            assert iv_var_addr in all_ivs
            iv = all_ivs[iv_var_addr]
            ivs_dict[iv_var_name] = LiftedIV(
                iv_var_name, iv.init_val, iv.total_count, iv_var
            )
    return ivs_dict


def lift_mul(term):
    assert len(term.args) == 2
    assert isMemRead(term.args[0])
    assert isMemRead(term.args[1])
    # TODO: check act and param anno

    return Mul(term.args[0], term.args[1])


def lift_sum(term, offset, idx_iv, all_ivs):
    """
    Given the term, lower bound and upper bound of the sum,
    return the constructed sum op.
    """

    if term.op == "__mul__":
        if offset is not None:
            assert isMemRead(offset)

        # to lifted_iv
        # loop_merging needs IV
        """
        lifted_idx_iv = [
            LiftedIV(iv.name, iv.init_val, iv.total_count, iv.iv_var)
            for iv in idx_iv
        ]
        return Sum(lift_mul(term), offset, lifted_idx_iv)
        """

        return Sum(lift_mul(term), offset, idx_iv)

    else:
        assert False


def sort_reduce_list_cmp(item1, item2):
    solver = item1[1]

    if solver.eval(item1[0] < item2[0]):
        return -1
    if solver.eval(item1[0] > item2[0]):
        return 1
    else:
        return 0


def sort_reduce_list(to_reduce_list, solver):
    """
    Given a to_reduce_list, sort it.
    A triky thing is how to pass solver to cmp, we just put solver with element
    """

    temp_list = [(item, solver) for item in to_reduce_list]

    temp_list = sorted(temp_list, key=cmp_to_key(sort_reduce_list_cmp))

    return [item[0] for item in temp_list]


def reduce(to_reduce_list, to_reduce_iv, to_reduce_iv_var, solver):
    """
    Given a list with an IV, return the reduced repr.
    The to_reduce_iv's increment will be changed later.
    """
    # check
    assert (
        len(to_reduce_list) == to_reduce_iv.increment
        or len(to_reduce_list) == to_reduce_iv.reroll_increment
    )

    try:
        # sort the list
        to_reduce_list = sort_reduce_list(to_reduce_list, solver)
    except:
        # an angr weak-ref bug
        # from IPython import embed
        # embed()
        # assert (False)
        print("[reduce] angr weak-ref bug")
        to_reduce_list = sorted(to_reduce_list, key=lambda k: get_num_children_asts(k))

    return to_reduce_list[0]


def reduce_without_iv(to_reduce_list, solver):
    """
    Given a list of expr without an IV (so it is fully rolled),
    return the reduced repr and the created IV.
    """
    try:
        solver.BVS("test", 32)
    except:
        print("[reduce_without_iv] solver does not work!")
        assert False

    print("[reduce_without_iv] to_reduce_list: ", to_reduce_list)

    # each element is mul
    # we need to find MemRead sub-elements, reduce the sub-elements and re-assemble them
    if to_reduce_list[0].op == "__mul__":
        assert isMemRead(to_reduce_list[0].args[0])
        assert isMemRead(to_reduce_list[1].args[0])

        ls_diff_0 = expr_list_diff([expr.args[0] for expr in to_reduce_list], solver)
        ls_diff_1 = expr_list_diff([expr.args[1] for expr in to_reduce_list], solver)
        assert ls_diff_0 == ls_diff_1

        ls_diff = ls_diff_1

        # all elements equal
        if ls_diff.count(0) == len(ls_diff):
            return to_reduce_list[0], None

        # arithmetic sequence
        elif ls_diff.count(ls_diff[0]) == len(ls_diff):
            # iv_var: RC => reduce create
            iv_name = "IVRC_" + str(to_reduce_list[0].__hash__())[:6]
            reduce_iv_var = solver.BVS(iv_name, 32)

            # iv
            reduce_iv = IV(
                name=iv_name, init_val=0, increment=1, loop_count=len(to_reduce_list)
            )
            reduce_iv.set_iv_var(reduce_iv_var)
            print("Create IV: ", reduce_iv, " with loop count: ", reduce_iv.loop_count)

            if isMemRead(to_reduce_list[0].args[0]) and isMemRead(
                to_reduce_list[0].args[1]
            ):
                reduce_term = (
                    to_reduce_list[0].args[0] + ls_diff[0] * reduce_iv_var
                ).annotate(MemReadAnnotation(0)) * (
                    to_reduce_list[0].args[1] + ls_diff[0] * reduce_iv_var
                ).annotate(
                    MemReadAnnotation(0)
                )
            else:
                reduce_term = (
                    to_reduce_list[0].args[0] + ls_diff[0] * reduce_iv_var
                ) * (to_reduce_list[0].args[1] + ls_diff[0] * reduce_iv_var)

            return reduce_term, reduce_iv

        else:
            assert False

    # take each element in the to_reduce_list as a whole
    else:
        # if isMemRead(to_reduce_list[0]):

        to_reduce_list = sort_reduce_list(to_reduce_list, solver)

        ls_diff = expr_list_diff(to_reduce_list, solver)
        # assert concrete
        assert all([isinstance(item, int) for item in ls_diff])

        # all elements equal
        if ls_diff.count(0) == len(ls_diff):
            return to_reduce_list[0], None

        # arithmetic sequence
        elif ls_diff.count(ls_diff[0]) == len(ls_diff):
            # iv_var: RC => reduce create
            iv_name = "IVRC_" + str(to_reduce_list[0].__hash__())[:6]
            reduce_iv_var = solver.BVS(iv_name, 32)

            # iv
            reduce_iv = IV(
                name=iv_name, init_val=0, increment=1, loop_count=len(to_reduce_list)
            )
            reduce_iv.set_iv_var(reduce_iv_var)
            print("Create IV: ", reduce_iv, " with loop count: ", reduce_iv.loop_count)

            reduce_term = to_reduce_list[0] + ls_diff[0] * reduce_iv_var

            if isMemRead(to_reduce_list[0]):
                reduce_term = reduce_term.annotate(MemReadAnnotation(0))

            return reduce_term, reduce_iv

        else:
            from IPython import embed

            embed()
            assert False


def reduce_with_new_iv(to_reduce_list, new_iv, solver):
    """
    It is similar to `reduce_without_iv`, but with the given new_iv
    """
    to_reduce_list = sort_reduce_list(to_reduce_list, solver)

    ls_diff = expr_list_diff(to_reduce_list, solver)

    # assert concrete
    assert all([isinstance(item, int) for item in ls_diff])

    # all elements equal
    if ls_diff.count(0) == len(ls_diff):
        return to_reduce_list[0]

    # arithmetic sequence
    elif ls_diff.count(ls_diff[0]) == len(ls_diff):
        assert new_iv.loop_count == len(to_reduce_list)

        return to_reduce_list[0] + ls_diff[0] * new_iv.iv_var

    else:
        assert False


def min_max_cond_idx(mem_write_mr):
    """
    Reduce the idx of the mr with the least/most constraints
    """
    assert len(mem_write_mr) >= 2

    min_idx = 0
    max_idx = 0
    for idx in range(1, len(mem_write_mr)):
        if len(mem_write_mr[idx].cond) < len(mem_write_mr[min_idx].cond):
            min_idx = idx
        if len(mem_write_mr[idx].cond) > len(mem_write_mr[max_idx].cond):
            max_idx = idx

    return min_idx, max_idx


def conditional_heuristic(proj, mem_record):
    """
    We introduce some heuristics to prune complicated conditional ast:
        1. padding -> padding heuristic: select one of the mem_record
        2. fused operator (e.g. ReLu)
        In if-else, select one leaf ast (without any condition)
    """
    print("Using conditional heuristic")

    # print("before padding heuristic:\n", mem_record)
    mem_record = padding_heuristic(mem_record)
    # print("after padding heuristic:\n", mem_record)

    assert not check_ITE_in_expr(mem_record.addr)
    mem_record = fusion_heuristic(proj, mem_record)
    # print("after fusion heuristic:\n", mem_record)

    # still too slow
    # assert (mem_record.expr.ite_excavated.op == 'If')
    # assert (not check_ITE_in_expr(mem_record.expr.ite_excavated.args[2]))

    return mem_record


def padding_heuristic(mem_record):
    """
    This heuristic applies to arm thumb, where conditions are included in expr (through ITE).
    least/most constrains -> handle padding checking
    constraints => iv[i] + iv[j]
    Currently keep the ones with most constraints
    """
    print("Using padding heuristic")

    # Not sure about the new heuristic, so comment the old out
    # if len(mem_record) > 1:
    #     min_idx, max_idx = min_max_cond_idx(mem_record)
    #     new_mem_record = mem_record[max_idx]
    # else:
    #     new_mem_record = mem_record[0]

    if len(mem_record) > 2:
        # max one
        min_idx, max_idx = min_max_cond_idx(mem_record)
        new_mem_record = mem_record[max_idx]
    elif len(mem_record) == 2:
        # min one
        min_idx, max_idx = min_max_cond_idx(mem_record)
        new_mem_record = mem_record[min_idx]
    else:
        new_mem_record = mem_record[0]

    return new_mem_record


def fusion_heuristic(proj, mem_record):
    """
    We choose the simpler (i.e., shallower) expr in the ITE
    """

    new_mem_record = copy(mem_record)
    if is_arm_arch(proj.arch):
        if check_ITE_in_expr(mem_record.expr):
            assert mem_record.expr.op == "fpToIEEEBV"
            assert mem_record.expr.args[0].op == "If"

            # if mem_record.op_addr == 0x6000969d or mem_record.op_addr == 0x60009c85:
            #     print(hex(mem_record.op_addr))
            #     print(mem_record.expr.args[0].args[1])
            #     print(mem_record.expr.args[0].args[2])

            # if mem_record.expr.args[0].args[1].depth == 1:
            #     new_mem_record.expr = mem_record.expr.args[0].args[2]
            #     return new_mem_record
            # elif mem_record.expr.args[0].args[2].depth == 1:
            #     new_mem_record.expr = mem_record.expr.args[0].args[1]
            #     return new_mem_record

            # choose the simpler expr
            simpler_expr = (
                mem_record.expr.args[0].args[1]
                if (
                    mem_record.expr.args[0].args[1].depth
                    < mem_record.expr.args[0].args[2].depth
                )
                else mem_record.expr.args[0].args[2]
            )
            assert not check_ITE_in_expr(simpler_expr)
            new_mem_record.expr = simpler_expr
            new_mem_record.relu_flag = True

            return new_mem_record

        if isinstance(mem_record.expr, float):
            new_mem_record.expr = None
            return new_mem_record

    elif is_x86(proj.arch):
        new_mem_record.expr = None
        return new_mem_record


def recursive_is_max_min_pooling_relu(expr):
    """
    One of the elements to be compared is a constant.
    """
    if expr.op != "If":
        return None

    if expr.args[1].op == "If" and expr.args[2].op == "fpToFP":
        num = recursive_is_max_min_pooling_relu(expr.args[1])
    elif expr.args[2].op == "If" and expr.args[1].op == "fpToFP":
        num = recursive_is_max_min_pooling_relu(expr.args[2])
    elif (expr.args[1].op == "fpToFP" and expr.args[2].op == "FPV") or (
        expr.args[1].op == "FPV" and expr.args[2].op == "fpToFP"
    ):
        num = 1
    else:
        return None

    if num is not None:
        return num + 1


def lift_special(mem_write_dict):
    lifted_ast = lift_max_min_pooling_relu(mem_write_dict)
    if lifted_ast is not None:
        return lifted_ast

    lifted_ast = lift_avg_pooling(mem_write_dict)
    if lifted_ast is not None:
        return lifted_ast

    return None


def lift_avg_pooling(mem_write_dict):
    """
    Here is the over-simplified version of the `check_mem_record` in lifter.py
    """
    num_elements = []
    for addr, mem_write_mr in mem_write_dict.items():
        if len(mem_write_mr) >= 2:
            return None

        if mem_write_mr[0].expr.op != "fpToIEEEBV":
            return None

        # match with avg pooling
        if mem_write_mr[0].expr.args[0].op == "fpMul":
            scale = mem_write_mr[0].expr.args[0].args[2].args[0]
            num_elements.append(int(1 / scale))
        else:
            return None

    if not all([num == num_elements[0] for num in num_elements]):
        assert False

    assert num_elements[0] ** 0.5 == int(num_elements[0] ** 0.5)
    kernel_size = int(num_elements[0] ** 0.5)

    lifted_ast = LiftedAST(None, None, None, None)
    lifted_ast.op_type = AST_OP.AVGPOOL
    lifted_ast.kernel_size = kernel_size
    return lifted_ast


def lift_max_min_pooling_relu(mem_write_dict):
    """
    max/min pooling: constant (FPV) used to compare with is a min/max value
    relu: constant (FPV) used to compare with is 0
    """
    # It means we timeout at the ast extraction, only happen in arm max/min pooling since lots of conditions (IT instruction). If the pooling kernel is large, it would be extremely slow.
    if len(mem_write_dict) == 0:
        lifted_ast = LiftedAST(None, None, None, None)
        lifted_ast.op_type = AST_OP.MAXPOOL
        return lifted_ast

    num_elements = []
    constants = []
    for addr, mem_write_mr in mem_write_dict.items():
        if len(mem_write_mr) >= 2:
            return None

        if mem_write_mr[0].expr.op != "fpToIEEEBV":
            return None

        num = recursive_is_max_min_pooling_relu(mem_write_mr[0].expr.args[0])

        if num is None:
            return None

        num_elements.append(num - 1)

        constant_leaf = [
            leaf for leaf in mem_write_mr[0].expr.leaf_asts() if leaf.op == "FPV"
        ]
        constants.append(constant_leaf[0].args[0])
    
    # Relu
    if constants[0] == 0:
        lifted_ast = LiftedAST(None, None, None, None)
        lifted_ast.op_type = AST_OP.RELU
        return lifted_ast

    if not all([num == num_elements[0] for num in num_elements]):
        return None

    assert num_elements[0] ** 0.5 == int(num_elements[0] ** 0.5)
    kernel_size = int(num_elements[0] ** 0.5)

    lifted_ast = LiftedAST(None, None, None, None)
    lifted_ast.op_type = AST_OP.MAXPOOL
    lifted_ast.kernel_size = kernel_size
    return lifted_ast


def is_data_movement(mem_write_dict):
    if len(mem_write_dict) == 0:
        return False
    
    for addr in mem_write_dict:
        for record in mem_write_dict[addr]:
            if len(record.expr.annotations) == 0:
                return False
            if not isinstance(record.expr.annotations[0], MemReadAnnotation):
                return False
    return True