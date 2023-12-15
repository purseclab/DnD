import operator

from .lifter_helper import (
    conditional_heuristic,
    construct_lifted_ast,
    construct_lifted_iv_dict,
    lift_sum,
    reduce,
    reduce_with_new_iv,
    reduce_without_iv,
    min_max_cond_idx,
    lift_special,
    is_data_movement,
)
from .lifted_ast import LiftedAST, LiftedIV
from .mem_record import MemRecord
from .anno import isMemRead, isIV
from .utils import (
    check_ITE_in_expr,
    check_iv_in_expr,
    expr_list_diff,
    iv_structurally_match,
    iv_to_iv_name,
    retrieve_iv_var,
    retrieve_specific_iv_var,
    check_iv_expr,
    iv_to_iv_addr,
    get_num_children_asts,
    find_iv_from_all_ivs,
    flatten_add_expr,
)
from .simplify import simplify
from .op import Mul, Sum, Add, Avg
from .dbg import print_anno

from math import e, isclose
from itertools import combinations


def lift_ast_with_ongoing_loop(
    addr_expr, ast_expr, solver, all_ivs, completed_loop_iv_list, ongoing_loop_iv_list
):
    """
    Handle accumulate_ongoing;
    Also check if we can reduce expr by creating new iv
    """
    print("[lift_ast_with_ongoing_loop]")
    # print("[lift_ast_with_ongoing_loop] addr_expr: ", addr_expr)
    # print("[lift_ast_with_ongoing_loop] ast_expr: ", ast_expr)

    if ast_expr.op == "__add__":
        ast_expr_list = flatten_add_expr(ast_expr)

        # print("Annotation:")
        # print_anno(ast_expr)

        print("ast_expr_list: ", ast_expr_list)

        # One of the elements in ast_expr_list should be the accumulated destionation, which should be "similar" to the addr_expr. Once identified, we can remove it from the list.
        acc_idx = None
        for idx in range(len(ast_expr_list)):
            if ast_expr_list[idx].structurally_match(addr_expr):
                acc_idx = idx
                break
        assert acc_idx is not None
        del ast_expr_list[acc_idx]

        # remove 0 from the ast_expr_list
        zero_idx = []
        for idx in range(len(ast_expr_list)):
            if solver.eval(ast_expr_list[idx]) == 0:
                zero_idx.append(idx)
        assert len(zero_idx) <= 1
        if len(zero_idx) == 1:
            del ast_expr_list[zero_idx[0]]

        if len(ast_expr_list) > 1:
            try:
                reduce_term, reduce_iv = reduce_without_iv(ast_expr_list, solver)
            except:
                assert False

            # Insert the created IV into all_ivs
            fake_iv_addr = int(reduce_iv.name[5:], 16)
            assert fake_iv_addr not in all_ivs
            all_ivs[fake_iv_addr] = reduce_iv

            # denote loop iv's hierarchy
            reduce_iv.completed_loop_iv_names = set(
                [iv.name for iv in completed_loop_iv_list]
            )
            reduce_iv.ongoing_loop_iv_names = set(
                [iv.name for iv in ongoing_loop_iv_list]
            )

        else:
            reduce_term = ast_expr_list[0]

        addr_iv_var = retrieve_iv_var(addr_expr)
        addr_iv = [find_iv_from_all_ivs(iv_var, all_ivs) for iv_var in addr_iv_var]

        expr_iv_var = retrieve_iv_var(reduce_term)
        expr_iv = [find_iv_from_all_ivs(iv_var, all_ivs) for iv_var in expr_iv_var]

        # all addr_expr_iv should be in reduce_term_iv
        assert all([iv in expr_iv for iv in addr_iv])

        # idx_iv: reduce_term_iv - addr_expr_iv
        idx_iv = [iv for iv in expr_iv if iv not in addr_iv]

        lifted_ast = lift_sum(reduce_term, None, idx_iv, all_ivs)
        return lifted_ast

    else:
        # For the accumulation case, it is always sum
        assert False


def lift_ast_with_completed_loop(
    addr_expr, ast_expr, completed_iv_list, all_ivs, solver
):
    """
    Complete and lift ast expr.
    Accumulation here refers to accumulate_completed
    """
    print("[lift_ast_with_completed_loop]")
    # print("addr_expr: ", addr_expr)

    assert len(completed_iv_list) == 1
    completed_iv_var = completed_iv_list[0][0]
    completed_iv = completed_iv_list[0][1]

    if ast_expr.op == "__add__":
        ast_expr_args = flatten_add_expr(ast_expr)
        # print("ast_expr_args: ", ast_expr_args)

        # check accumulation and constant
        const = None
        const_idx = None
        acc_idx = None
        for idx in range(len(ast_expr_args)):
            if ast_expr_args[idx].concrete:
                # assert only one constant
                assert const is None
                const = solver.eval(ast_expr_args[idx])
                const_idx = idx
            # accumulated
            elif iv_structurally_match(ast_expr_args[idx], addr_expr):
                assert acc_idx is None
                acc_idx = idx

        assert const is None or const == 0
        if const is not None:
            print("constant term: ", ast_expr_args[const_idx])

        # it must be accumulated
        if acc_idx is None:
            assert False
        assert acc_idx is not None
        print("accumulated term: ", ast_expr_args[acc_idx])

        # acc different => has offset
        offset = None
        if not addr_expr.structurally_match(ast_expr_args[acc_idx]):
            offset = ast_expr_args[acc_idx]

        # remove acc and constant (optional)
        if const_idx is not None:
            for idx in sorted([const_idx, acc_idx], reverse=True):
                del ast_expr_args[idx]
        else:
            del ast_expr_args[acc_idx]

        # we can simplify ast_expr_args
        assert len(ast_expr_args) == completed_iv_list[0][1].increment

        reduce_ast_expr = reduce(ast_expr_args, completed_iv, completed_iv_var, solver)

        return lift_sum(reduce_ast_expr, offset, [completed_iv], all_ivs)

    else:
        assert False


def lift_mem_record(addr, mem_record, solver, all_ivs):
    """
    addr: the address the memory write happens

    1. Check if addr can be accumulated
    2. Complete and lift the expr according to completed loops

    accumulate_ongoing vs. accumulate_completed:
        accumulate_ongoing:
            accumulate in the ongoing loop (one of ongoing_loop_iv not in addr_expr_iv)
        accumulate_completed:
            accumulate in the completed loop

    Two cases can happen at the same time: a rolled loop inside a loop
    """

    # Currently assume only one of lifting be used
    accumulate_ongoing_flag = False
    accumulate_completed_flag = False

    outer_loop = mem_record.outer_loop
    addr_expr = mem_record.addr
    ast_expr = mem_record.expr

    completed_loop = [
        loop
        for loop in outer_loop[1]
        if loop.entry.addr in mem_record.completed_loop_entry
    ]
    completed_loop_iv_list = [loop._iv for loop in completed_loop]
    # print("completed_loop_iv_list: ", [iv.name for iv in completed_loop_iv_list])

    ongoing_loop = [
        loop
        for loop in outer_loop[1]
        if loop.entry.addr in mem_record.ongoing_loop_entry
    ]
    ongoing_loop_iv_list = [loop._iv for loop in ongoing_loop]
    # print("ongoing_loop_iv_list: ", [iv.name for iv in ongoing_loop_iv_list])

    addr_expr_iv_var_list = [iv_var for iv_var in retrieve_iv_var(addr_expr)]
    # print("addr_expr_iv_var_list: ", addr_expr_iv_var_list)

    ast_expr_iv_var_list = [iv_var for iv_var in retrieve_iv_var(ast_expr)]
    # print("ast_expr_iv_var_list: ", ast_expr_iv_var_list)

    # addr_expr_iv should be in ongoing_loop_iv list
    if any(
        [
            iv_to_iv_name(iv_var) not in [_iv.name for _iv in ongoing_loop_iv_list]
            for iv_var in addr_expr_iv_var_list
        ]
    ):
        assert False

    # accumulate_ongoing: one of ongoing_loop_iv not in addr_expr_iv
    if any(
        [
            iv.name not in [iv_to_iv_name(_iv_var) for _iv_var in addr_expr_iv_var_list]
            for iv in ongoing_loop_iv_list
        ]
    ):
        accumulate_ongoing_flag = True
        print("[lift_ast_with_ongoing_loop] @ ", hex(addr))
        ast_expr = lift_ast_with_ongoing_loop(
            addr_expr,
            ast_expr,
            solver,
            all_ivs,
            completed_loop_iv_list,
            ongoing_loop_iv_list,
        )

    # Do lifting for completed loop if needed
    completed_iv_list = []
    for iv_var in ast_expr_iv_var_list:
        for _iv in completed_loop_iv_list:
            if iv_to_iv_name(iv_var) == _iv.name:
                completed_iv_list.append((iv_var, _iv))

    if len(completed_iv_list) > 0:
        if not accumulate_ongoing_flag:
            accumulate_completed_flag = True
            ast_expr = lift_ast_with_completed_loop(
                addr_expr, ast_expr, completed_iv_list, all_ivs, solver
            )
        else:
            # If accumulate_ongoing is already flagged, it means that the rerolled expr is executed several times in the completed loop. In this case, we can just modify the reroll(created) IV's loop count. We also need to eliminate the complete IV gracefully.

            # scale is the time the the completed loop is executed
            scale = (
                completed_iv_list[0][1].loop_count
                if completed_iv_list[0][1].increment != 0
                else 2
            )

            # find the just created IV that's contained in ast_expr
            ast_expr_iv_names_list = list(
                set([iv_to_iv_name(iv_var) for iv_var in retrieve_iv_var(ast_expr)])
            )
            created_iv_list = []
            for iv_name in all_ivs:
                iv = all_ivs[iv_name]
                if iv.name.startswith("IVRC") and iv.name in ast_expr_iv_names_list:
                    created_iv_list.append(iv)
            assert len(created_iv_list) == 1

            print("Modifying created IV's loop count and eliminate IV")
            created_iv_list[0].loop_count *= scale
            # eliminate the complate IV by replacing it with zero
            ast_expr = ast_expr.replace(completed_iv_list[0][0], solver.BVV(0, 32))

    # debugging
    # print("[lift_mem_record] all_ivs at the end: ", all_ivs)

    return MemRecord(
        addr=addr_expr,
        expr=ast_expr,
        completed_loop_entry=mem_record.completed_loop_entry,
        ongoing_loop_entry=mem_record.ongoing_loop_entry,
        op_addr=mem_record.op_addr,
    )


def find_reroll_iv(addr_expr_list, all_ivs):
    """
    Return reroll_iv and reroll_iv_var, based on the increment
    """
    # find reroll_iv and reroll_iv_var
    addr_iv_list = [
        iv for iv in all_ivs.values() if iv.increment == len(addr_expr_list)
    ]

    assert len(addr_iv_list) == 1 or len(addr_iv_list) == 0

    if len(addr_iv_list) == 1:
        # there is already an "anchor" iv
        reroll_iv = addr_iv_list[0]
        reroll_iv_var = retrieve_specific_iv_var(addr_expr_list[0], reroll_iv.name)
        assert reroll_iv_var is not None
        # print(reroll_iv_var)
        return True, reroll_iv, reroll_iv_var
    elif len(addr_iv_list) == 0:
        # IV does not exist
        return False, None, None


def reroll_reduce_addr_and_expr(addr_expr_list, ast_expr_list, all_ivs, solver):
    """
    A helper function for reroll, currently only support ast_expr with two args
    """
    if isinstance(ast_expr_list[0], Sum):
        arg_0_list = [ast.expr.expr_0 for ast in ast_expr_list]
        arg_1_list = [ast.expr.expr_1 for ast in ast_expr_list]
    elif ast_expr_list[0].op == "__add__":
        arg_0_list = [ast.args[0] for ast in ast_expr_list]
        arg_1_list = [ast.args[1] for ast in ast_expr_list]

    # find reroll_iv and reroll_iv_var based on increment
    # found->True if addr_expr are incremental on an IV (i, i+4, i+8...)
    # found->False if not found, so we need to create an additional one (0, 4, 8...)
    found, reroll_iv, reroll_iv_var = find_reroll_iv(addr_expr_list, all_ivs)

    if found:
        # reduce
        reduce_addr = reduce(addr_expr_list, reroll_iv, reroll_iv_var, solver)
        reduce_arg_0 = reduce(arg_0_list, reroll_iv, reroll_iv_var, solver)
        reduce_arg_1 = reduce(arg_1_list, reroll_iv, reroll_iv_var, solver)

        # set iv's reroll fields
        if not reroll_iv.reroll_flag:
            reroll_iv.reroll_flag = True
            reroll_iv.reroll_count = reroll_iv.total_count
            reroll_iv.reroll_increment = 1

        # ivs_dict
        ivs_var_set = set(
            [
                *retrieve_iv_var(reduce_addr),
                *retrieve_iv_var(reduce_arg_0),
                *retrieve_iv_var(reduce_arg_1),
            ]
        )
        ivs_dict = construct_lifted_iv_dict(ivs_var_set, all_ivs)

        return reduce_addr, reduce_arg_0, reduce_arg_1, ivs_dict

    else:
        # we need to create an IV and reduce across several addr_expr/ast_expr

        reduce_addr, reduce_iv = reduce_without_iv(addr_expr_list, solver)
        reduce_arg_0 = reduce_with_new_iv(arg_0_list, reduce_iv, solver)
        reduce_arg_1 = reduce_with_new_iv(arg_1_list, reduce_iv, solver)

        # insert into all_ivs
        fake_iv_addr = int(reduce_iv.name[5:], 16)
        assert fake_iv_addr not in all_ivs
        all_ivs[fake_iv_addr] = reduce_iv

        reduce_iv.reroll_flag = True

        # ivs_dict
        ivs_var_set = set(
            [
                *retrieve_iv_var(reduce_addr),
                *retrieve_iv_var(reduce_arg_0),
                *retrieve_iv_var(reduce_arg_1),
            ]
        )
        ivs_dict = construct_lifted_iv_dict(ivs_var_set, all_ivs)

        return reduce_addr, reduce_arg_0, reduce_arg_1, ivs_dict


def reroll(proj, mem_write_lift_list, solver, all_ivs):
    """
    Reroll multiple memory write corresponding to the multiple loops,
    due to loop rolling.
    """

    # TODO: these cases can actually be unified.
    # Basically it is just reducing the args
    if all(mr.expr.op == "sum" for mr in mem_write_lift_list):
        addr_expr_list = [mr.addr for mr in mem_write_lift_list]
        ast_expr_list = [mr.expr for mr in mem_write_lift_list]

        assert all([ast.expr.op == "mul" for ast in ast_expr_list])
        assert all([ast.offset == None for ast in ast_expr_list])

        reduce_addr, reduce_arg_0, reduce_arg_1, ivs_dict = reroll_reduce_addr_and_expr(
            addr_expr_list, ast_expr_list, all_ivs, solver
        )

        # TODO: probably it is not the right place: it should happen when we construct the Sum
        # extract offset
        # offset = [
        #     (read_addr, val) for read_addr, val in proj.constant_read_dict.items()
        # ]
        # offset.sort(key=lambda x: x[0])
        # offset = [x[1] for x in offset]
        offset = proj.constant_read_list

        # return LiftedAST
        reduce_sum_mul = Sum(
            Mul(reduce_arg_0, reduce_arg_1), offset, ast_expr_list[0].idx_iv
        )
        return LiftedAST(reduce_addr, reduce_sum_mul, ivs_dict, solver)

    elif all(mr.expr.op == "__add__" for mr in mem_write_lift_list):
        addr_expr_list = [mr.addr for mr in mem_write_lift_list]
        ast_expr_list = [mr.expr for mr in mem_write_lift_list]

        reduce_addr, reduce_arg_0, reduce_arg_1, ivs_dict = reroll_reduce_addr_and_expr(
            addr_expr_list, ast_expr_list, all_ivs, solver
        )

        # return
        reduce_add = Add(reduce_arg_0, reduce_arg_1)
        return LiftedAST(reduce_addr, reduce_add, ivs_dict, solver)

    else:
        assert False


def merge_loop(mem_write_lift_list, to_merge_iv_list):
    """
    Substitute iv in to_merge_iv_list[i][j] into to_merge_iv_list[i][0].
    This is to handle the case where a loop is split into two.
    (e.g. libjit_conv2d_f_9_specialized in glow_mobilenet_M4)
    """

    print("[merge_loop] before merging")
    # print(mem_write_lift_list)

    for to_merge_iv in to_merge_iv_list:
        assert len(to_merge_iv) >= 2
        for to_merge_iv_idx in range(1, len(to_merge_iv)):
            old_iv = to_merge_iv[to_merge_iv_idx]
            new_iv = to_merge_iv[0]

            old_iv_var = None
            new_iv_var = None

            # retrieve old_iv_var
            for mr in mem_write_lift_list:
                old_iv_var = retrieve_specific_iv_var(mr.addr, old_iv.name)
                if old_iv_var is not None:
                    break
                old_iv_var = retrieve_specific_iv_var(mr.expr, old_iv.name)
                if old_iv_var is not None:
                    break
            if old_iv_var is None:
                continue

            # retrieve new_iv_var
            for mr in mem_write_lift_list:
                new_iv_var = retrieve_specific_iv_var(mr.addr, new_iv.name)
                if new_iv_var is not None:
                    break
                new_iv_var = retrieve_specific_iv_var(mr.expr, new_iv.name)
                if new_iv_var is not None:
                    break
            assert new_iv_var is not None

            # begin replacement
            for mr in mem_write_lift_list:
                if check_iv_in_expr(mr.addr, old_iv.name):
                    mr.addr = mr.addr.replace(old_iv_var, new_iv_var)
                if check_iv_in_expr(mr.expr, old_iv.name):
                    try:
                        mr.expr = mr.expr.replace(old_iv_var, new_iv_var)
                        mr.expr.update_idx(old_iv, new_iv)
                    except:
                        print("symvar replacement fail")
                        assert False


def check_mem_record(mem_record, all_ivs, solver):
    """
    Check to see if some additional heuristics need to be applied.
        glow_mobilenet - libjit_avg_pool_f_41_specialized:
            mem_read/write idx unrelated to identified iv
    """
    if not check_iv_expr(mem_record.addr) and not check_iv_expr(mem_record.expr):
        # this heuristic has been applied in the `lift_pooling`, should not be invoked again
        assert False

        assert len(all_ivs) == 1
        iv_var = list(all_ivs.values())[0].iv_var

        # addr
        mem_record.addr = mem_record.addr + 4 * iv_var

        # expr
        assert mem_record.expr.op == "__mul__"
        args = flatten_add_expr(mem_record.expr.args[0])
        args = [arg + 4 * iv_var for arg in args]
        if mem_record.expr.args[1].symbolic:
            factor = solver.fp_dict["FP_" + iv_to_iv_addr(mem_record.expr.args[1])]
        else:
            assert False
        assert isclose(1 / len(args), factor, rel_tol=1e-06)

        # reduce the term
        reduce_term, reduce_iv = reduce_without_iv(args, solver)

        # insert into all_ivs
        fake_iv_addr = int(reduce_iv.name[5:], 16)
        assert fake_iv_addr not in all_ivs
        all_ivs[fake_iv_addr] = reduce_iv

        # it is Avg
        mem_record.expr = Avg(reduce_term, reduce_iv)
        lifted_ast = construct_lifted_ast(mem_record, all_ivs, solver)

        return lifted_ast

    elif not check_iv_expr(mem_record.addr) or not check_iv_expr(mem_record.expr):
        assert False

    else:
        return None


def lift_mem_write(proj, mem_write_dict, solver):
    """
    Lift all mem_records into ASTs.
    """

    # retrieve all_ivs
    outer_loop = list(mem_write_dict.values())[0].outer_loop
    all_ivs = {loop._iv.addr: loop._iv for loop in outer_loop[1]}

    # lifting
    mem_write_lift_dict = {}
    for addr in mem_write_dict:
        assert addr not in mem_write_lift_dict
        mem_record = mem_write_dict[addr]

        # if it is a tricky case, we construct LiftedAST and return
        lifted_ast = check_mem_record(mem_record, all_ivs, solver)
        if isinstance(lifted_ast, LiftedAST):
            return lifted_ast

        print("---------------------------------------")
        print("handling mem_record at ", hex(addr), " with mem_record:\n ", mem_record)
        mem_write_lift_dict[addr] = lift_mem_record(addr, mem_record, solver, all_ivs)

    # assert all mem_write are at the same loop
    mem_write_lift_list = list(mem_write_lift_dict.values())
    assert all(
        mr.completed_loop_entry == mem_write_lift_list[0].completed_loop_entry
        for mr in mem_write_lift_list
    )
    assert all(
        mr.ongoing_loop_entry == mem_write_lift_list[0].ongoing_loop_entry
        for mr in mem_write_lift_list
    )

    # Debugging
    # print("Before loop merging")
    # print(mem_write_lift_list)
    # print(all_ivs)

    # Merge IV
    # If
    #   1. several loops are at the same hierachy
    #   2. they have same iteration count
    #   3. they are still at ast
    # We try to merge them
    to_merge_iv_list = []
    for l in outer_loop[1]:
        if len(l.subloops) > 1:
            to_merge_iv = [l._iv for l in l.subloops]
            # same iteration count
            if all(iv.total_count == to_merge_iv[0].total_count for iv in to_merge_iv):
                to_merge_iv_list.append(to_merge_iv)

    # We also merge the created IVs (IVRC) if they are at the same hierachy and have the same iteration count. We group the IVRC by their loop count, completed_loop_iv_names, and ongoing_loop_iv_names.
    created_iv_list = []
    for iv_name in all_ivs:
        iv = all_ivs[iv_name]
        if iv.name.startswith("IVRC"):
            created_iv_list.append(iv)

    iv_group_list = []
    grouped_iv_idx = set()
    for iv_idx, iv in enumerate(created_iv_list):
        if iv_idx in grouped_iv_idx:
            continue
        grouped_iv_idx.add(iv)
        iv_group = [iv]
        for other_iv_idx in range(iv_idx + 1, len(created_iv_list)):
            if other_iv_idx in grouped_iv_idx:
                continue
            other_iv = created_iv_list[other_iv_idx]
            if (
                iv.loop_count == other_iv.loop_count
                and iv.completed_loop_iv_names == other_iv.completed_loop_iv_names
                and iv.ongoing_loop_iv_names == other_iv.ongoing_loop_iv_names
            ):
                iv_group.append(other_iv)
                grouped_iv_idx.add(other_iv_idx)
        if len(iv_group) > 1:
            iv_group_list.append(iv_group)
    print("created iv_group_list: ", iv_group_list)
    to_merge_iv_list.extend(iv_group_list)

    # updated_to_merge_iv_list = []
    # if to_merge_iv_list:
    #     for to_merge_iv_pair in to_merge_iv_list:
    #         embed()
    #         # check if the iv in to_merge_iv_list are still in the ast. Either each mem_write has one of the iv, or each does not have any of the iv.
    #         if all([
    #             any([mem_write.expr.check_has_iv(iv) for iv in to_merge_iv_pair])
    #             for mem_write in mem_write_lift_list]
    #         ):
    #             updated_to_merge_iv_list.append(to_merge_iv_pair)
    #         elif all([
    #             all([not mem_write.expr.check_has_iv(iv) for iv in to_merge_iv_pair])
    #             for mem_write in mem_write_lift_list]
    #         ):
    #             print("remove to_merge_iv_pair: ", to_merge_iv_pair)
    #         else:
    #             assert False
    # to_merge_iv_list = updated_to_merge_iv_list

    print("[merge_loop] to_merge_iv_list: ", to_merge_iv_list)

    if to_merge_iv_list:
        print("[lifter] merge loop")
        print("[lift_mem_write] to_merge_iv_list: ", to_merge_iv_list)
        merge_loop(mem_write_lift_list, to_merge_iv_list)

    # Debugging
    print("[merge_loop] after merging")
    print(mem_write_lift_list)
    # print(all_ivs)

    # Reroll the loop and construct lifted AST
    if len(mem_write_lift_list) > 1:
        print("[lifter] reroll")
        lifted_ast = reroll(proj, mem_write_lift_list, solver, all_ivs)
    else:
        # construct lifted AST
        lifted_ast = construct_lifted_ast(mem_write_lift_list[0], all_ivs, solver)

    return lifted_ast


def lift_simplify(proj, mem_write_dict, solver):
    """
    Simplify all mem_records in mem_write_dict,
    """

    ret_mem_write_dict = {}

    # simplify
    for addr in mem_write_dict:
        mem_record = mem_write_dict[addr]
        new_mem_record = mem_record.copy()

        new_mem_record.addr = simplify(mem_record.addr, solver, proj)
        new_mem_record.expr = simplify(mem_record.expr, solver, proj)

        ret_mem_write_dict[addr] = new_mem_record

    return ret_mem_write_dict


def lift_condition(proj, mem_write_dict, solver):
    """
    apply conditional heuristic to prune
    """

    ret_mem_write_dict = {}
    relu_flag = False

    # handle conditions with heuristic
    remove_entry = set()
    for addr in mem_write_dict:
        # print("Handling addr ", hex(addr))

        # select one mem_record from each mem_write_dict[addr]
        if len(mem_write_dict[addr]) > 1 or check_ITE_in_expr(
            mem_write_dict[addr][0].expr
        ):
            # print("Multiple write expr at one addr or ITE @ ", hex(addr))
            mem_record = conditional_heuristic(proj, mem_write_dict[addr])
            if mem_record.relu_flag:
                relu_flag = True
        else:
            mem_record = mem_write_dict[addr][0]

        # we wanna remove some mem_record
        # TODO: they should be removed in `fusion_heuristic`
        if mem_record.expr is None or mem_record.expr.concrete:
            remove_entry.add(addr)
            # print("Remove entry @ ", hex(addr), mem_record.expr)
        else:
            ret_mem_write_dict[addr] = mem_record

    for remove_addr in remove_entry:
        if remove_addr in ret_mem_write_dict:
            del ret_mem_write_dict[remove_addr]

    # print("Finish handling condition")

    return ret_mem_write_dict, relu_flag


def lift(proj, mem_write_dict, solver):
    """
    Lift the memory write addr/expr to AST
    """

    # Don't handle data movement op (e.g., transpose)
    if is_data_movement(mem_write_dict):
        return None

    # Special handling of some ops (maxpooling, avgpooling, relu). Solver is hard to handle them since they have lots of ITEs and floating point operations, resulting in *very* lenthy symbolic constraints.
    lifted_ast = lift_special(mem_write_dict)
    if lifted_ast is not None:
        return lifted_ast

    # Handling condition (padding and fusion)
    mem_write_dict, relu_flag = lift_condition(proj, mem_write_dict, solver)

    # Simplify the expr
    new_mem_write_dict = lift_simplify(proj, mem_write_dict, solver)

    # lift to AST
    lifted_ast = lift_mem_write(proj, new_mem_write_dict, solver)

    if relu_flag:
        lifted_ast.relu_flag = True

    return lifted_ast
