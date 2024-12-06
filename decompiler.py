import angr
from collections import defaultdict
import pickle
import sys

from src.loader import load
from src.iv_identify import identify_iv
from src.ast import extract_ast
from src.lifter import lift
from src.lifted_ast import LiftedAST, AST_OP
from src.timeout import timeout
from src.onnx_builder import export_onnx


def lift_no_loop_func_to_ast(proj, func_addr):
    """
    Lift the function does not contain any loop, usually it the last layer, with simple logic.
    """
    func = proj.funcs[func_addr]

    # softmax
    callee_func_names = [
        proj.funcs[func.get_call_target(callsite)].name
        for callsite in func.get_call_sites()
    ]
    if "exp" in callee_func_names or "expf" in callee_func_names:
        lifted_ast = LiftedAST(None, None, None, None)
        lifted_ast.op_type = AST_OP.SOFTMAX
        return lifted_ast


def lift_func_to_ast(proj, func_addr):
    outer_loop_idx = 0
    if len(proj.outer_loops[func_addr]) == 0:
        return lift_no_loop_func_to_ast(proj, func_addr)
    if len(proj.outer_loops[func_addr]) > 1:
        assert len(proj.outer_loops[func_addr]) == 2
        outer_loop_idx = 1

    while True:
        try:
            iv_dict, iv_aux = identify_iv(proj, func_addr, outer_loop_idx)
            break
        except:
            pass

    simgr, solver, mem_read_dict, mem_write_dict = extract_ast(
        proj, func_addr, register_view=proj.func_calling_regs[func_addr], timeout=100
    )
    if len(mem_write_dict) == 0:
        print(
            "should not concretize the argument at the beginning, but it would be significantly slower."
        )
        try:
            with timeout(seconds=100):
                simgr, solver, mem_read_dict, mem_write_dict = extract_ast(
                    proj, func_addr, timeout=100
                )
        except TimeoutError:
            pass

    lifted_ast = lift(proj, mem_write_dict, solver)

    return lifted_ast


def recover_topology(proj, lifted_ast_map):
    WINDOW_SIZE = 3

    # graph repr: adjacency matrix
    # <node, succ_node>
    adj_map = defaultdict(set)

    func_info = sorted(
        [
            [
                addr,
                lifted_ast_map[addr],
                lifted_ast_map[addr].get_mem_read_base_reg(),
                lifted_ast_map[addr].get_mem_write_base_reg(),
            ]
            for addr in lifted_ast_map.keys()
            if lifted_ast_map[addr] is not None
        ],
        key=lambda x: x[0],
    )

    for f_idx in range(1, len(func_info)):
        cur_addr = func_info[f_idx][0]
        cur_ast = func_info[f_idx][1]
        cur_ast_read_base = func_info[f_idx][2]

        # print("---------------------")
        # print("cur_addr: ", hex(cur_addr))

        if cur_ast_read_base is not None:
            # print("cur_ast_read_base: ", cur_ast_read_base)

            # keeps tracks of the base prev written addr that has been matched (e.g., relu usually read and write the same addr) 
            matched_base = []
            
            for prev_f_idx in range(max(0, f_idx - WINDOW_SIZE), f_idx)[::-1]:
                prev_addr = func_info[prev_f_idx][0]
                prev_ast = func_info[prev_f_idx][1]
                prev_ast_write_base = func_info[prev_f_idx][3]
                # print("prev_addr: ", hex(prev_addr))
                # print("prev_ast_write_base: ", prev_ast_write_base)
                # specicial handle the case where the write base is not currently collected (relu). Ideally, we should collect it when lifting ast.
                if prev_ast_write_base is None:
                    func_info[prev_f_idx][3] = cur_ast_read_base
                    # print("add ", hex(cur_addr), " to ", hex(prev_addr))
                    adj_map[prev_addr].add(cur_addr)
                    break
                
                if prev_ast_write_base and any(
                    [rr in prev_ast_write_base for rr in cur_ast_read_base] 
                ) and prev_ast_write_base not in matched_base:
                    matched_base.append(prev_ast_write_base)
                    adj_map[prev_addr].add(cur_addr)
                    # print("add ", hex(cur_addr), " to ", hex(prev_addr))
        else:
            prev_addr = func_info[f_idx - 1][0]
            adj_map[prev_addr].add(cur_addr)
            # print("add ", hex(cur_addr), " to ", hex(prev_addr))

    return adj_map


def decompile(path, outpath):
    # mnist sample
    # bin_path = "./binary_samples/mnist/evkbimxrt1050_glow_lenet_mnist_release.axf"
    proj = load(path)

    # AST
    lifted_ast_map = {}
    for f in proj.analysis_funcs:
        if f not in lifted_ast_map:
            lifted_ast = lift_func_to_ast(proj, f)
            if lifted_ast:
                lifted_ast_map[f] = lifted_ast

    # recover the info necessary for topology recovery
    for ast in lifted_ast_map.values():
        ast.recover()

    # recover topology
    adj_map = recover_topology(proj, lifted_ast_map)

    # recover attributes and weights
    op_info = {}
    state = proj.factory.blank_state()
    for ast_addr, ast in lifted_ast_map.items():
        prev_info = [
            op_info[addr] for addr in adj_map.keys() if ast_addr in adj_map[addr]
        ]

        info = ast.recover_attributes(prev_info)
        info["op"] = ast.op_type
        weights, bias, weights_addr, bias_addr = ast.extract_weights(state)
        info["weights"] = weights
        info["bias"] = bias
        op_info[ast_addr] = info

    # export to pickle
    # with open("adj_map", "wb") as file:
    #     pickle.dump(adj_map, file)
    # with open("op_info", "wb") as file:
    #     pickle.dump(op_info, file)

    # export to onnx
    export_onnx(lifted_ast_map, adj_map, op_info, outpath)


if __name__ == "__main__":
    decompile(sys.argv[1], sys.argv[2])
