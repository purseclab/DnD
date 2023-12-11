import angr
from collections import defaultdict
import pickle

from src.loader import load
from src.iv_identify import identify_iv
from src.ast import extract_ast
from src.lifter import lift
from src.lifter import lift_mem_write, lift_condition, lift_simplify
from src.timeout import timeout
from src.onnx_builder import export_onnx


def lift_func_to_ast(proj, func_addr):
    outer_loop_idx = 0
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
    adj_map = defaultdict(set)

    for f_idx in range(1, len(proj.analysis_funcs)):
        cur_addr = proj.analysis_funcs[f_idx]
        cur_ast = lifted_ast_map[cur_addr]

        # infer its memory read/write region
        # TODO: due to time constraint, for maxpooling we might not have its range
        cur_ast.get_mem_rw_range()

        if cur_ast.read_range:
            for prev_f_idx in range(max(0, f_idx - WINDOW_SIZE), f_idx - 1):
                prev_addr = proj.analysis_funcs[prev_f_idx]
                prev_ast = lifted_ast_map[prev_addr]
                if prev_ast.write_range and any(
                    [rr in prev_ast.write_range for rr in cur_ast.read_range]
                ):
                    adj_map[prev_addr].add(cur_addr)
        else:
            adj_map[proj.analysis_funcs[f_idx - 1]].add(cur_addr)
            adj_map[cur_addr].add(proj.analysis_funcs[f_idx + 1])

    return adj_map


def decompile():
    # loading the binary
    bin_path = "/home/ruoyu/workspace/DnD-LM/binary_samples/mnist/lenet_m4.axf"
    # bin_path = "/home/ruoyu/Documents/MCUXpresso_11.4.1_6260/workspace/evkbimxrt1050_glow_lenet_mnist_new/Release/evkbimxrt1050_glow_lenet_mnist_new.axf"
    proj = load(bin_path)

    # AST
    lifted_ast_map = {}
    for f in proj.analysis_funcs:
        if f not in lifted_ast_map:
            lifted_ast_map[f] = lift_func_to_ast(proj, f)

    # topology
    incoming_map = recover_topology(proj, lifted_ast_map)

    # recover
    for ast in lifted_ast_map.values():
        ast.recover()

    op_info = {}

    # recover attributes
    for ast_addr, ast in lifted_ast_map.items():
        op_info[ast_addr] = ast.recover_attributes()
        op_info[ast_addr]["op"] = ast.op_type

    # recover weights
    state = proj.factory.blank_state()
    for ast_addr, ast in lifted_ast_map.items():
        weights, bias = ast.extract_weights(state)
        op_info[ast_addr]["weights"] = weights
        op_info[ast_addr]["bias"] = bias

    # export to pickle
    with open("adj_map", "wb") as file:
        pickle.dump(adj_map, file)
    with open("op_info", "wb") as file:
        pickle.dump(op_info, file)

    # export to onnx
    export_onnx(proj.analysis_funcs, adj_map, op_info)


if __name__ == "__main__":
    decompile()
