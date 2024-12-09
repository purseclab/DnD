from .ndarray import NdArray
from .register import RegisterView
from .utils import (
    find_iv_from_all_ivs,
    is_reg,
    reg_sym_to_reg_name,
    replace_and_eval,
    retrieve_iv_var,
    iv_to_iv_name,
    bytes_to_float,
    compare_coefficient,
)
from enum import Enum, auto

from itertools import product, combinations
from functools import reduce
import struct

import numpy as np
import claripy


class AST_OP(Enum):
    CONV = auto()
    DWCONV = auto()  # deepwise conv
    MAXPOOL = auto()
    AVGPOOL = auto()
    FC = auto()
    BN = auto()
    RELU = auto()
    ADD = auto()
    SOFTMAX = auto()

    def __eq__(self, other):
        if isinstance(other, AST_OP):
            return self.value == other.value
        return NotImplemented


class LiftedIV:
    """
    IV in lifted ast, far more simple than class IV.
    The increment here is always 1.
    """

    def __init__(self, name, lb, ub, iv_var, is_fake=False):
        self.name = name
        # inclusive
        self.lb = lb
        # TODO: exclusive
        self.ub = ub
        self.iv_var = iv_var
        self.is_fake = is_fake

    def __repr__(self) -> str:
        return "name: %s, lb: %s, ub: %s" % (self.name, self.lb, self.ub)

    def size(self):
        return self.ub - self.lb


class LiftedAST:
    """
    Represent the lifted ast
    """

    def __init__(self, addr_expr, ast_expr, ivs_dict, solver):
        self.addr_expr = addr_expr
        self.ast_expr = ast_expr
        self.ivs_dict = ivs_dict

        self._solver = solver

        self.reg_constraints = []

        # dict: write_addr => (val_tuple, read_values)
        # with self.axis as axis
        self.rw_dict = {}

        self.write_range = None
        self.read_range = None

        # tuple: (iv, iv_var)
        self.addr_iv_tuple = []
        self.expr_iv_tuple = []

        # op, attributes, weights
        self.op_type = None
        self.kernel_size = None
        self.relu_flag = False

        self._unsolved_reg = set()
        self._prepare()
        #if self.ast_expr is not None and self.ast_expr.offset_mem is not None:
        #    print("Type: ",self.op_type)
        #    print("Lifted ast offset: ",self.ast_expr.offset)
        #    print("Lifted ast offset mem: ",self.ast_expr.offset_mem)

    def _prepare(self):
        if self.addr_expr is None:
            return

        # Collect the unresolved reg symbol
        for leaf in self.addr_expr.leaf_asts():
            if is_reg(leaf):
                self._unsolved_reg.add(leaf)

        for leaf in self.ast_expr.leaf_asts():
            if is_reg(leaf):
                self._unsolved_reg.add(leaf)

        # Collect addr_iv_tuple
        addr_iv_var = set(retrieve_iv_var(self.addr_expr))
        addr_iv = [
            find_iv_from_all_ivs(iv_var, self.ivs_dict) for iv_var in addr_iv_var
        ]
        self.addr_iv_tuple = [(iv, iv.iv_var) for iv in addr_iv]

        expr_iv_var = set(retrieve_iv_var(self.ast_expr))
        expr_iv = [
            find_iv_from_all_ivs(iv_var, self.ivs_dict) for iv_var in expr_iv_var
        ]
        self.expr_iv_tuple = [(iv, iv.iv_var) for iv in expr_iv]

        # r/w addr
        self.axis = [iv_tuple[0] for iv_tuple in self.addr_iv_tuple]

        # match
        self.match()

    def __repr__(self) -> str:
        return "<Lifted AST: %s>\n addr_expr: %s\n ast_expr: %s\n ivs_dict: %s\n" % (
            self.op_type,
            self.addr_expr,
            self.ast_expr,
            self.ivs_dict,
        )

    def concretize_reg(self, func_calling_regs):
        """ """
        # get extra constraints from func_calling_regs, and do replacement
        if func_calling_regs is not None:
            assert isinstance(func_calling_regs, RegisterView)
            for sym in self._unsolved_reg:
                reg_name = reg_sym_to_reg_name(func_calling_regs._arch, sym)
                reg_val = func_calling_regs[reg_name]
                assert reg_val.concrete
                # self.reg_constraints.append(sym == self._solver.eval(reg_val))
                self.addr_expr = self.addr_expr.replace(sym, reg_val)
                self.ast_expr = self.ast_expr.replace(sym, reg_val)

    def _get_base_reg(self, expr):
        base_reg = []
        for leaf in expr.leaf_asts():
            if leaf.concrete and leaf.args[0] > 1000:
                base_reg.append(leaf.args[0])
        assert len(base_reg) == 1
        return base_reg[0]

    def get_mem_read_base_reg(self):
        if self.op_type == AST_OP.ADD:
            return [
                self._get_base_reg(self.ast_expr._expr_0),
                self._get_base_reg(self.ast_expr._expr_1),
            ]
        elif hasattr(self, "input_expr") and self.input_expr is not None:
            return [self._get_base_reg(self.input_expr)]
        else:
            return None

    def get_mem_write_base_reg(self):
        if hasattr(self, "addr_expr") and self.addr_expr is not None:
            return [self._get_base_reg(self.addr_expr)]
        else:
            return None

    def get_mem_rw_range(self):
        """
        Get the coarse-grained range of memory read/write addr, it is to determine the topology of the neural network
        TODO: we dont consider the constraints (e.g. iv0 + iv1 > 1),
            it affects act range, but not param range
        FIXME: some iv expr in the activation ast (input_expr) have offset 1
        """

        # TODO: we need to pass these info for pooling layer
        if self.addr_expr is None or self.ast_expr is None:
            self.read_range = []
            self.write_range = []
            return

        # addr range
        min_addr_iv_val_list = [
            (iv_tuple[1], iv_tuple[0].lb) for iv_tuple in self.addr_iv_tuple
        ]
        min_addr_addr = replace_and_eval(
            min_addr_iv_val_list, self.addr_expr, self._solver
        )
        max_addr_iv_val_list = [
            (iv_tuple[1], iv_tuple[0].ub) for iv_tuple in self.addr_iv_tuple
        ]
        max_addr_addr = replace_and_eval(
            max_addr_iv_val_list, self.addr_expr, self._solver
        )
        self.write_range = (min_addr_addr, max_addr_addr)

        # expr range
        min_expr_iv_val_list = [
            (iv_tuple[1], iv_tuple[0].lb) for iv_tuple in self.expr_iv_tuple
        ]
        min_expr_addr = self.ast_expr.get_mem_read_addr(
            min_expr_iv_val_list, self._solver
        )
        max_expr_iv_val_list = [
            (iv_tuple[1], iv_tuple[0].ub) for iv_tuple in self.expr_iv_tuple
        ]
        max_expr_addr = self.ast_expr.get_mem_read_addr(
            max_expr_iv_val_list, self._solver
        )
        self.read_range = list(zip(min_expr_addr, max_expr_addr))

    def get_mem_rw(self):
        """
        Get all the memory read/write addr
        However it is too slow
        """
        addr_iv_val_list = [
            [i for i in range(iv_tuple[0].lb, iv_tuple[0].ub)]
            for iv_tuple in self.addr_iv_tuple
        ]

        # data format
        shape = tuple([iv.size() for iv in self.axis])
        nd_array = NdArray(shape, self.axis)

        # TODO: not use 32
        for addr_iv_val in list(product(*addr_iv_val_list)):
            print("addr_iv_var", addr_iv_val)
            # create addr_iv -> val
            addr_iv_val_tuple_list = []
            for addr_iv_idx in range(len(self.addr_iv_tuple)):
                addr_iv_val_tuple_list.append(
                    (
                        self.addr_iv_tuple[addr_iv_idx][1],
                        self._solver.BVV(addr_iv_val[addr_iv_idx], 32),
                    )
                )

            # replace iv with val and get addr
            eval_addr_expr = self.addr_expr
            for iv_val_tuple in addr_iv_val_tuple_list:
                eval_addr_expr = eval_addr_expr.replace(
                    iv_val_tuple[0], iv_val_tuple[1]
                )
            addr = self._solver.eval_one(eval_addr_expr)

            assert addr not in self.rw_dict

            self.rw_dict[addr] = (
                addr_iv_val,
                self.ast_expr.get_mem_read(addr_iv_val_tuple_list, self._solver),
            )

    def match(self):
        if self.ast_expr.op == "sum":
            if self.ast_expr.expr.op == "mul":
                if len(self.ivs_dict) > 2:
                    self.op_type = AST_OP.CONV
                else:
                    self.op_type = AST_OP.FC
        if self.ast_expr.op == "add":
            self.op_type = AST_OP.ADD

    def recover_attributes(self, prev_info):
        attributes = {}
        if self.op_type == AST_OP.CONV:
            attributes["input_channel"] = self.input_channel_iv.size()
            attributes["output_channel"] = self.output_channel_iv.size()
            attributes["kernel_height"] = self.kernel_height_iv.size()
            attributes["kernel_width"] = self.kernel_width_iv.size()
            attributes["relu"] = self.relu_flag

            # input shape: [input_channel, k_h, k_w, height, width]
            height_iv = None
            width_iv = None
            input_iv_var_list = retrieve_iv_var(self.input_expr)
            input_lifted_iv_list = [
                self._iv_var_to_lifted_iv(iv_var) for iv_var in input_iv_var_list
            ]
            if self.input_channel_iv in input_lifted_iv_list:
                input_lifted_iv_list.remove(self.input_channel_iv)
            # print(input_lifted_iv_list)

            if len(input_lifted_iv_list) == 4 or len(input_lifted_iv_list) == 5:
                iv_pairs = list(combinations(input_lifted_iv_list, 2))
                ivs = [pair for pair in iv_pairs if pair[0].size() == pair[1].size()]
                ivs.sort(key=lambda x: x[0].size())
                # print("ivs", ivs)
                assert len(ivs) == 2
                width_iv = ivs[0][0]
                height_iv = ivs[0][1]

                attributes["input_height"] = ivs[1][0].size()
                attributes["input_width"] = ivs[1][1].size()

            elif len(input_lifted_iv_list) == 2:
                # k_h and k_w are 1
                iv_pairs = list(combinations(input_lifted_iv_list, 2))
                ivs = [pair for pair in iv_pairs if pair[0].size() == pair[1].size()]

                attributes["input_height"] = ivs[0][0].size()
                attributes["input_width"] = ivs[0][1].size()
            else:
                assert False

            # output shape: [output_channel, height, width]
            output_iv_var_list = retrieve_iv_var(self.addr_expr)
            output_lifted_iv_list = [
                self._iv_var_to_lifted_iv(iv_var) for iv_var in output_iv_var_list
            ]
            if len(output_lifted_iv_list) == 3:
                output_ivs = [
                    iv for iv in output_lifted_iv_list if iv != self.output_channel_iv
                ]
                attributes["output_height"] = output_ivs[0].size()
                attributes["output_width"] = output_ivs[1].size()
            else:
                assert False

            assert len(prev_info) <= 1
            if len(prev_info) == 1 and "output_height" in prev_info[0]:
                prev_output_height = prev_info[0]["output_height"]
                prev_output_width = prev_info[0]["output_width"]
                assert prev_output_height == prev_output_width

                # striding
                # print("prev_output_height", prev_output_height)
                # print("input_height", attributes["input_height"])
                if attributes["input_height"] < prev_output_height:
                    assert prev_output_height % attributes["input_height"] == 0
                    attributes["striding"] = (
                        prev_output_height // attributes["input_height"]
                    )
                    attributes["input_height"] = prev_output_height
                    attributes["input_width"] = prev_output_width
                else:
                    attributes["striding"] = 1
            else:
                attributes["striding"] = 1

            # padding
            attributes["padding"] = (
                attributes["output_height"] * attributes["striding"]
                + attributes["kernel_height"]
                - attributes["input_height"]
                - 1
            ) // 2

        elif self.op_type == AST_OP.FC:
            attributes["output_size"] = self.col_idx_iv.size()
            attributes["contracted_size"] = self.row_idx_iv.size()
            attributes["input_size"] = 1
            attributes["output_channel"] = 1

        elif self.op_type == AST_OP.MAXPOOL:
            # TODO: infer it from the context
            if self.kernel_size is None:
                self.kernel_size = 3
            attributes["kernel_shape"] = self.kernel_size
            attributes["stride"] = self.kernel_size
            attributes["output_height"] = int(
                (
                    prev_info[0]["output_height"] - attributes["kernel_shape"]
                ) / attributes["stride"] + 1
            )
            attributes["output_width"] = int(
                (
                    prev_info[0]["output_width"] - attributes["kernel_shape"]
                ) / attributes["stride"] + 1
            )
            attributes["output_channel"] = prev_info[0]["output_channel"]

        elif self.op_type == AST_OP.ADD:
            attributes["output_height"] = prev_info[0]["output_height"]
            attributes["output_width"] = prev_info[0]["output_width"]
            attributes["output_channel"] = prev_info[0]["output_channel"]

        elif self.op_type == AST_OP.RELU:
            attributes["output_height"] = prev_info[0]["output_height"]
            attributes["output_width"] = prev_info[0]["output_width"]
            attributes["output_channel"] = prev_info[0]["output_channel"]

        elif self.op_type == AST_OP.AVGPOOL:
            attributes["kernel_shape"] = self.kernel_size
            attributes["stride"] = self.kernel_size
            attributes["output_height"] = int(
                (
                    prev_info[0]["output_height"] - attributes["kernel_shape"]
                ) / attributes["stride"] + 1
            )
            attributes["output_width"] = int(
                (
                    prev_info[0]["output_width"] - attributes["kernel_shape"]
                ) / attributes["stride"] + 1
            )
            attributes["output_channel"] = prev_info[0]["output_channel"]

        elif self.op_type == AST_OP.SOFTMAX:
            return {"output_size": prev_info[0]["output_size"]}

        return attributes

    def extract_weights(self, state):
        """
        Extract weights. We need `state` to get the concrete value from the binary.
        TODO: we also need to use mem_read and mem_write to more precisely decide weights and previous outputs
        """

        assert self.op_type is not None
        if self.op_type == AST_OP.CONV:
            assert self.output_channel_iv is not None
            assert self.input_channel_iv is not None
            assert self.kernel_height_iv is not None
            assert self.kernel_width_iv is not None

            print(self.output_channel_iv)
            print(self.input_channel_iv)
            print(self.kernel_height_iv)
            print(self.kernel_width_iv)

            # iterate through each iv in weight_expr and replace iv_var with the concrete value to get the weights
            weights = np.zeros(
                (
                    self.output_channel_iv.size(),
                    self.input_channel_iv.size(),
                    self.kernel_height_iv.size(),
                    self.kernel_width_iv.size(),
                ), dtype=np.float32
            )
            weights_addr = np.zeros(
                (
                    self.output_channel_iv.size(),
                    self.input_channel_iv.size(),
                    self.kernel_height_iv.size(),
                    self.kernel_width_iv.size(),
                ), dtype=int
            )
            print("Extracting weights")
            print("Weight expr: ",self.weight_expr)
            for output_channel_idx in range(self.output_channel_iv.size()):
                for input_channel_idx in range(self.input_channel_iv.size()):
                    for kernel_height_idx in range(self.kernel_height_iv.size()):
                        for kernel_width_idx in range(self.kernel_width_iv.size()):
                            iv_assignment_list = [
                                (self.output_channel_iv.iv_var, output_channel_idx),
                                (self.input_channel_iv.iv_var, input_channel_idx),
                                (self.kernel_height_iv.iv_var, kernel_height_idx),
                                (self.kernel_width_iv.iv_var, kernel_width_idx),
                            ]
                            # remove the fake iv
                            iv_assignment_list = [
                                assignment
                                for assignment in iv_assignment_list
                                if assignment[0] is not None
                            ]

                            weight_addr = replace_and_eval(
                                iv_assignment_list, self.weight_expr, state.solver
                            )
                            #added to export the adress mapping for patcher API
                            weights_addr[
                                output_channel_idx,
                                input_channel_idx,
                                kernel_height_idx,
                                kernel_width_idx,
                            ] = weight_addr
                            weight_bytes = state.memory.load(weight_addr, 4).args[0]

                            weights[
                                output_channel_idx,
                                input_channel_idx,
                                kernel_height_idx,
                                kernel_width_idx,
                            ] = bytes_to_float(weight_bytes, endian=False)

            print("Extracting bias")
            bias = np.zeros(self.output_channel_iv.size(),dtype=np.float32)
            bias_addr_list = np.zeros(self.output_channel_iv.size(), dtype=int)
            if self.ast_expr.offset is not None:
                for output_channel_idx in range(self.output_channel_iv.size()):
                    bias[output_channel_idx] = bytes_to_float(
                        self.ast_expr.offset[output_channel_idx].args[0]
                    )
                    bias_addr_list[output_channel_idx] = self.ast_expr.offset_mem[output_channel_idx].args[0]
                    print(
                        "extracted offset: ", 
                        hex(self.ast_expr.offset_mem[output_channel_idx].args[0]),
                        " -> ",
                        hex(self.ast_expr.offset[output_channel_idx].args[0])
                    )

            return weights, bias, weights_addr, bias_addr_list

        elif self.op_type == AST_OP.FC:
            weights = np.zeros(
                (
                    self.row_idx_iv.size(), self.col_idx_iv.size()
                ), dtype=np.float32
            )
            weights_addr = np.zeros((self.row_idx_iv.size(),
                self.col_idx_iv.size()), dtype=int)
            for row_idx in range(self.row_idx_iv.size()):
                for col_idx in range(self.col_idx_iv.size()):
                    iv_assignment_list = [
                        (self.row_idx_iv.iv_var, row_idx),
                        (self.col_idx_iv.iv_var, col_idx),
                    ]
                    weight_addr = replace_and_eval(
                        iv_assignment_list, self.weight_expr, state.solver
                    )
                    weights_addr[row_idx, col_idx] = weight_addr #added to export the adress mapping for patcher API 
                    weight_bytes = state.memory.load(weight_addr, 4).args[0]
                    weights[row_idx, col_idx] = bytes_to_float(
                        weight_bytes, endian=False
                    )

            bias = np.zeros(self.col_idx_iv.size(), dtype=np.float32)
            bias_addr_list = np.zeros(self.col_idx_iv.size(), dtype=int)
            for col_idx in range(self.col_idx_iv.size()):
                iv_assignment_list = [(self.col_idx_iv.iv_var, col_idx)]
                bias_addr = replace_and_eval(
                    iv_assignment_list, self.ast_expr.offset, state.solver
                )
                bias_addr_list[col_idx] = bias_addr
                bias_bytes = state.memory.load(bias_addr, 4).args[0]
                bias[col_idx] = bytes_to_float(bias_bytes, endian=False)

            return weights, bias, weights_addr, bias_addr_list

        else:
            return None, None, None, None

    def recover(self):
        """ """
        assert self.op_type is not None
        print("op_type", self.op_type)

        if self.op_type == AST_OP.CONV:
            # decide weights expr: heuristic here is that, for conv, the iv of weights (i.e. kernel window) is smaller than the iv of input.
            expr_0 = self.ast_expr.expr.expr_0
            iv_range_0 = self._range_of_expr(expr_0)
            expr_1 = self.ast_expr.expr.expr_1
            iv_range_1 = self._range_of_expr(expr_1)
            if iv_range_0 != iv_range_1:
                self.weight_expr = expr_0 if iv_range_0 < iv_range_1 else expr_1
                self.input_expr = expr_0 if iv_range_0 > iv_range_1 else expr_1
            else:
                expr_0_iv_var_list = retrieve_iv_var(expr_0)
                expr_1_iv_var_list = retrieve_iv_var(expr_1)
                self.weight_expr = (
                    expr_0
                    if len(expr_0_iv_var_list) < len(expr_1_iv_var_list)
                    else expr_1
                )
                self.input_expr = (
                    expr_0
                    if len(expr_0_iv_var_list) > len(expr_1_iv_var_list)
                    else expr_1
                )
            print("weight_expr", self.weight_expr)
            print("input_expr", self.input_expr)

            # weights shape: [output_channel, input_channel, kernel_height, kernel_width]
            input_channel_iv = None
            kernel_height_iv = None
            kernel_width_iv = None
            output_channel_iv = None

            iv_var_list = retrieve_iv_var(self.weight_expr)
            lifted_iv_list = [
                self._iv_var_to_lifted_iv(iv_var) for iv_var in iv_var_list
            ]
            num_ivs = len(lifted_iv_list)

            # FIXME: the following code needs refactoring
            # 1. reasoning which case it falls to
            # 2. merge with self.recover_attributes
            if num_ivs == 2:
                # kernel size is 1x1
                self.kernel_height_iv = LiftedIV(
                    "kernel_height", 0, 1, None, is_fake=True
                )
                self.kernel_width_iv = LiftedIV(
                    "kernel_width", 0, 1, None, is_fake=True
                )

                output_iv_var_list = retrieve_iv_var(self.addr_expr)
                output_lifted_iv_list = [
                    self._iv_var_to_lifted_iv(iv_var) for iv_var in output_iv_var_list
                ]
                self.input_channel_iv = [
                    iv for iv in lifted_iv_list if iv not in output_lifted_iv_list
                ][0]

                self.output_channel_iv = [
                    iv for iv in lifted_iv_list if iv != input_channel_iv
                ][0]

            elif num_ivs == 3:
                # input_channel == 1
                self.input_channel_iv = LiftedIV(
                    "input_channel", 0, 1, None, is_fake=True
                )

                # kernel_height usually equals to kernel_width, and have the expr pattern "kernel_height_iv * kernel_width + kernel_width_iv" (i.e. access a element in a 2d array)
                iv_pairs = list(combinations(lifted_iv_list, 2))
                kernel_ivs = [
                    pair for pair in iv_pairs if pair[0].size() == pair[1].size()
                ]
                assert len(kernel_ivs) == 1

                if compare_coefficient(
                    self.weight_expr,
                    kernel_ivs[0][0].iv_var,
                    kernel_ivs[0][1].iv_var,
                    self._solver,
                ):
                    self.kernel_height_iv = kernel_ivs[0][0]
                    self.kernel_width_iv = kernel_ivs[0][1]
                else:
                    self.kernel_height_iv = kernel_ivs[0][1]
                    self.kernel_width_iv = kernel_ivs[0][0]

                self.output_channel_iv = [
                    iv
                    for iv in lifted_iv_list
                    if iv != self.kernel_width_iv and iv != self.kernel_height_iv
                ][0]

            elif num_ivs == 4:
                iv_pairs = list(combinations(lifted_iv_list, 2))
                kernel_ivs = [
                    pair for pair in iv_pairs if pair[0].size() == pair[1].size()
                ]
                kernel_ivs.sort(key=lambda x: x[0].size())

                # one of the channel size equals to kernel size. A better way here to compare their coefficient.
                if len(kernel_ivs) == 3:
                    kernel_ivs = [
                        ivs
                        for ivs in kernel_ivs
                        if "IVRC" not in ivs[0].name and "IVRC" not in ivs[1].name
                    ]

                if compare_coefficient(
                    self.weight_expr,
                    kernel_ivs[0][0].iv_var,
                    kernel_ivs[0][1].iv_var,
                    self._solver,
                ):
                    self.kernel_height_iv = kernel_ivs[0][0]
                    self.kernel_width_iv = kernel_ivs[0][1]
                else:
                    self.kernel_height_iv = kernel_ivs[0][1]
                    self.kernel_width_iv = kernel_ivs[0][0]
                
                # in the addr_expr, there is no input channel iv
                addr_iv_var_list = retrieve_iv_var(self.addr_expr)
                addr_lifted_iv_list = [
                    self._iv_var_to_lifted_iv(iv_var) for iv_var in addr_iv_var_list
                ]
                assert len(addr_lifted_iv_list) == 3
                self.input_channel_iv = [
                    iv
                    for iv in lifted_iv_list
                    if iv not in addr_lifted_iv_list
                    and iv != self.kernel_width_iv
                    and iv != self.kernel_height_iv
                ][0]

                self.output_channel_iv = [
                    iv
                    for iv in lifted_iv_list
                    if iv != self.kernel_width_iv
                    and iv != self.kernel_height_iv
                    and iv != self.input_channel_iv
                ][0]

            elif num_ivs == 5:
                # When one outer loop is split into two

                # height usually equals to width, and have the expr pattern "height_iv * width + width_iv" (i.e. access a element in a 2d array)
                iv_pairs = list(combinations(lifted_iv_list, 2))
                kernel_ivs = [
                    pair for pair in iv_pairs if pair[0].size() == pair[1].size()
                ]
                kernel_ivs.sort(key=lambda x: x[0].size())
                if compare_coefficient(
                    self.weight_expr,
                    kernel_ivs[0][0].iv_var,
                    kernel_ivs[0][1].iv_var,
                    self._solver,
                ):
                    self.kernel_height_iv = kernel_ivs[0][0]
                    self.kernel_width_iv = kernel_ivs[0][1]
                else:
                    self.kernel_height_iv = kernel_ivs[0][1]
                    self.kernel_width_iv = kernel_ivs[0][0]
                
                # remaining three are output and input channel

                # in the addr_expr, there is no input channel iv
                addr_iv_var_list = retrieve_iv_var(self.addr_expr)
                addr_lifted_iv_list = [
                    self._iv_var_to_lifted_iv(iv_var) for iv_var in addr_iv_var_list
                ]

                assert len(addr_lifted_iv_list) == 4
                self.input_channel_iv = [
                    iv
                    for iv in lifted_iv_list
                    if iv not in addr_lifted_iv_list
                    and iv != self.kernel_width_iv
                    and iv != self.kernel_height_iv
                ][0]

                # the other two are output_channel_iv, we eliminate the first one and modify the second one
                output_channel_iv_list = [
                    iv
                    for iv in lifted_iv_list
                    if iv != self.input_channel_iv
                    and iv != self.kernel_width_iv
                    and iv != self.kernel_height_iv
                ]
                to_eliminate_iv = output_channel_iv_list[0]
                self.addr_expr = self.addr_expr.replace(
                    to_eliminate_iv.iv_var, self._solver.BVV(0, 32)
                )
                self.ast_expr = self.ast_expr.replace(
                    to_eliminate_iv.iv_var, self._solver.BVV(0, 32)
                )
                self.ivs_dict[
                    output_channel_iv_list[1].name
                ].ub *= to_eliminate_iv.size()
                del self.ivs_dict[to_eliminate_iv.name]
                self.output_channel_iv = output_channel_iv_list[1]

                # reacquire weight expr since ast_expr has been changed
                expr_0 = self.ast_expr.expr.expr_0
                iv_range_0 = self._range_of_expr(expr_0)
                expr_1 = self.ast_expr.expr.expr_1
                iv_range_1 = self._range_of_expr(expr_1)
                assert iv_range_0 != iv_range_1
                self.weight_expr = expr_0 if iv_range_0 < iv_range_1 else expr_1

                # eliminate one of the iv in together_iv_var_list
                # eliminated_iv_var = together_iv_var_list[0]
                # eliminated_iv = self._iv_var_to_lifted_iv(eliminated_iv_var)
                # self.addr_expr.replace(eliminated_iv_var, self._solver.BVV(0, 32))
                # self.ast_expr.replace(eliminated_iv_var, self._solver.BVV(0, 32))
                # self.ivs_dict[
                #     self._iv_var_to_lifted_iv(together_iv_var_list[1]).addr
                # ].ub *= eliminated_iv.size()
                # del self.ivs_dict[together_iv_var_list[0]]

            else:
                assert False

            print("input_channel_iv", self.input_channel_iv)
            print("output_channel_iv", self.output_channel_iv)
            print("kernel_height_iv", self.kernel_height_iv)
            print("kernel_width_iv", self.kernel_width_iv)

        elif self.op_type == AST_OP.FC:
            # only one constracted dimension, normally the last op of the network
            if len(self.ast_expr.idx_iv) == 1:
                weight_expr = (
                    self.ast_expr.expr.expr_0
                    if len(retrieve_iv_var(self.ast_expr.expr.expr_0))
                    > len(retrieve_iv_var(self.ast_expr.expr.expr_1))
                    else self.ast_expr.expr.expr_1
                )
                weight_iv_var_list = retrieve_iv_var(weight_expr)
                assert len(weight_iv_var_list) == 2
                self.weight_expr = weight_expr

                # weights shape: [row_idx, col_idx]
                weight_lifted_iv_list = [
                    self._iv_var_to_lifted_iv(iv_var) for iv_var in weight_iv_var_list
                ]
                weight_lifted_iv_list.sort(key=lambda x: x.size())

                self.row_idx_iv = weight_lifted_iv_list[1]
                self.col_idx_iv = weight_lifted_iv_list[0]

                print("row_idx_iv", self.row_idx_iv)
                print("col_idx_iv", self.col_idx_iv)

                # bias shape: [col_idx]
                bias_iv_var_list = retrieve_iv_var(self.ast_expr.offset)
                bias_lifted_iv_list = [
                    self._iv_var_to_lifted_iv(iv_var) for iv_var in bias_iv_var_list
                ]
                assert len(bias_lifted_iv_list) == 1
                self.bias_iv = bias_lifted_iv_list[0]
                assert self.bias_iv == self.col_idx_iv

            else:
                assert False

        else:
            pass

    def _range_of_expr(self, expr):
        """
        Get the total range of expr
        """
        return reduce(
            (lambda x, y: x * y),
            [
                self._iv_var_to_lifted_iv(iv_var).size()
                for iv_var in retrieve_iv_var(expr)
            ],
        )

    def _iv_var_to_lifted_iv(self, iv_var):
        """
        Get the LiftedIV object from iv_var
        """
        return self.ivs_dict[iv_to_iv_name(iv_var)]
