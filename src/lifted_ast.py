from .ndarray import NdArray
from .register import RegisterView
from .utils import find_iv_from_all_ivs, is_reg, reg_sym_to_reg_name, replace_and_eval, retrieve_iv_var

import itertools


class LiftedIV():
    '''
    IV in lifted ast, far more simple than class IV.
    The increment here is always 1.
    '''
    def __init__(self, name, lb, ub, iv_var):
        self.name = name
        # inclusive
        self.lb = lb
        # TODO: exclusive
        self.ub = ub
        self.iv_var = iv_var

    def __repr__(self) -> str:
        return "name: %s, lb: %s, ub: %s" % (self.name, self.lb, self.ub)

    def size(self):
        return self.ub - self.lb


class LiftedAST():
    '''
    Represent the lifted ast
    '''
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

        self._unsolved_reg = set()
        self._prepare()

    def _prepare(self):
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
            find_iv_from_all_ivs(iv_var, self.ivs_dict)
            for iv_var in addr_iv_var
        ]
        self.addr_iv_tuple = [(iv, iv.iv_var) for iv in addr_iv]

        expr_iv_var = set(retrieve_iv_var(self.ast_expr))
        expr_iv = [
            find_iv_from_all_ivs(iv_var, self.ivs_dict)
            for iv_var in expr_iv_var
        ]
        self.expr_iv_tuple = [(iv, iv.iv_var) for iv in expr_iv]

        # r/w addr
        self.axis = [iv_tuple[0] for iv_tuple in self.addr_iv_tuple]

    def __repr__(self) -> str:
        return "<Lifted AST>\n addr_expr: %s\n ast_expr: %s\n ivs_dict: %s\n" % (
            self.addr_expr, self.ast_expr, self.ivs_dict)

    def concretize_reg(self, func_calling_regs):
        # get extra constraints from func_calling_regs, and do replacement
        if func_calling_regs is not None:
            assert (isinstance(func_calling_regs, RegisterView))
            for sym in self._unsolved_reg:
                reg_name = reg_sym_to_reg_name(func_calling_regs._arch, sym)
                reg_val = func_calling_regs[reg_name]
                assert (reg_val.concrete)
                # self.reg_constraints.append(sym == self._solver.eval(reg_val))
                self.addr_expr = self.addr_expr.replace(sym, reg_val)
                self.ast_expr = self.ast_expr.replace(sym, reg_val)

    def get_mem_rw_range(self):
        '''
        Get the coarse-grained range of memory read/write addr
        TODO: we dont consider the constraints (e.g. iv0 + iv1 > 1), 
            it affects act range, but not param range
        '''
        # addr range
        min_addr_iv_val_list = [(iv_tuple[1], iv_tuple[0].lb)
                                for iv_tuple in self.addr_iv_tuple]
        min_addr_addr = replace_and_eval(min_addr_iv_val_list, self.addr_expr,
                                         self._solver)

        max_addr_iv_val_list = [(iv_tuple[1], iv_tuple[0].ub)
                                for iv_tuple in self.addr_iv_tuple]
        max_addr_addr = replace_and_eval(max_addr_iv_val_list, self.addr_expr,
                                         self._solver)

        self.write_range = (min_addr_addr, max_addr_addr)

        # expr range
        min_expr_iv_val_list = [(iv_tuple[1], iv_tuple[0].lb)
                                for iv_tuple in self.expr_iv_tuple]
        min_expr_addr = self.ast_expr.get_mem_read_addr(
            min_expr_iv_val_list, self._solver)

        max_expr_iv_val_list = [(iv_tuple[1], iv_tuple[0].ub)
                                for iv_tuple in self.expr_iv_tuple]
        max_expr_addr = self.ast_expr.get_mem_read_addr(
            max_expr_iv_val_list, self._solver)

        self.read_range = list(zip(min_expr_addr, max_expr_addr))

    def get_mem_rw(self):
        '''
        Get all the memory read/write addr
        However it is too slow
        '''
        addr_iv_val_list = [[i for i in range(iv_tuple[0].lb, iv_tuple[0].ub)]
                            for iv_tuple in self.addr_iv_tuple]

        # data format
        shape = tuple([iv.size() for iv in self.axis])
        nd_array = NdArray(shape, self.axis)

        # TODO: not use 32
        for addr_iv_val in list(itertools.product(*addr_iv_val_list)):
            print("addr_iv_var", addr_iv_val)
            # create addr_iv -> val
            addr_iv_val_tuple_list = []
            for addr_iv_idx in range(len(self.addr_iv_tuple)):
                addr_iv_val_tuple_list.append(
                    (self.addr_iv_tuple[addr_iv_idx][1],
                     self._solver.BVV(addr_iv_val[addr_iv_idx], 32)))

            # replace iv with val and get addr
            eval_addr_expr = self.addr_expr
            for iv_val_tuple in addr_iv_val_tuple_list:
                eval_addr_expr = eval_addr_expr.replace(
                    iv_val_tuple[0], iv_val_tuple[1])
            addr = self._solver.eval_one(eval_addr_expr)

            assert (addr not in self.rw_dict)

            self.rw_dict[addr] = (addr_iv_val,
                                  self.ast_expr.get_mem_read(
                                      addr_iv_val_tuple_list, self._solver))

    def extract(self, state):
        '''
        Extract parameters.
        state is for 1) get memory 2)create new sym
        '''
        # Iterate through each iv in addr and add into extra_constraints

        # extract parameters
        self.ast_expr.extract(state, self._solver, self.reg_constraints)
