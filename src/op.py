import itertools

from .ndarray import NdArray
from .utils import hex_to_float, replace_and_eval, retrieve_iv_var, iv_to_iv_name

from functools import reduce
import operator


class SumMul:
    """
    Deprecated
    """

    def __init__(self, arg_0, arg_1, offset, idx_iv, all_ivs):
        self._arg_0 = arg_0
        self._arg_1 = arg_1
        self._offset = offset

        # TODO: we should do multiple idx iv here
        self._idx_iv = idx_iv  # the to_complete_iv
        self._all_ivs = all_ivs

    @property
    def op(self):
        return "summul"

    @property
    def idx_lb(self):
        return self._idx_iv.init_val

    @property
    def idx_ub(self):
        return self._idx_iv.total_count

    def __eq__(self, other) -> bool:
        assert False

    def __repr__(self) -> str:
        return "[Sum of Mul]\n arg_0 : %s\n arg_1 : %s\n offset : %s\n idx: %s\n" % (
            self._arg_0,
            self._arg_1,
            self._offset,
            self._idx_iv.name,
        )

    def leaf_asts(self):
        yield from self._arg_0.leaf_asts()
        yield from self._arg_1.leaf_asts()
        if self._offset is not None:
            yield from self._offset.leaf_asts()

    def replace(self, old_iv_var, new_iv_var):
        """
        Instantiate a new SumMul
        """
        new_arg_0 = self._arg_0.replace(old_iv_var, new_iv_var)
        new_arg_1 = self._arg_1.replace(old_iv_var, new_iv_var)
        new_offset = None
        if self._offset is not None:
            new_offset = self._offset.replace(old_iv_var, new_iv_var)

        return SumMul(new_arg_0, new_arg_1, new_offset, self._idx_iv, self._all_ivs)

    def update_idx(self, old_iv, new_iv):
        """
        When doing replacement, idx needs to be checked and updated
        """
        if self._idx_iv == old_iv:
            self._idx_iv = new_iv

    def get_iv_vars_set(self):
        return set(
            [
                *retrieve_iv_var(self._arg_0),
                *retrieve_iv_var(self._arg_1),
                *retrieve_iv_var(self._offset),
            ]
        )

    def get_idx_iv_var(self):
        for iv_var in self.get_iv_vars_set():
            if self._idx_iv.name in iv_var.__str__():
                return iv_var

    def get_addr_iv_var(self):
        for iv_var in self.get_iv_vars_set():
            if self._idx_iv.name not in iv_var.__str__():
                return iv_var

    def get_addr_iv(self):
        for iv_addr in self._all_ivs:
            if iv_addr != self._idx_iv.addr:
                return self._all_ivs[iv_addr]
    
    def check_has_iv(self, iv):
        return iv in self.get_iv_vars_set()

    def extract(self, state, solver, extra_constraints):
        """
        Extract parameters
        """
        mem = state.memory
        # extract offset
        if self._offset is not None:
            offset_params = []
            addr_iv = self.get_addr_iv()
            addr_iv_var = self.get_addr_iv_var()
            for idx_val in range(
                addr_iv.init_val, addr_iv.total_count, addr_iv.increment
            ):
                # we replace the iv here because of
                # the constraints added to break loop
                replaced_expr = self._offset.replace(
                    addr_iv_var, state.solver.BVV(idx_val, 32)
                )

                mem_offset = solver.eval_one(
                    replaced_expr, extra_constraints=extra_constraints
                )
                # assuming it is 32-bits LE float
                hex_str = hex(solver.eval_one(mem.load(mem_offset, 4)))
                offset_params.append(hex_to_float(hex_str))


class Add:
    """
    Add
    """

    def __init__(self, expr_0, expr_1):
        self.op = "add"

        self._expr_0 = expr_0
        self._expr_1 = expr_1

    def __repr__(self) -> str:
        return "[Add]\n expr_0:\n %s\n expr_1:\n %s\n \n" % (self._expr_0, self._expr_1)

    @property
    def expr_0(self):
        return self._expr_0

    @property
    def expr_1(self):
        return self._expr_1

    def leaf_asts(self):
        yield from self._expr_0.leaf_asts()
        yield from self._expr_1.leaf_asts()

    def replace(self, old_iv_var, new_iv_var):
        new_expr_0 = self._expr_0.replace(old_iv_var, new_iv_var)
        new_expr_1 = self._expr_1.replace(old_iv_var, new_iv_var)

        return Add(new_expr_0, new_expr_1)

    def get_mem_read_addr(self, iv_val_list, solver):
        eval_expr_0 = self._expr_0
        expr_0_addr = replace_and_eval(iv_val_list, eval_expr_0, solver)

        eval_expr_1 = self._expr_1
        expr_1_addr = replace_and_eval(iv_val_list, eval_expr_1, solver)

        return (expr_0_addr, expr_1_addr)


class Mul:
    """
    Multiply of expr_0 and expr_1
    """

    def __init__(self, expr_0, expr_1):
        self.op = "mul"

        self._expr_0 = expr_0
        self._expr_1 = expr_1

    def __repr__(self):
        return "[Mul]\n expr_0:\n %s\n expr_1:\n %s\n \n" % (self._expr_0, self._expr_1)

    @property
    def expr_0(self):
        return self._expr_0

    @property
    def expr_1(self):
        return self._expr_1

    def leaf_asts(self):
        yield from self._expr_0.leaf_asts()
        yield from self._expr_1.leaf_asts()

    def replace(self, old_iv_var, new_iv_var):
        new_expr_0 = self._expr_0.replace(old_iv_var, new_iv_var)
        new_expr_1 = self._expr_1.replace(old_iv_var, new_iv_var)

        return Mul(new_expr_0, new_expr_1)

    def get_mem_read(self, solver):
        expr_0_addr = solver.eval_one(self._expr_0)
        expr_1_addr = solver.eval_one(self._expr_1)
        return (expr_0_addr, expr_1_addr)

    def get_mem_read_addr(self, iv_val_list, solver):
        eval_expr_0 = self._expr_0
        expr_0_addr = replace_and_eval(iv_val_list, eval_expr_0, solver)

        eval_expr_1 = self._expr_1
        expr_1_addr = replace_and_eval(iv_val_list, eval_expr_1, solver)

        return (expr_0_addr, expr_1_addr)


class Sum:
    """
    Sum of an expr and an optional offset, with idx_iv as the sum idx.
    Note that there could be multiple sum idx.
    """

    def __init__(self, expr, offset, idx_iv):
        self.op = "sum"

        self._expr = expr
        self._offset = offset

        assert isinstance(idx_iv, list)
        self._idx_iv = idx_iv

    def __repr__(self):
        return "[Sum] \nidx: %s\n expr:\n %s\n offset:\n %s\n" % (
            [_iv.name for _iv in self._idx_iv],
            self._expr,
            self._offset,
        )

    @property
    def idx_iv(self):
        return self._idx_iv

    @property
    def idx_lb(self):
        assert False
        return self._idx_iv.init_val

    @property
    def idx_ub(self):
        assert False
        return self._idx_iv.total_count

    @property
    def expr(self):
        return self._expr

    @property
    def offset(self):
        return self._offset

    def __eq__(self, other) -> bool:
        assert False

    def leaf_asts(self):
        yield from self._expr.leaf_asts()
        # if self._offset is not None:
        #     yield from self._offset.leaf_asts()

    def replace(self, old_iv_var, new_iv_var):
        new_expr = self._expr.replace(old_iv_var, new_iv_var)
        # if self._offset is not None:
        #     new_offset = self._offset.replace(old_iv_var, new_iv_var)

        if new_iv_var.op == "BVV":
            # remove old_iv_var from idx_iv
            old_iv_idx = None
            for idx, iv in enumerate(self._idx_iv):
                if iv.name == iv_to_iv_name(old_iv_var):
                    old_iv_idx = idx 
            
            if old_iv_idx is not None:
                del self._idx_iv[old_iv_idx]

        # TODO: we should update idx_iv as well

        return Sum(new_expr, self._offset, self._idx_iv)

    def update_idx(self, old_iv, new_iv):
        # TODO: should update sub-expr
        ls_idx = self._idx_iv.index(old_iv)
        self._idx_iv[ls_idx] = new_iv

    def get_iv_vars_set(self):
        if self._expr.op == "mul":
            return set(
                [
                    *retrieve_iv_var(self._expr._expr_0),
                    *retrieve_iv_var(self._expr._expr_1),
                    *retrieve_iv_var(self._offset),
                ]
            )
        else:
            assert False

    def check_has_iv(self, iv):
        return iv in self.get_iv_vars_set()

    def get_mem_read(self, addr_iv_val_tuple_list, solver):
        """
        Get all the mem_read addr. However it is too slow

        @ addr_iv_val_list: concretized addr_iv
        """
        # Returning data's format
        axis = [iv for iv in self.idx_iv]
        shape = tuple([idx_iv.size() for idx_iv in axis])
        nd_array = NdArray(shape, axis)

        eval_ast_expr = self._expr
        for iv_val_tuple in addr_iv_val_tuple_list:
            eval_ast_expr = eval_ast_expr.replace(iv_val_tuple[0], iv_val_tuple[1])

        iv_val_list = [[i for i in range(iv.lb, iv.ub)] for iv in self._idx_iv]

        # Assume iv.lb must be zero, otherwise there is an offset
        # to index data_nd_array
        assert all([iv.lb == 0 for iv in self._idx_iv])

        for iv_val in list(itertools.product(*iv_val_list)):
            temp_eval_ast_expr = eval_ast_expr
            iv_val_tuple_list = []
            # create iv val list
            for idx in range(len(self._idx_iv)):
                iv_val_tuple_list.append(
                    (self._idx_iv[idx].iv_var, solver.BVV(iv_val[idx], 32))
                )

            # replace iv
            for iv_val_tuple in addr_iv_val_tuple_list + iv_val_tuple_list:
                temp_eval_ast_expr = temp_eval_ast_expr.replace(
                    iv_val_tuple[0], iv_val_tuple[1]
                )

            nd_array.write(iv_val, temp_eval_ast_expr.get_mem_read(solver))

        return nd_array

    def get_mem_read_addr(self, addr_iv_val_list, solver):
        """
        Get the mem_read addr
        """
        return self._expr.get_mem_read_addr(addr_iv_val_list, solver)

    def extract(self, state, solver, extra_constraints):
        """
        *Deprecated*
        Extract parameters from each element and aggregate them.
        For each idx, do iteration
        """
        assert False

        axis = [iv for iv in self.idx_iv]
        shape = tuple([idx_iv.size() for idx_iv in self.idx_iv])


class Avg:
    """
    Average over a term, with idx_iv as the index,
    count of idx_iv as # of elements
    """

    def __init__(self, expr, idx_iv):
        self.op = "avg"

        self._expr = expr
        self._idx_iv = idx_iv

    def __repr__(self):
        return "[Avg]\n expr:\n %s\n idx:\n %s\n" % (self._expr, self._idx_iv.name)

    @property
    def idx_iv(self):
        return self._idx_iv

    @property
    def idx_lb(self):
        return self._idx_iv.init_val

    @property
    def idx_ub(self):
        return self._idx_iv.total_count

    @property
    def expr(self):
        return self._expr

    def __eq__(self, other) -> bool:
        assert False

    def get_iv_vars_set(self):
        return set([*retrieve_iv_var(self._expr)])

    def leaf_asts(self):
        yield from self._expr.leaf_asts()
