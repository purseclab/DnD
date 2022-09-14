from traitlets.traitlets import Instance
from .anno import IVAnnotation, MemReadAnnotation
from .dbg import print_anno
from .utils import check_iv, get_iv_anno, check_iv_expr, is_arm_arch, is_x86

import angr
import claripy

from functools import partial
import operator


def float_to_bvv(f, bit):
    return claripy.BVV(int(f), bit)


def simplify(expr, sol, proj):
    '''
    Simplify expr in a DFS manner.
    Currently we have to enumerate all the operators even if we dont modify, 
    since it is not clear how to create certain operator given its string repr.
    
    If an expr is annotated, we use claripy.simplify() to simplify it. Currently it 
    only supports __add__. There's an issue that constant and offset are merged.
    One solution would be "eliminate" the constant.
    
    All bit-operation are converted into 32/64-bit integer domain.
    '''

    if is_x86(proj.arch):
        bit = 64
    elif is_arm_arch(proj.arch):
        bit = 32
    else:
        assert (False)

    # It is to reuse the solver. Create sol everytime is time-costing
    simplify_sol = partial(simplify, sol=sol, proj=proj)

    if not hasattr(expr, 'op'):
        return None

    if expr.op == 'BVS':
        assert (expr.size() == 32 or expr.size() == 64)
        ret = expr

    elif expr.op == '__add__':
        ret = sum(map(simplify_sol, expr.args))

    elif expr.op == '__mul__':
        assert (len(expr.args) == 2)
        first = simplify_sol(expr.args[0])
        second = simplify_sol(expr.args[1])
        ret = first * second

    elif expr.op == '__lshift__':
        assert (len(expr.args) == 2)
        assert (expr.args[1].concrete)

        exp = sol.eval(expr.args[1])
        ret = simplify_sol(expr.args[0]) * pow(2, exp)

    elif expr.op == '__invert__':
        ret = operator.__invert__(simplify_sol(expr.args[0]))

    elif expr.op == '__xor__':
        ret = operator.__xor__(simplify_sol(expr.args[0]),
                               simplify_sol(expr.args[1]))

    # most likely, it is an addition
    elif expr.op == '__or__':
        ret = simplify_sol(expr.args[0]) + simplify_sol(expr.args[1])
        '''
        ret = operator.__or__(simplify_sol(expr.args[0]),
                              simplify_sol(expr.args[1]))
        '''

    elif expr.op == '__ne__':
        ret = operator.__ne__(simplify_sol(expr.args[0]),
                              simplify_sol(expr.args[1]))

    elif expr.op == '__eq__':
        ret = operator.__eq__(simplify_sol(expr.args[0]),
                              simplify_sol(expr.args[1]))

    elif expr.op == '__and__':
        ret = operator.__and__(simplify_sol(expr.args[0]),
                               simplify_sol(expr.args[1]))

    elif expr.op == '__sub__':
        ret = operator.__sub__(simplify_sol(expr.args[0]),
                               simplify_sol(expr.args[1]))

    # TODO: its semantic?
    elif expr.op == 'LShR':
        ret = claripy.LShR(simplify_sol(expr.args[0]),
                           simplify_sol(expr.args[1]))

    elif expr.op == 'Concat':
        # assert expr is symbolic
        assert (check_iv_expr(expr))

        assert (len(expr.args) >= 2)

        # not contains iv
        if not check_iv_expr(expr):
            ret = claripy.Concat(*(map(simplify_sol, expr.args)))

        elif len(expr.args) > 2:
            assert (False)
            return claripy.Concat(*(map(simplify_sol, expr.args)))

        # power case
        elif expr.args[0].symbolic and expr.args[1].concrete:

            base = simplify_sol(expr.args[0])
            exponent = pow(2, expr.args[1].size())
            divisor = 1

            # handle inside division, which is introduced by extract
            if hasattr(base, 'op') and base.op == '__floordiv__':
                if base.args[1].concrete:
                    divisor = sol.eval(base.args[1])
                    base = base.args[0]

            multipiler = int(exponent / divisor)
            if multipiler > 1:
                power = multipiler * base
            else:
                power = base

            size_diff = power.size() - expr.args[1].size()
            assert (size_diff >= 0)
            offset = claripy.ZeroExt(size_diff, expr.args[1])

            # FIXME: get rid of this heuristic.
            # it should be directly from the ast
            if check_iv(power):
                ret = (power + offset).annotate(IVAnnotation(0))
            else:
                ret = power + offset

        # div case
        elif expr.args[0].concrete and expr.args[1].symbolic:
            ret = simplify_sol(expr.args[1])

    elif expr.op == 'Extract':
        left = expr.args[0]
        right = expr.args[1]
        val = expr.args[2]
        ret = simplify_sol(val)
        if right > 0:
            ret = ret / pow(2, right)

    elif expr.op == 'ZeroExt':
        # assert (expr.args[0] == 32)
        ret = simplify_sol(expr.args[1])

    elif expr.op == 'fpToIEEEBV':
        ret = simplify_sol(expr.args[0])

    elif expr.op == 'fpToFP':
        # It has three signatures: check fpToFP impl
        if len(expr.args) == 2 and isinstance(expr.args[1], claripy.fp.FSort):
            ret = simplify_sol(expr.args[0])
        elif isinstance(expr.args[0], claripy.fp.RM) and isinstance(
                expr.args[2], claripy.fp.FSort):
            ret = simplify_sol(expr.args[1])
        else:
            from IPython import embed
            embed()
            assert (False)

    elif expr.op == 'FPV':
        ret = expr.args[0]

    elif expr.op == 'fpAdd':
        t1 = simplify_sol(expr.args[1])
        t2 = simplify_sol(expr.args[2])

        if type(t1) == float:
            t1 = int(t1)
        if type(t2) == float:
            t2 = int(t2)

        ret = t1 + t2

    elif expr.op == 'fpMul':
        assert (len(expr.args) == 3)
        first = simplify_sol(expr.args[1])
        second = simplify_sol(expr.args[2])

        if isinstance(first, claripy.ast.bv.BV) and isinstance(second, float):
            fp_name = 'FP_' + str(expr.__hash__())[:6]
            sol.fp_dict[fp_name] = second
            second = sol.BVS(fp_name, bit)

        ret = first * second

    elif expr.op == 'fpLT':
        left = simplify_sol(expr.args[0])
        right = simplify_sol(expr.args[1])
        if isinstance(left, float):
            left = float_to_bvv(left, bit)
        if isinstance(right, float):
            right = float_to_bvv(right, bit)
        ret = operator.lt(left, right)

    elif expr.op == 'fpGT':
        left = simplify_sol(expr.args[0])
        right = simplify_sol(expr.args[1])
        if isinstance(left, float):
            left = float_to_bvv(left, bit)
        if isinstance(right, float):
            right = float_to_bvv(right, bit)
        ret = operator.gt(left, right)

    elif expr.op == 'fpEQ':
        left = simplify_sol(expr.args[0])
        right = simplify_sol(expr.args[1])
        if isinstance(left, float):
            left = float_to_bvv(left, bit)
        if isinstance(right, float):
            right = float_to_bvv(right, bit)
        ret = operator.eq(left, right)

    elif expr.op == 'BVV':
        ret = claripy.ZeroExt(bit - expr.size(), expr)

    elif expr.op == 'If':
        cond = simplify_sol(expr.args[0])
        first = simplify_sol(expr.args[1])
        second = simplify_sol(expr.args[2])

        if isinstance(second, float):
            second = float_to_bvv(second, bit)

        ret = claripy.If(cond, first, second)
        '''
        # it is a Relu or Clip
        assert (expr.args[2].concrete)

        # currently we ignore the condition, but we definitely can prove
        # the condition denotes "the last round"

        # Clip
        if expr.args[1].op == 'If':
            pass
        '''

    else:
        print("[unsupported op]: ", expr.op)
        print(expr)
        print()
        from IPython import embed
        embed()
        assert (False)
        ret = expr

    # copy anno and return
    for anno in expr.annotations:
        if anno not in ret.annotations:
            ret = ret.annotate(anno)
    return ret
