from collections import deque
from archinfo import arch_arm
from .anno import BitsConvertAnnotation, IVAnnotation, isMemRead

import angr
import claripy
import archinfo

import re
import struct
import operator
import functools


def is_arm_arch(arch):
    if isinstance(arch, archinfo.arch_arm.ArchARMEL) or isinstance(
            arch, archinfo.arch_arm.ArchARM) or isinstance(
                arch, archinfo.arch_arm.ArchARMCortexM):
        return True
    return False


def is_x86(arch):
    if isinstance(arch, archinfo.arch_amd64.ArchAMD64):
        return True
    return False


def is_aarch64(arch):
    if isinstance(arch, archinfo.arch_aarch64.ArchAArch64):
        return True
    return False


def check_arch(arch):
    '''
    Our support arch
    '''
    if is_arm_arch(arch):
        return True
    return False


def check_regular_register(arch, reg_name):
    ''' 
    check if reg is one of regular reg
    '''
    if check_arch(arch):
        # rxx
        if re.match(r"^r\d{1,2}$", reg_name):
            return True

        # lr (glow_mobilenet: fc)
        if re.match("lr", reg_name):
            return True

        return False

    elif is_x86(arch):
        # 32-bits general-purpose registers
        gpr_32 = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
        gpr_64 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi']
        additional_reg = ['r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
        if reg_name in gpr_32 + gpr_64 + additional_reg:
            return True

        return False

    elif is_aarch64(arch):
        assert (False)
        pass

    else:
        print("[check_regular_register] arch not supported")
        assert (False)


def flatten_add_expr(expr):
    '''
    Given an addition expr, 
    return all the arguments in one lists
    '''
    if isMemRead(expr):
        return [expr]

    if expr.op == '__add__':
        ret_list = []
        for sub_expr in expr.args:
            ret_list = ret_list + flatten_add_expr(sub_expr)
        return ret_list
    else:
        return [expr]


def get_func_addr_from_addr(proj, addr):
    '''
    return the func addr where the addr is in
    '''
    for f_addr, func in proj.funcs.items():
        if check_in_func(func, addr):
            return f_addr


def check_in_block(block, addr):
    '''
    check if addr is in the block
    '''
    if addr >= block.addr and addr < block.addr + block.size:
        return True
    return False


def get_func_boundary(func):
    '''
    Return the min and max addr of the given func.
    
    Note that addr + size is not the max, because size = sum of block.size, 
    and it is possible that random bytes in the func.
    e.g. glow_mnist_8_ARM_M4 0x101af
    
    Also note the max_addr is not the addr of last inst, but the next one.
    '''
    min_addr = func.addr

    last_blk_addr = max(func.block_addrs_set)
    last_blk = func._local_blocks[last_blk_addr]
    max_addr = last_blk.addr + last_blk.size

    return min_addr, max_addr


def check_in_func(func, addr):
    '''
    check if addr is in func
    '''

    min_addr, max_addr = get_func_boundary(func)

    if addr >= min_addr and addr < max_addr:
        return True
    return False


def get_last_inst_addr_in_blk(func, blk):
    '''
    get blk's last inst addr
    '''
    proj = func.project
    block = None
    if isinstance(blk, angr.codenode.BlockNode):
        assert (blk.addr in proj.block_map)
        block = proj.block_map[blk.addr]
    elif isinstance(blk, angr.block.Block):
        block = blk
    else:
        assert (False)

    return block.instruction_addrs[-1]


def get_last_inst_addr_in_func(func):
    '''
    Get func's last inst addr
    '''
    last_blk_addr = max(func.block_addrs_set)
    last_blk = func._local_blocks[last_blk_addr]
    return get_last_inst_addr_in_blk(func, last_blk)


def solve_addr(state, addr):
    '''
    https://github.com/angr/angr/blob/master/angr/concretization_strategies/__init__.py: _eval
    '''
    addrs = state.solver.eval_upto(addr, 2)
    if len(addrs) == 1:
        return True, hex(addrs[0])
    return False, None


def check_symexpr_variables(symexpr, flag):
    '''
    For region, return *one* matched string.
    For iv, return all matched iv
    '''
    if flag == 'region':
        region = []
        for v in symexpr.variables:
            if "act" in v or "weight" in v or "io" in v:
                region.append(v)

        # should only belong to one or zero region
        assert (len(region) <= 1)

        if len(region) == 1:
            return (True, region[0])
        return (False, None)

    elif flag == 'loop':
        iv = []
        for v in symexpr.variables:
            if "loop" in v:
                iv.append(v)
        if len(iv) > 0:
            return (True, iv)
        return (False, None)

    else:
        raise ValueError("not supported flag")


def get_idx_from_loop_list(loop_list, l):
    '''
    get the idx of loop from loop_list, if loop is in the loop_list. 
    '''
    for idx in range(len(loop_list)):
        if loop_list[idx] == l:
            return idx
    return None


def reg_sym_to_reg_name(arch, sym):
    assert (is_reg(sym))
    offset_str = '_'.join(sym.__str__().split(' ')[1].split('_')[1:2])
    offset = int(offset_str, 16)
    return get_reg_name(arch, offset, 8)


def get_reg_name(arch, offset, size):
    '''
    Given the offset and size of reg read/write, return the name.
    
    ARM: d0 -> (s1, s0); d1 -> (s3, s2) ...
    Size could be zero when it is called in before breakpoint,
    thus we can not decide it is 's' or 'd'. By default we return 's'
    '''
    if is_arm_arch(arch):
        if offset >= 0x80 and offset <= 0x178:
            # d1 - d31
            if offset in range(0x80, 0x178, 8):
                if size == 8:
                    return arch.register_names[offset]
                else:
                    return 's' + str(int(arch.register_names[offset][1:]) * 2)
            # if it is odd 's'
            elif offset in range(0x84, 0x17c, 4):
                assert (offset != 8)
                return 's' + str(
                    int(arch.register_names[offset - 4][1:]) * 2 + 1)
            else:
                print("[get_reg_name]: not a valid offset")
                assert (False)
        else:
            return arch.register_names[offset]

    elif is_x86(arch):
        if offset >= 224 and offset <= 736:
            return "SSE2"
        return arch.register_names[offset]
    
    elif is_aarch64(arch):
        return arch.register_names[offset]
    
    else:
        print("[get_reg_name] arch not supported")
        assert (False)


def retrieve_iv_var(expr):
    '''
    retrieve iv variable in the expr (for eval)
    '''

    if expr is None:
        return []

    iv_var_list = []
    for l_expr in expr.leaf_asts():
        if 'IV' in l_expr.__str__():
            iv_var_list.append(l_expr)
    return iv_var_list


def retrieve_specific_iv_var(expr, iv_name):
    '''
    retrieve the iv_var with the given name
    '''
    for l_expr in expr.leaf_asts():
        if iv_name in l_expr.__str__():
            return l_expr
    return None


def check_iv_in_expr(expr, iv_name):
    '''
    Check if iv of iv_name in expr or not
    '''
    for l_expr in expr.leaf_asts():
        if iv_name in l_expr.__str__():
            return True
    return False


def iv_to_iv_name(iv):
    return '_'.join(iv.__str__().split(' ')[1].split('_')[:2])


def iv_to_iv_version(iv):
    return '_'.join(iv.__str__().split(' ')[1].split('_')[2:3])


def iv_to_iv_addr(iv):
    return '_'.join(iv.__str__().split(' ')[1].split('_')[1:2])


def get_iv_anno(expr):
    '''
    Get IV annos from expr. 
    '''
    iv_anno_list = []
    for anno in expr.annotations:
        if isinstance(anno, IVAnnotation):
            iv_anno_list.append(anno)
    return iv_anno_list


def check_iv_expr(expr):
    '''
    Return True if iv in expr
    '''
    for v in expr.variables:
        if "IV" in v:
            return True
    return False


def check_iv(expr):
    '''
    Return True if expr is iv
    '''
    if expr.op != 'BVS':
        return False

    if "IV" not in list(expr.variables)[0]:
        return False

    return True


def blk_adjacent_pred(blk):
    """
    Check if blk are adjacent with its pred
    (i.e., being split by angr)
    If blk:
        1. it only has one pred
        2. its pred only has one succ, which is blk
    then they are adjacent
    """
    try:
        if len(blk.predecessors()) != 1:
            return False
        pred = blk.predecessors()[0]
        if len(pred.successors()) != 1:
            return False
        assert (pred.successors()[0] == blk)
        return True
    except:
        return False


def get_iv_expr(expr):
    '''
    Given an expr, return all sub-expr annotated with IV    
    '''
    ret_set = set()
    for e in expr.children_asts():
        if any([isinstance(anno, IVAnnotation) for anno in e.annotations]):
            ret_set.add(e)
    return ret_set


def get_outer_iv_expr(expr):
    '''
    Given an expr, return all outer expr annotated with IV    
    '''
    ret_set = set()

    ast_queue = deque([iter(expr.args)])
    while ast_queue:
        try:
            ast = next(ast_queue[-1])
        except StopIteration:
            ast_queue.pop()
            continue

        if isinstance(ast, claripy.ast.Base):
            if any(
                [isinstance(anno, IVAnnotation) for anno in ast.annotations]):
                ret_set.add(ast)
            else:
                ast_queue.append(iter(ast.args))

    return ret_set


def get_num_leaf_asts(expr):
    '''
    Given an expr, return the number of its leaf asts
    '''
    counter = 0
    for l in expr.leaf_asts():
        counter += 1
    return counter


def get_num_children_asts(expr):
    '''
    Given an expr, return the number of its leaf asts
    '''
    counter = 0
    for l in expr.children_asts():
        counter += 1
    return counter


def retrieve_from_addition_expr(expr):
    '''
    Given an addition expr (symbolic + concrete), return the concrete and the symbolic
    '''
    assert (expr.op == '__add__' or expr.op == '__sub__')
    assert (len(expr.args) >= 2)

    e0 = expr.args[0]
    e1 = expr.args[1]

    if e0.concrete and e1.symbolic and len(expr.args) == 2:
        if expr.op == '__add__':
            return e0, e1
        elif expr.op == '__sub__':
            return -e0, e1
    elif e0.symbolic and e1.concrete and len(expr.args) == 2:
        if expr.op == '__add__':
            return e1, e0
        if expr.op == '__sub__':
            return -e1, e0
    else:
        assert (expr.op == '__add__')
        expr_args = flatten_add_expr(expr)
        con = None
        sym = None
        for arg in expr_args:
            if arg.concrete:
                if con is None:
                    con = arg
                else:
                    con = con + arg
            elif arg.symbolic:
                if sym is None:
                    sym = arg
                else:
                    sym = sym + arg
        return con, sym


def reset_mem_dict(proj):
    del proj.mem_write_dict
    del proj.mem_read_dict
    del proj.mem_write_lift_dict

    proj.mem_write_dict = {}
    proj.mem_read_dict = {}
    proj.mem_write_lift_dict = {}


def reset_mem_lift_dict(proj):
    del proj.mem_write_lift_dict
    proj.mem_write_lift_dict = {}


def expr_list_diff(ls, solver):
    '''
    Return the difference of a list
    Default is using solver, if fails, use pattern matching
    '''
    try:
        ls_diff = [
            solver.eval(ls[idx] - ls[idx - 1]) for idx in range(1, len(ls))
        ]
    except:
        pass
    return ls_diff


def is_reg(expr):
    assert (expr.op in claripy.operations.leaf_operations)
    return 'reg' in expr.__str__()


def is_IV(expr):
    assert (expr.op in claripy.operations.leaf_operations)
    if expr.op == 'BVS':
        return 'IV' in expr.__str__()
    return False


def iv_structurally_match(expr_1, expr_2):
    '''
    Adapted from "base.py: structurally_match"
    Difference:
        1. dont compare registers
        2. IV version could be different (X)
    (e.g. <BV32 reg_8_71_32{UNINITIALIZED} + IV_0x10017_1_32 * 0x4> matches to 
    <BV32 reg_14_34_32{UNINITIALIZED} + IV_0x10017_141_32>)
    '''

    if expr_1.op != expr_2.op:
        return False

    if len(expr_1.args) != len(expr_2.args):
        return

    for arg_a, arg_b in zip(expr_1.args, expr_2.args):
        # I dont know what's doing here
        if not isinstance(arg_a, claripy.ast.Base):
            if type(arg_a) != type(arg_b):
                return False
            if arg_a != arg_b:
                return False
            else:
                continue

        if arg_a.op in claripy.operations.leaf_operations:
            # we dont compare reg
            if is_reg(arg_a) and is_reg(arg_b):
                continue
            '''
            # for IV sym, we only consider IV addr
            if is_IV(arg_a) and is_IV(arg_b):
                if iv_to_iv_addr(arg_a) == iv_to_iv_addr(arg_b):
                    continue
                else:
                    return False
            '''

            if arg_a is not arg_b:
                return False

        else:
            if not iv_structurally_match(arg_a, arg_b):
                return False

    return True


def find_reroll_loop_candidate(outer_loop):
    '''
    find the loops that
        1. at the same hierarchy 
        2. have the same loop count
        3. len(loops) == increment
    '''

    loop = outer_loop[0]

    while True:
        print(loop)
        print(loop.subloops)
        print()

        if not loop.subloops:
            break

        if len(loop.subloops) == 1:
            loop = loop.subloops[0]
            continue

        if len(loop.subloops) > 1:
            from IPython import embed
            embed()


def hex_to_float(hex_str):
    assert (hex_str[:2] == '0x')
    return struct.unpack('<f', bytes.fromhex(hex_str[2:].zfill(8)))[0]


def check_ITE_in_expr(expr):
    '''
    Return True if ITE in expr, otherwise return False
    '''
    for e in expr.children_asts():
        if e.op == 'If':
            return True

    return False


def dissect_ite():
    '''
    Given an ITE expr, return all leaf asts (without ITE) with 
    their corresponding conditions
    '''
    pass


def find_iv_from_all_ivs(iv_var, all_ivs):
    iv_name = iv_to_iv_name(iv_var)
    for _iv in all_ivs.values():
        if iv_name == _iv.name:
            return _iv
    return None


def find_jump_addr(proj, dis):
    '''
    Given a disassembly of a (jump) instruction, 
    return the jump addr
    '''

    assert (check_arch(proj.arch))
    assert (dis.insn.mnemonic == 'bl')

    return int(dis.insn.op_str[1:], 16)


def replace_and_eval(iv_val_list, expr, solver):
    '''
    iv_val_list: [(sym, val)]
    '''

    eval_expr = expr
    for iv_val in iv_val_list:
        eval_expr = eval_expr.replace(iv_val[0], solver.BVV(iv_val[1], 32))

    return solver.eval_one(eval_expr)


def make_eliminatable(expr):
    for sub_ast in expr.children_asts():
        for anno in sub_ast.annotations:
            anno._eliminatable = True
            anno._relocatable = True
    return expr


def simplify_and_sort(expr_list, solver):
    new_expr_list = [make_eliminatable(expr) for expr in expr_list]
    simplify_expr_list = [solver.simplify(expr) for expr in new_expr_list]
    simplify_expr_list.sort(key=get_num_leaf_asts)

    return simplify_expr_list


def replace_64_to_32(state, symvar):
    '''
    It is more complicated than I thought, since we can not use replace to change size. 
    So we adopt the alternative that truncate symvar into 
    '''

    assert (symvar.size() == 64)
    new_symvar = claripy.ops.Extract(31, 0, symvar)
    assert (new_symvar.size() == 32)
    return new_symvar.annotate(BitsConvertAnnotation(state.addr))

    # create replace list
    replace_list = []
    for leaf in symvar.leaf_asts():
        assert (leaf.size() == 64)
        if leaf.symbolic:
            assert ("reg" in leaf.__str__())
            name = '_'.join(leaf.__str__().split(' ')[1].split('_')[:2])
            new_leaf = claripy.BVS(name, 32)
        else:
            assert (leaf.op == 'BVV')
            concrete_val = state.solver.eval(leaf)
            new_leaf = claripy.BVV(concrete_val, 32)
        replace_list.append((leaf, new_leaf))

    from IPython import embed
    embed()
    
    # replace 
    new_symvar = symvar
    for pair in replace_list:
        new_symvar = new_symvar.replace(pair[0], pair[1])

    return new_symvar