from .utils import get_reg_name, solve_addr

import claripy


def expr_debug(state):
    print("[expr@", hex(state.addr), "]: expr: ", state.inspect.expr,
          " expr_result", state.inspect.expr_result)

    print()


def sym_var_debug(state):
    print("[sym_var_bp@", hex(state.addr), "]: sym_var_name: ",
          state.inspect.symbolic_name, " sym_var_size",
          state.inspect.symbolic_size, " sym_var_expr",
          state.inspect.symbolic_expr)

    print()


def print_regs(state):
    '''
    print out important registers
    '''
    print("regular registers: ")
    print("[r0]: ", state.regs.r0)
    print("[r1]: ", state.regs.r1)
    print("[r2]: ", state.regs.r2)
    print("[r3]: ", state.regs.r3)
    print("[r4]: ", state.regs.r4)
    print("[r5]: ", state.regs.r5)
    print("[r6]: ", state.regs.r6)
    print("[r7]: ", state.regs.r7)
    print("[r8]: ", state.regs.r8)

    # return

    # extended register.
    # d: double, s: single
    print()
    print("extended registers: ")
    print("[d0]: ", state.regs.d0)
    print("[d1]: ", state.regs.d1)
    print("[d2]: ", state.regs.d2)
    print("[d3]: ", state.regs.d3)


def state_debug_pre(state):
    print('------', hex(state.addr), '------')
    for stmt in state.project.vex_stmt_map[state.addr]:
        stmt.pp()
    print()
    print_regs(state)
    print()


def state_debug_post(state):
    '''
    print info that only available AFTER stepping
    '''
    print("After stepping")
    print("constraints:", state.solver.constraints)
    print_regs(state)
    print()


def mem_write_debug(state):
    print("[mem_write @", hex(state.addr), "]: write_addr: ",
          state.inspect.mem_write_address, " write_expr: ",
          state.inspect.mem_write_expr, " write_cond: ",
          state.inspect.mem_write_condition)

    print()


def mem_read_debug(state):
    print("[mem_read @", hex(state.addr), "]: read_addr_sym: ",
          state.inspect.mem_read_address, " solve read_addr_sym",
          solve_addr(state, state.inspect.mem_read_address), " read_expr: ",
          state.inspect.mem_read_expr, " read_cond: ",
          state.inspect.mem_read_condition)

    print_regs(state)
    print()


def constraints_debug(state):
    print("[constraints added @ ", hex(state.addr), "]")
    for constraint in state.inspect.added_constraints:
        print(constraint)
    print()


def address_concretization_debug(state):
    if state.inspect.address_concretization_result is None:
        return

    print("[addr concretized @ ", hex(state.addr), "]", " strategy: ",
          state.inspect.address_concretization_strategy, " expr: ",
          state.inspect.address_concretization_expr, " result: ",
          state.inspect.address_concretization_result)
    print()


def reg_write_debug(state):

    reg_offset = state.inspect.reg_write_offset
    # print(reg_offset)
    if isinstance(reg_offset, claripy.ast.bv.BV):
        assert (reg_offset.concrete)
        reg_offset = state.solver.eval(reg_offset)
    reg_size = state.inspect.reg_write_length

    print("[reg_write @", hex(state.addr), "]: reg_to_write: ",
          get_reg_name(state.project.arch, reg_offset,
                       reg_size), " reg_write_expr: ",
          state.inspect.reg_write_expr, " reg_write_expr obj: ",
          hex(id(state.inspect.reg_write_expr)))

    print()


def exit_debug(state):
    print("[exit @", hex(state.addr), "]: exit_target: ",
          state.inspect.exit_target, " exit_guard: ", state.inspect.exit_guard,
          " exit_jumpkind: ", state.inspect.exit_jumpkind)


def print_expr(expr):
    print(expr.op)
    print(len(expr.args))

    for arg in expr.args:
        print(arg)


def print_anno(expr):
    if expr.annotations:
        print(expr)
        for anno in expr.annotations:
            print(anno)
        print()

    for sub_expr in expr.children_asts():
        if sub_expr.annotations:
            print(sub_expr)
            for anno in sub_expr.annotations:
                print(anno)
            print()


def print_loop(loop):
    print("entry edge: ", loop.entry_edges)
    print("break edge: ", loop.break_edges)
    print("continue edge: ", loop.continue_edges)
    print()


class StatefulDebug():
    def __init__(self, start_addr):
        self.start_addr = start_addr

    def debug(self, state):
        if state.addr >= self.start_addr:
            from IPython import embed
            embed()
