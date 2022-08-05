def _estimate_iv(proj, iv_dict, iv_filtered):
    '''
    A wrapper to estimate iv loop count value.
    '''
    for iv in iv_dict.values():
        assert (len(iv.exit_condition.variables) >= 1)

        # trivial case
        if iv.increment == 0:
            # TODO: do some checkings
            iv.loop_count = 2
            continue

        # init-as-sym and init-from-arg are resolved
        if iv.init_sym or iv.from_arg:
            continue

        _symbolic_estimate_iv(proj, iv, iv_filtered)

        # deprecated
        # _pattern_matching_estimate_iv(proj, iv)


def _symbolic_estimate_iv(proj, iv, iv_filtered):
    '''
    Solve the iv.exit_condition directly
    '''

    # retrieve iv var
    iv_var = None
    for l in iv.exit_condition.leaf_asts():
        if iv.name in l.__str__():
            iv_var = l
    assert (iv_var is not None)
    assert (iv_var.op == 'BVS')

    # retrieve other var, if there are any
    other_var = []
    for l in iv.exit_condition.leaf_asts():
        if l.op == 'BVS' and l.__str__() != iv_var.__str__():
            other_var.append(l)

    # fresh solver
    # dont do sol = proj.factory.entry_state().solver, it is buggy
    state = proj.factory.entry_state()
    state.solver.add(iv.exit_condition)

    # assign other var to their init val
    # FIXME: name
    for var in other_var:
        iv_addr = iv_filtered.lookup_name(list(var.variables)[0])
        assert (iv_addr)
        state.solver.add(var == iv_filtered[iv_addr].init_val)

    # create loop_count var
    loop_idx = state.solver.BVS("loop_idx", proj.bit)
    state.solver.add(iv_var == iv.init_val + loop_idx * iv.increment)

    # increase case
    if iv.increment > 0:
        iv.loop_count = state.solver.min(loop_idx) + 1
    # decrease case
    elif iv.increment < 0:
        iv.loop_count = state.solver.max(loop_idx) + 1


def _pattern_matching_estimate_iv(proj, iv):
    '''
    We are looking for '<=' '>=' pattern and only solve for pattern ast.
    It is not necessary if _symbolic_estimate_iv() works fine

    TODO: it does not calculate loop_count
    '''

    comparator_op = ['SGE', 'SLE', 'SGT', 'SLT', 'UGE', 'ULE', 'UGT', 'ULT']

    assert (iv.increment is not None)
    assert (iv.exit_condition is not None)

    # find the pattern
    pattern_ast = None
    for ast in iv.exit_condition.children_asts():
        if ast.op not in comparator_op:
            continue

        if ast.args[0].op == 'BVV' and ast.args[1].op == 'BVS':
            constant_idx = 0
            symbolic_idx = 1
        elif ast.args[0].op == 'BVS' and ast.args[1].op == 'BVV':
            constant_idx = 1
            symbolic_idx = 0
        else:
            continue

        assert (len(ast.args[symbolic_idx].variables) == 1)

        # match to iv
        if not iv.name in list(ast.args[symbolic_idx].variables)[0]:
            continue

        # this is the ast we are looking for
        pattern_ast = ast
        break

    assert (pattern_ast is not None)

    # retrieve iv var
    sym_var = None
    for l in iv.exit_condition.leaf_asts():
        if iv.name in l.__str__():
            sym_var = l
    assert (sym_var is not None)
    assert (sym_var.op == 'BVS')

    state = proj.factory.entry_state()
    state.solver.add(pattern_ast)

    # increase case
    if iv.increment > 0:
        iv.loop_count = state.solver.min(sym_var)
    # decrease case
    elif iv.increment < 0:
        iv.loop_count = state.solver.max(sym_var)
