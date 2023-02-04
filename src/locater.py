from collections import defaultdict

from .utils import get_loop_depth, has_math_func, get_func_addr_from_addr, get_pred, get_succ

def locate(proj):
    '''
    Locate the inference function and all the operator functions
    '''
    loop_finder = proj.cfg.project.analyses.LoopFinder(kb=proj.cfg.kb)
    
    # look for candidate op_func
    cand_op_func = []
    for f_addr in proj.cfg.kb.functions:
        # nested loops
        loop_flag = False
        if f_addr in loop_finder.loops_hierarchy:
            loop = loop_finder.loops_hierarchy[f_addr]
            if get_loop_depth(loop) > 2:
                loop_flag = True
                
        # math func
        math_flag = has_math_func(proj, f_addr)
        
        if loop_flag or math_flag:
            cand_op_func.append(f_addr)
                
    # vote for "inference function"
    vote_dict = defaultdict(int)
    for f_addr in cand_op_func:
        preds = [get_func_addr_from_addr(proj, p) for p in get_pred(proj, f_addr)]
        for p in preds:
            vote_dict[p] += 1
        
    # decide inference function
    max_count = max(vote_dict.values())
    infer_f_addr = [k for k, v in vote_dict.items() if v == max_count]
    assert(len(infer_f_addr) == 1)
    infer_f_addr = infer_f_addr[0]
    
    # retrieve all the op_func
    op_func_addr = get_succ(proj, infer_f_addr)
    
    return infer_f_addr, op_func_addr