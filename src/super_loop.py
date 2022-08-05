from .dbg import print_loop
from .utils import check_in_func, get_last_inst_addr_in_blk, blk_adjacent_pred
from .constant import unknown_ret_addr
from .iv import IV
from .branch_type import Branch

from angr.analyses.loopfinder import Loop


class SuperLoop(Loop):
    '''
    A loop wrapper
    '''
    def __init__(self, loop, func):
        super().__init__(loop.entry, loop.entry_edges, loop.break_edges,
                         loop.continue_edges, loop.body_nodes, loop.graph,
                         loop.subloops)

        self._func = func
        self._ret_break_blk = None
        self._iv = None
        self._iv_dict = None

        self._check_entry_edge()
        self._check_break_edge()
        self._check_continue_edge()

    def __eq__(self, other):
        '''
        We assume that loops have different entry.
        '''
        if self.entry == other.entry:
            return True
        return False

    def _check_entry_edge(self):
        '''
        We assume exactly one entry edge.
        There could be multiple entry blks because of 
        angr's spliting on large basic block. 
        For each loop's entry block, if:
        then, they are "adjacent"
        '''
        assert (len(self.entry_edges) == 1)

        # collect adj blk
        self._adj_entry_blk = []
        src_blk = self.entry_edges[0][0]
        while blk_adjacent_pred(src_blk):
            pred = src_blk.predecessors()[0]
            self._adj_entry_blk.append(pred)
            src_blk = pred

    def _check_break_edge(self):
        '''
        If no break edge, check if loop's break edge is return 
        and assign _ret_break_blk. 
        If more than one break edge, decide the break dest blk.
        We also decide _fake_break_edge_dest_blk_addr, which is jumping 
        to the real one.
        '''

        # init
        self._break_edge_dest_blk_addr = None
        self._fake_break_edge_dest_blk_addr = []

        if len(self.break_edges) == 1:
            self._break_edge_dest_blk_addr = self.break_edges[0][1].addr

        if len(self.break_edges) >= 2:
            break_edge_dest_blk_set = set([e[1] for e in self.break_edges])

            # fake -- the ones will jump to the real
            real_break_edge_dest_blk_set = set()
            fake_break_edge_dest_blk_set = set()

            for blk in break_edge_dest_blk_set:
                if len(blk.successors()) != 1:
                    continue
                if blk.successors()[0].addr in [
                        blk.addr for blk in break_edge_dest_blk_set
                ]:
                    fake_break_edge_dest_blk_set.add(blk)
            real_break_edge_dest_blk_set = break_edge_dest_blk_set.difference(
                fake_break_edge_dest_blk_set)
            assert (len(real_break_edge_dest_blk_set) == 1)

            self._break_edge_dest_blk_addr = list(
                real_break_edge_dest_blk_set)[0].addr
            self._fake_break_edge_dest_blk_addr = [
                blk.addr for blk in fake_break_edge_dest_blk_set
            ]

        if len(self.break_edges) == 0:
            break_blk_list = []
            for ret_blk in self._func.ret_sites:
                for body_blk in self.body_nodes:
                    if body_blk.addr == ret_blk.addr:
                        break_blk_list.append(body_blk)
                        break

            self._ret_break_blk = break_blk_list[0]

            # only one break edge
            assert (len(break_blk_list) == 1)

    def _check_continue_edge(self):
        '''
        We assume exctly one cont edge
        '''
        assert (len(self.continue_edges) == 1)

    def set_iv(self, iv):
        assert (isinstance(iv, IV))
        self._iv = iv

    def set_iv_dict(self, iv_dict):
        self._iv_dict = iv_dict

    def set_aux_iv_dict(self, aux_iv_dict):
        self._aux_iv_dict = aux_iv_dict

    @property
    def entry_edge_src_blk(self):
        '''
        Return a list of entry blocks (with adj blk)
        '''
        ret_list = [self.entry_edges[0][0]]
        ret_list.extend(self._adj_entry_blk)
        return ret_list

    @property
    def entry_edge_src_blk_addr(self):
        '''
        Return the addr of the "first" entry block,
        which is at the end of the list
        '''
        return self.entry_edge_src_blk[-1].addr

    @property
    def continue_edge_src_blk(self):
        return self.continue_edges[0][0]

    @property
    def continue_edge_src_blk_addr(self):
        return self.continue_edges[0][0].addr

    @property
    def continue_edge_dest_blk_addr(self):
        return self.continue_edges[0][1].addr

    @property
    def _break_edge_src_blk(self):
        '''
        Return a list of break edge src blk
        '''
        if self._ret_break_blk:
            return [self._ret_break_blk]

        return [e[0] for e in self.break_edges]

    @property
    def break_edge_dest_blk_addr(self):
        if self._ret_break_blk:
            return unknown_ret_addr
        return self._break_edge_dest_blk_addr

    @property
    def branch_addr(self):
        '''
        Return a list of branch addr
        '''
        if self._ret_break_blk:
            addr = get_last_inst_addr_in_blk(self._func, self._ret_break_blk)
            return [addr]
        else:
            branch_blk_set = set()
            for blk in self._break_edge_src_blk:
                branch_blk_set.add(blk)
            # assume only one continue edge
            assert (len(self.continue_edges) == 1)
            branch_blk_set.add(self.continue_edge_src_blk)

            return [
                get_last_inst_addr_in_blk(self._func, blk)
                for blk in branch_blk_set
            ]

    @property
    def branch_continue_dest_addr(self):
        '''
        Return the continue addr after branch
        '''
        if self._ret_break_blk:
            return self.continue_edge_src_blk_addr
        return self.continue_edge_dest_blk_addr
    
    @property
    def branch_continue_src_addr(self):
        '''
        Return the continue addr before branch
        '''
        return get_last_inst_addr_in_blk(self._func, self.continue_edge_src_blk)

    def match_branch(self, addr_pair):
        '''
        When simgr spawns, we decide what type the spawn it is.
        '''
        assert (len(addr_pair) == 2)
        if self._ret_break_blk:
            if addr_pair[
                    0] == self.continue_edge_src_blk_addr and not check_in_func(
                        self._func, addr_pair[1]):
                return Branch.BREAK_CONT
            if addr_pair[
                    1] == self.continue_edge_src_blk_addr and not check_in_func(
                        self._func, addr_pair[0]):
                return Branch.BREAK_CONT
            return Branch.NON_LOOP
        else:
            if self.break_edge_dest_blk_addr in addr_pair:
                # normal break_cont case
                if self.continue_edge_dest_blk_addr in addr_pair:
                    return Branch.BREAK_CONT
                # break case
                else:
                    return Branch.BREAK
            # fake break edge case
            if self.continue_edge_dest_blk_addr in addr_pair:
                if any(addr in self._fake_break_edge_dest_blk_addr
                       for addr in addr_pair):
                    return Branch.BREAK_CONT
            return Branch.NON_LOOP

    def check_break_edge_dest(self, addr):
        '''
        Check if a given addr is break edge addr or not. 
        If the loop is a return-as-break, we check if it is outside of func.
        Else, we check if the addr 
            1. is _break_edge_dest_blk_addr
            2. is jumping to _break_edge_dest_blk_addr
        '''
        if self._ret_break_blk:
            if not check_in_func(self._func, addr):
                return True
            return False
        else:
            if addr == self._break_edge_dest_blk_addr:
                return True
            if addr in self._fake_break_edge_dest_blk_addr:
                return True
            return False

    def get_fake_edge_dest_blk_addr(self, addr_pair):
        '''
        DEPRECATED
        From addr_pair, we find one _fake_break_edge_blk_addr
        '''
        assert (False)
        assert (len(addr_pair) == 2)
        addr = [
            addr for addr in addr_pair
            if addr in self._fake_break_edge_dest_blk_addr
        ]
        assert (len(addr) == 1)
        return addr[0]
