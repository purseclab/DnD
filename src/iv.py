class IV():
    '''
    A data structure to represent IV
    '''
    def __init__(self,
                 addr=None,
                 reg=None,
                 name=None,
                 loop=None,
                 increment=None,
                 exit_condition=None,
                 loop_count=None,
                 init_sym=False,
                 init_val=None,
                 from_arg=False,
                 is_aux=False):
        self.addr = addr
        self.reg = reg
        self.name = name
        # superLoop
        self.loop = loop
        # by default it is None. 0 denotes that it is a "trivial" loop (twice)
        self.increment = increment
        # the addr where IV indexed mem read happens
        # i.e., addr is symbolic or expr is symbolic
        self.indexed_mem_write = []
        # the addr where loop branch depends on this iv
        self.branch_depend_addr = []
        # condition on which the break is taken
        self.exit_condition = exit_condition
        # upper bound (included) of how many time the loop is iterated
        self.loop_count = loop_count
        # if init value depends on symbol
        self.init_sym = init_sym
        # init value
        self.init_val = init_val
        # is it from arg
        self.from_arg = from_arg
        # is it aux iv
        self.is_aux = is_aux

        # keep iv_var WHEN extracting ast
        self.iv_var = None

        # reroll flag
        self.reroll_flag = False
        self.reroll_increment = None
        self.reroll_count = None

    def set_iv_var(self, iv_var):
        self.iv_var = iv_var

    @property
    def total_count(self):
        '''
        Return loop_count * increment
        '''
        if self.increment is None:
            assert (False)
        elif self.increment == 0:
            # TODO: check it
            assert (False)
            return 2
        else:
            return self.increment * self.loop_count

    def __repr__(self):
        try:
            ret_str = "\n<IV @ %s>\n name: %s\n is_aux: %s\n reg: %s\n from_arg: %s\n loop_entry: %s\n loop_entry_edge: %s\n init_sym: %s\n init_val: %s\n increment: %s\n count: %s\n index_mem_write: %s\n" % (
                hex(self.addr), self.name, self.is_aux, self.reg,
                self.from_arg, hex(
                    self.loop.entry.addr), self.loop.entry_edges[0],
                self.init_sym, self.init_val, self.increment, self.loop_count,
                [hex(addr) for addr in self.indexed_mem_write])
        except:
            ret_str = "\n<IV @ %s>\n" % self.name
        return ret_str

    def get_constraints(self):
        upper_bound = None
        lower_bound = None
        type = None
        if self.increment == 0:
            type = 'set'
        elif self.increment > 0:
            lower_bound = self.init_val
            upper_bound = self.init_val + self.increment * self.loop_count
            type = 'increase'
        elif self.increment < 0:
            upper_bound = self.init_val
            lower_bound = self.init_val + self.increment * self.loop_count
            type = 'decrease'

        return (lower_bound, upper_bound, type)
