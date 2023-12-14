class MemRecord:
    """
    A data structure to represent memory read/write
    """

    def __init__(
        self,
        addr=None,
        expr=None,
        cond=[],
        completed_loop_entry=None,
        ongoing_loop_entry=None,
        outer_loop=None,
        op_addr=None,
    ):
        self.addr = addr
        self.expr = expr
        self.cond = cond
        self.completed_loop_entry = (
            completed_loop_entry  # the loops that have finished when mem write happen
        )
        self.ongoing_loop_entry = (
            ongoing_loop_entry  # the loops that are ongoing when mem write happen
        )
        self.outer_loop = outer_loop

        # the addr when the mem is read/written
        self.op_addr = op_addr

    def __repr__(self):
        return "[addr]: %s\n [expr]: %s\n\n" % (self.addr, self.expr)

    def copy(self):
        """
        For lifting usage
        """
        return MemRecord(
            None,
            None,
            self.cond,
            self.completed_loop_entry,
            self.ongoing_loop_entry,
            self.outer_loop,
            self.op_addr,
        )
