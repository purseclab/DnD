from .super_loop import SuperLoop


class IVDict():
    '''
    A dict to store multiple IVs
    {addr: IV}
    '''
    def __init__(self, IVs=None):
        self._backer = IVs if IVs is not None else {}

    def __getitem__(self, k):
        return self._backer[k]

    def __setitem__(self, k, v):
        assert (isinstance(v.loop, SuperLoop))
        self._backer[k] = v

    def __delitem__(self, k):
        del self._backer[k]

    def __contains__(self, k):
        return k in self._backer

    def __repr__(self) -> str:
        return self._backer.__repr__()

    def __len__(self):
        return len(self._backer)

    def __iter__(self):
        return iter(self._backer)

    def keys(self):
        return self._backer.keys()

    def values(self):
        return self._backer.values()

    def items(self):
        return self._backer.items()

    def get(self, k, alt=None):
        return self._backer.get(k, alt)

    def pop(self, k, alt=None):
        return self._backer.pop(k, alt)

    @property
    def _name(self):
        '''
        return a set of name
        '''
        name_set = set()
        for iv in self.values():
            name_set.add(iv.name)
        return name_set

    def lookup_name(self, name):
        '''
        if sym name (the full one) exists, return addr (the key).
        '''
        for iv in self.values():
            if iv.name in name:
                return iv.addr

    def lookup_branch(self, addr):
        '''
        given an addr, check if it is the branch inst of one of iv 
        '''
        iv_addr_list = []
        for iv in self.values():
            if addr in iv.loop.branch_addr:
                iv_addr_list.append(iv.addr)

        return iv_addr_list

    def lookup_loop(self, loop):
        '''
        given a loop, check if it is one of the iv's loop
        '''
        for iv in self.values():
            if iv.loop == loop:
                return iv
        return None

    def lookup_break_addr(self, addr):
        '''
        given a addr, decide if it is one of the exit_addr 
        (first addr of break edge dest)
        '''
        for iv in self.values():
            if iv.loop.check_break_edge_dest(addr):
                return True
        return False

    def get_ivs(self, loop_addr):
        '''
        Given loop entry addr, return all ivs associated with that loop
        '''
        return [iv for iv in self.values() if iv.loop.entry.addr == loop_addr]

    def merge(self, other):
        '''
        Merge two iv_dict
        '''
        assert (isinstance(other, IVDict))
        for addr, iv in other.items():
            assert (addr not in self._backer)
            self._backer[addr] = iv
