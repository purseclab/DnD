from copy import deepcopy

from angr.state_plugins.plugin import SimStatePlugin


class SimStateLocals(SimStatePlugin):
    def __init__(self, backer=None):
        super(SimStateLocals, self).__init__()
        self._backer = backer if backer is not None else {}

    def set_state(self, state):
        pass

    def merge(self, others, merge_conditions, common_ancestor=None):

        for other in others:
            for k in other.keys():
                if k not in self:
                    self[k] = other[k]

        return True

    def widen(self, others):
        return False

    def __getitem__(self, k):
        return self._backer[k]

    def __setitem__(self, k, v):
        self._backer[k] = v

    def __delitem__(self, k):
        del self._backer[k]

    def __contains__(self, k):
        return k in self._backer

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

    @SimStatePlugin.memo
    def copy(self, memo):
        return SimStateLocals(deepcopy(dict(self._backer)))
