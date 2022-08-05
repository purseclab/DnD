from .utils import is_arm_arch


class RegisterView():
    '''
    An architecture-agonistic register view (checkpoint) of a state. 
    Implemented following SimRegNameView.
    
    Arm:
        r0 - r9, lr
    
    '''
    def __init__(self, state) -> None:
        self._arch = state.project.arch
        self._backend = []

        if is_arm_arch(self._arch):
            for idx in range(10):
                val = getattr(state.regs, 'r' + str(idx)).ast
                self._backend.append(val)

            self._backend.append(state.regs.lr.ast)

        else:
            assert (False)

    def __getattr__(self, k):
        if is_arm_arch(self._arch):
            if k[0] == 'r' and k[1].isdigit():
                assert (len(k) == 2)
                return self._backend[int(k[1])]
            elif k == 'lr':
                return self._backend[11]
            else:
                assert (False)
        else:
            assert (False)

    def __getitem__(self, k):
        return self.__getattr__(k)
