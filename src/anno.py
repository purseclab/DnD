from builtins import min, property
from claripy import Annotation


class MemReadAnnotation(Annotation):
    def __init__(self, addr):
        super(MemReadAnnotation, self).__init__()

        self.addr = addr

        self._eliminatable = False
        self._relocatable = False

    @property
    def eliminatable(self):
        return self._eliminatable

    @property
    def relocatable(self):
        return self._relocatable

    def __hash__(self):
        return hash(('mem_read', self.addr))

    def __eq__(self, other):
        if not isinstance(other, MemReadAnnotation):
            return False

        return self.addr == other.addr

    def __repr__(self):
        return "MemReadAnnotation @ %s" % hex(self.addr)


def isMemRead(expr):
    for anno in expr.annotations:
        if isinstance(anno, MemReadAnnotation):
            return True
    return False


class IVAnnotation(Annotation):
    def __init__(self, addr, reg=None):
        super(IVAnnotation, self).__init__()

        self.addr = addr
        self.reg = reg

        self._eliminatable = False
        self._relocatable = False

    @property
    def eliminatable(self):
        return self._eliminatable

    @property
    def relocatable(self):
        return self._relocatable

    def __hash__(self):
        return hash(('iv', self.addr))

    def __eq__(self, other):
        if not isinstance(other, IVAnnotation):
            return False

        return self.addr == other.addr

    def __repr__(self):
        return "IVAnnotation @ %s" % hex(self.addr)


def isIV(expr):
    for anno in expr.annotations:
        if isinstance(anno, IVAnnotation):
            return True
    return False


class ClipAnnotation(Annotation):
    def __init__(self, min_, max_):
        super(ClipAnnotation, self).__init__()

        self.min = min_
        self.max = max_

    @property
    def eliminatable(self):
        return False

    @property
    def relocatable(self):
        return False

    def __repr__(self):
        return "ClipAnnotation: min: %s, max: %s" % (self.min, self.max)


class IncrementAnnotation(Annotation):
    def __init__(self, addr, reg=None):
        super(IncrementAnnotation, self).__init__()

        self.addr = addr
        self.reg = reg

    @property
    def eliminatable(self):
        return False

    @property
    def relocatable(self):
        return False

    def __hash__(self):
        return hash(('increment', self.addr))

    def __repr__(self):
        return "IncrementAnnotation @ %s" % hex(self.addr)


class BitsConvertAnnotation(Annotation):
    def __init__(self, addr, reg=None):
        super(BitsConvertAnnotation, self).__init__()

        self.addr = addr
        self.reg = reg

    @property
    def eliminatable(self):
        return False

    @property
    def relocatable(self):
        return False

    def __hash__(self):
        return hash(('bits', self.addr))

    def __repr__(self):
        return "BitsConvertAnnotation @ %s" % hex(self.addr)
