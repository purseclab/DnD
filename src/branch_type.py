from enum import Enum, auto


class Branch(Enum):
    NON_LOOP = auto()
    BREAK = auto()
    CONT = auto()
    BREAK_CONT = auto()
