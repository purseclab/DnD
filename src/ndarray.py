class NdArray():
    '''
    An NdArray that can hold any element
    '''
    def __init__(self, shape, axis):
        self.shape = shape
        self.axis = axis

        self._backer = self._create_empty_list_of_shape(shape)

    def _create_empty_list_of_shape(self, shape):
        '''
        A recursive function to create nd list
        '''

        if shape:
            return [
                self._create_empty_list_of_shape(shape[1:])
                for i in range(shape[0])
            ]

    def read(self, idx_list):
        a = self._backer
        for idx in idx_list:
            a = a[idx]
        return a
        # return functools.reduce(operator.getitem, idx, array)

    def write(self, idx_list, val):
        a = self._backer
        for idx_idx in range(len(idx_list)):
            if idx_idx == len(idx_list) - 1:
                a[idx_list[idx_idx]] = val
                return
            else:
                a = a[idx_list[idx_idx]]
