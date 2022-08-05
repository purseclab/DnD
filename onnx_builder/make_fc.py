import onnx
from onnx import helper
from onnx import AttributeProto, TensorProto, GraphProto
import numpy as np

from enum import Enum, auto


class FC_TYPE(Enum):
    MUL_ADD = auto()
    GEMM = auto()


def make_fc(num_input, num_output, option=FC_TYPE.MUL_ADD):
    '''
    make onnx for fc op
    '''
    if option == FC_TYPE.MUL_ADD:
        # make_graph init takes 1d array
        W = np.random.randn(num_input, num_output).astype(np.float32).flatten()
        B = np.random.rand(1, num_output).astype(np.float32).flatten()

        fc_graph_def = helper.make_graph(
            # node
            [
                helper.make_node("MatMul", ["X", "W"], ["I1"]),
                helper.make_node("Add", ["I1", "B"], ["Y"])
            ],
            # name
            "FC",
            # input def
            [
                helper.make_tensor_value_info('X', TensorProto.FLOAT,
                                              [1, num_input]),
                helper.make_tensor_value_info('W', TensorProto.FLOAT,
                                              [num_input, num_output]),
                helper.make_tensor_value_info("B", TensorProto.FLOAT,
                                              [1, num_output])
            ],
            # output def
            [
                helper.make_tensor_value_info('Y', TensorProto.FLOAT,
                                              [1, num_output])
            ],
            # init
            [
                helper.make_tensor('W', TensorProto.FLOAT,
                                   [num_input, num_output], W),
                helper.make_tensor('B', TensorProto.FLOAT, [1, num_output], B)
            ])

        onnx.checker.check_graph(fc_graph_def)
        print("pass graph-check")

        fc_model_def = helper.make_model(fc_graph_def,
                                         producer_name='onnx-builder')

        onnx.checker.check_model(fc_model_def)
        print("pass model-check")

        onnx.save_model(fc_model_def,
                        './onnx/fc_%s_%s.onnx' % (num_input, num_output))

    elif option == FC_TYPE.GEMM:
        assert (False)

    else:
        assert (False)
