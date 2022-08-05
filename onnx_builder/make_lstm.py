import onnx
from onnx import helper
from onnx import AttributeProto, TensorProto, GraphProto

import numpy as np

op_name = 'LSTM'

seq_size = 64
batch_size = 1
input_size = 10
hidden_size = 4
number_gates = 4
weight_scale = 0.1


def make_lstm():
    w = weight_scale * np.ones((1, number_gates * hidden_size, input_size)).astype(np.float32).flatten()
    r = weight_scale * np.ones((1, number_gates * hidden_size, hidden_size)).astype(np.float32).flatten()

    graph_def = helper.make_graph(
        # node
        [
            helper.make_node(
                op_name,
                inputs=['x', 'w', 'r'],
                outputs=['', 'y_last'],
                hidden_size=hidden_size
            )
        ],
        
        # name
        op_name, 
        
        # input def
        [
            helper.make_tensor_value_info('x', TensorProto.FLOAT,
                                              [seq_size, batch_size, input_size]),

            helper.make_tensor_value_info('w', TensorProto.FLOAT,
                                              [1, number_gates * hidden_size, input_size]),

            helper.make_tensor_value_info('r', TensorProto.FLOAT,
                                              [1, number_gates * hidden_size, hidden_size]),
        ],
        
        # output def
        [
            helper.make_tensor_value_info('y_last', TensorProto.FLOAT,
                                              [1, batch_size, hidden_size]),
        ],

        # init
        [
            helper.make_tensor('w', TensorProto.FLOAT,
                                [1, number_gates * hidden_size, input_size], w),
            helper.make_tensor('r', TensorProto.FLOAT, [1, number_gates * hidden_size, hidden_size], r)
        ]
    )
    
    onnx.checker.check_graph(graph_def)
    model_def = helper.make_model(graph_def)
    onnx.checker.check_model(model_def)
    onnx.save_model(model_def, "./ref_onnx/" + op_name + ".onnx")