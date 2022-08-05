import onnx
from onnx import helper
from onnx import AttributeProto, TensorProto, GraphProto

import numpy as np

op_name = 'LRN'

alpha = 0.0002
beta = 0.5
bias = 2.0
nsize = 3

def make_lrn():

    graph_def = helper.make_graph(
        # node
        [
            helper.make_node(
                'LRN',
                inputs=['x'],
                outputs=['y'],
                size=3,
                alpha=alpha,
                beta=beta,
                bias=bias,
            )
        ],
        
        # name
        op_name, 
        
        # input def
        [
            helper.make_tensor_value_info('x', TensorProto.FLOAT,
                                              [5, 5, 5, 5]),
        ],
        
        # output def
        [
            helper.make_tensor_value_info('y', TensorProto.FLOAT,
                                              [5, 5, 5, 5]),
        ],
    )
    
    onnx.checker.check_graph(graph_def)
    model_def = helper.make_model(graph_def)
    onnx.checker.check_model(model_def)
    onnx.save_model(model_def, "./ref_onnx/" + op_name + ".onnx")