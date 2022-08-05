import onnx
from onnx import helper
from onnx import AttributeProto, TensorProto, GraphProto

import numpy as np

op_name = 'Argmax'
num_input = 100

def make_argmax():

    graph_def = helper.make_graph(
        # node
        [
            helper.make_node('ArgMax',inputs=['x'],outputs=['y'],keepdims=1)
        ],
        
        # name
        op_name, 
        
        # input def
        [
            helper.make_tensor_value_info('x', TensorProto.FLOAT,
                                              [1, num_input]),
        ],
        
        # output def
        [
            helper.make_tensor_value_info('y', TensorProto.FLOAT,
                                              [1, num_input]),
        ],
        
        # init
        [
            
        ] 
    )
    
    onnx.checker.check_graph(graph_def)
    model_def = helper.make_model(graph_def)
    onnx.checker.check_model(model_def)
    onnx.save_model(model_def, "./ref_onnx/" + op_name + ".onnx")