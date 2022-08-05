import onnx
from onnx import helper
from onnx import AttributeProto, TensorProto, GraphProto

import numpy as np

op_name = 'Tile'
num_input = 100

def make_tile():

    graph_def = helper.make_graph(
        # node
        [
            helper.make_node('Tile', inputs=['x', 'y'], outputs=['z'])
        ],
        
        # name
        op_name, 
        
        # input def
        [
            helper.make_tensor_value_info('x', TensorProto.FLOAT,
                                              [2, 3, 4, 5]),
            helper.make_tensor_value_info('y', TensorProto.FLOAT,
                                              [4, ]),
        ],
        
        # output def
        [
            helper.make_tensor_value_info('z', TensorProto.FLOAT,
                                              [18, 6, 20, 20]),
        ],
        
        # init
        [
            
        ] 
    )
    
    onnx.checker.check_graph(graph_def)
    model_def = helper.make_model(graph_def)
    onnx.checker.check_model(model_def)
    onnx.save_model(model_def, "./ref_onnx/" + op_name + ".onnx")