import onnx
from onnx import helper
from onnx import AttributeProto, TensorProto, GraphProto

import numpy as np

op_name = 'Flatten'
num_input = 100


def make_flatten():

    graph_def = helper.make_graph(
        # node
        [
            helper.make_node('Flatten', inputs=['x'], outputs=['y'], axis=1)
        ],
        
        # name
        op_name, 
        
        # input def
        [
            helper.make_tensor_value_info('x', TensorProto.FLOAT,
                                              [200, 300, 400]),
        ],
        
        # output def
        [
            helper.make_tensor_value_info('y', TensorProto.FLOAT,
                                              [200, 120000]),
        ],
        
        # init
        [
            
        ] 
    )
    
    onnx.checker.check_graph(graph_def)
    model_def = helper.make_model(graph_def)
    onnx.checker.check_model(model_def)
    onnx.save_model(model_def, "./ref_onnx/" + op_name + ".onnx")