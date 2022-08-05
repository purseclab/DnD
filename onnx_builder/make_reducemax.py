import onnx
from onnx import helper
from onnx import AttributeProto, TensorProto, GraphProto

import numpy as np

op_name = 'ReduceMax'

shape = [100, 2, 2]
axes = None
keepdims = 1

def make_reducemax():

    graph_def = helper.make_graph(
        # node
        [
            helper.make_node(op_name,inputs=['x'],outputs=['y'],keepdims=1)
        ],
        
        # name
        op_name, 
        
        # input def
        [
            helper.make_tensor_value_info('x', TensorProto.FLOAT,
                                              shape),
        ],
        
        # output def
        [
            helper.make_tensor_value_info('y', TensorProto.FLOAT,
                                              [1]),
        ],
        
        # init
        [
            
        ] 
    )
    
    onnx.checker.check_graph(graph_def)
    model_def = helper.make_model(graph_def)
    onnx.checker.check_model(model_def)
    onnx.save_model(model_def, "./ref_onnx/" + op_name + ".onnx")