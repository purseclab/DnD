import onnx
from onnx import helper
from onnx import AttributeProto, TensorProto, GraphProto

import numpy as np

# ./model-compiler -backend=CPU -target=arm -mcpu=cortex-m4 -network-name=erf -model=/home/ruoyu/workspace/ml_decompiler/ml_decompiler_scripts/ml_decompiler/onnx_builder/ref_onnx/Erf.onnx -emit-bundle=/home/ruoyu/workspace/ml_decompiler/ml_decompiler_scripts/ml_decompiler/onnx_builder/ref_bin/Erf

op_name = 'Erf'
num_input = 100

def make_erf():

    graph_def = helper.make_graph(
        # node
        [
            onnx.helper.make_node(op_name, ['x'], ['y']) 
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
    )
    
    onnx.checker.check_graph(graph_def)
    model_def = helper.make_model(graph_def)
    onnx.checker.check_model(model_def)
    onnx.save_model(model_def, "./ref_onnx/" + op_name + ".onnx")