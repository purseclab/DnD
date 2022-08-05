import onnx

mnist_model = onnx.load("../models/mnist/onnx/mnist-8.onnx")
mobilenet_model = onnx.load("../models/mobilenet/mobilenetv2-7.onnx")
resnet_model = onnx.load("../models/resnet/resnet18-v2-7.onnx")

def get_num_op(model):
    return len(model.graph.node)

def get_num_op_type(model):
    type_set = set()
    for _node in model.graph.node:
        type_set.add(_node.op_type)
    return len(type_set)

def get_num_conn(model):
    # init output
    output_set = set()
    for _node in model.graph.node:
        for o in _node.output:
            assert (o not in output_set)
            output_set.add(o)
    
    # counting
    conn_count = 0
    for _node in model.graph.node:
        for i in _node.input:
            if i in output_set:
                conn_count += 1
                
    return conn_count

def get_num_param_float(model):
    count = 0
    for _init in model.graph.initializer:
        count += len(_init.float_data)
    return count

def get_num_param_dim(model):
    count = 0
    for _init in model.graph.initializer:
        local_count = 1
        for _dim in _init.dims:
            local_count *= _dim
        count += local_count
    return count

def get_stat(model):
    print("# op: ", get_num_op(model))
    print("# op type: ", get_num_op_type(model))
    print("# conn: ", get_num_conn(model))
    
def rename(model):
    counter = 0
    for _node in model.graph.node:
        _node.op_type = _node.op_type + "_" + str(counter)
        counter+=1
