import onnx
from onnx import helper, shape_inference
from onnx.helper import make_model, make_node, make_graph, make_tensor_value_info
from onnx import AttributeProto, TensorProto, GraphProto, numpy_helper
import numpy as np
from onnx.checker import check_model, check_graph

from collections import defaultdict
from collections import deque

from .lifted_ast import AST_OP


def export_onnx(lifted_ast_map, adj_map, op_info, filename="export_onnx"):
    # onnx graph building blocks
    created_nodes = []
    created_inputs = []
    created_outputs = []
    created_inits = []

    # used to keep track of previous outputs
    output_dict = {}
    output_node_dict = {}

    incoming_edge_map = {}
    for addr in lifted_ast_map.keys():
        incoming_edge_map[addr] = 0
    for src_addr in adj_map.keys():
        for dest_addr in adj_map[src_addr]:
            incoming_edge_map[dest_addr] += 1

    start_node_addr = [
        addr for addr in incoming_edge_map.keys() if incoming_edge_map[addr] == 0
    ]
    assert len(start_node_addr) == 1
    start_node_addr = start_node_addr[0]
    del incoming_edge_map[start_node_addr]

    # create input node
    inputs_node = make_tensor_value_info(
        "inputs",
        TensorProto.FLOAT,
        [
            1,  # batch size
            op_info[start_node_addr]["input_channel"],
            op_info[start_node_addr]["input_width"],
            op_info[start_node_addr]["input_height"],
        ],
    )
    if op_info[start_node_addr] == AST_OP.ADD:
        created_inputs.append(inputs_node)
        created_inputs.append(inputs_node)
    else:
        created_inputs.append(inputs_node)

    # worklist
    working_list = [start_node_addr]
    node_id = 0

    # keep track of the last node, to create output node
    cur_node_info = None

    while working_list:
        cur_node_addr = working_list.pop()
        cur_node_info = op_info[cur_node_addr]

        for dest_addr in adj_map[cur_node_addr]:
            incoming_edge_map[dest_addr] -= 1
            if incoming_edge_map[dest_addr] == 0:
                working_list.append(dest_addr)
                del incoming_edge_map[dest_addr]

        prev_output = []
        if len(output_dict) == 0:
            if cur_node_info["op"] == AST_OP.ADD:
                prev_output.append("inputs")
                prev_output.append("inputs")
            else:
                prev_output.append("inputs")
        else:
            prev_output.extend(
                [
                    output_dict[addr]
                    for addr in adj_map.keys()
                    if cur_node_addr in adj_map[addr]
                ]
            )
        prev_output_node = []
        if len(output_node_dict) == 0:
            prev_output_node.append(inputs_node)
        else:
            prev_output_node.extend(
                [
                    output_node_dict[addr]
                    for addr in adj_map.keys()
                    if cur_node_addr in adj_map[addr]
                ]
            )
        prev_node_addr = []
        for addr in adj_map.keys():
            if cur_node_addr in adj_map[addr]:
                prev_node_addr.append(addr)
        assert len(prev_output) > 0

        if cur_node_info["op"] == AST_OP.CONV:
            assert len(prev_output) == 1
            prev_output = prev_output[0]

            node_name = "conv_" + str(node_id)
            node_id += 1

            # node
            nodes, inputs, inits = make_conv(
                node_name,
                prev_output,
                node_name + "_output",
                cur_node_info["input_width"],
                cur_node_info["input_height"],
                1,
                cur_node_info["input_channel"],
                cur_node_info["output_channel"],
                cur_node_info["kernel_width"],
                cur_node_info["kernel_height"],
                cur_node_info["padding"],
                cur_node_info["striding"],
                cur_node_info["weights"],
                cur_node_info["bias"],
            )
            created_nodes.extend(nodes)
            #created_inputs.extend(inputs)
            created_inits.extend(inits)
            conv_output = nodes[0].output[0]
            output_dict[cur_node_addr] = nodes[0].output[0]

            output_node = make_tensor_value_info(
                output_dict[cur_node_addr], 
                TensorProto.FLOAT, 
                [
                    1,  # batch size
                    op_info[cur_node_addr]["output_channel"],
                    op_info[cur_node_addr]["output_width"],
                    op_info[cur_node_addr]["output_height"],
                ]
            )
            #created_outputs.append(output_node)
            output_node_dict[cur_node_addr] = output_node
            prev_output_node = prev_output_node[0]
            #created_inputs.append(prev_output_node)

            if "relu" in cur_node_info.keys() and cur_node_info["relu"]:
                node_name = "relu_" + str(node_id)
                node_id += 1
                nodes = make_relu(node_name, conv_output, node_name + "_output")
                created_nodes.extend(nodes)
                output_dict[cur_node_addr] = nodes[0].output[0]
                relu_output_node = make_tensor_value_info(
                    output_dict[cur_node_addr], 
                    TensorProto.FLOAT, 
                    [
                        1,  # batch size
                        op_info[cur_node_addr]["output_channel"],
                        op_info[cur_node_addr]["output_width"],
                        op_info[cur_node_addr]["output_height"],
                    ]
                )
                #created_outputs.append(relu_output_node)
                output_node_dict[cur_node_addr] = relu_output_node
                #created_inputs.append(output_node)

        elif cur_node_info["op"] == AST_OP.MAXPOOL:
            assert len(prev_output) == 1
            prev_output = prev_output[0]
            node_name = "maxpool_" + str(node_id)
            node_id += 1
            nodes = make_maxpool(
                node_name,
                prev_output,
                node_name + "_output",
                cur_node_info["kernel_shape"],
                cur_node_info["stride"],
            )
            created_nodes.extend(nodes)
            output_dict[cur_node_addr] = nodes[0].output[0]
            print("Output of MAXPOOL node: ", output_dict[cur_node_addr])
            output_node = make_tensor_value_info(
                output_dict[cur_node_addr], 
                TensorProto.FLOAT, 
                [
                    1,  # batch size
                    op_info[cur_node_addr]["output_channel"],
                    op_info[cur_node_addr]["output_width"],
                    op_info[cur_node_addr]["output_height"],
                ]
            )
            #created_outputs.append(output_node)
            output_node_dict[cur_node_addr] = output_node
            prev_output_node = prev_output_node[0]
            #created_inputs.append(prev_output_node)

        elif cur_node_info["op"] == AST_OP.FC:
            assert len(prev_output) == 1
            prev_output = prev_output[0]

            node_name = "fc_" + str(node_id)
            node_id += 1
            nodes, inputs, inits = make_gemm(
                node_name,
                prev_output,
                node_name + "_output",
                cur_node_info["input_size"],
                cur_node_info["contracted_size"],
                cur_node_info["output_size"],
                cur_node_info["weights"],
                cur_node_info["bias"],
            )
            created_nodes.extend(nodes)
            #created_inputs.extend(inputs)
            created_inits.extend(inits)
            output_dict[cur_node_addr] = nodes[0].output[0]
            output_node = make_tensor_value_info(
                output_dict[cur_node_addr], TensorProto.FLOAT, [1, cur_node_info["output_size"]]
            )
            #created_outputs.append(output_node)
            output_node_dict[cur_node_addr] = output_node
            prev_output_node = prev_output_node[0]
            #created_inputs.append(prev_output_node)

        elif cur_node_info["op"] == AST_OP.RELU:
            assert len(prev_output) == 1
            prev_output = prev_output[0]

            node_name = "relu_" + str(node_id)
            node_id += 1
            nodes = make_relu(node_name, prev_output, node_name + "_output")
            created_nodes.extend(nodes)
            output_dict[cur_node_addr] = nodes[0].output[0]
            output_node = make_tensor_value_info(
                output_dict[cur_node_addr], 
                TensorProto.FLOAT, 
                [
                    1,  # batch size
                    op_info[cur_node_addr]["output_channel"],
                    op_info[cur_node_addr]["output_width"],
                    op_info[cur_node_addr]["output_height"],
                ]
            )
            #created_outputs.append(output_node)
            output_node_dict[cur_node_addr] = output_node
            prev_output_node = prev_output_node[0]
            #created_inputs.append(prev_output_node)

        elif cur_node_info["op"] == AST_OP.ADD:
            assert len(prev_output) == 2
            prev_output_1 = prev_output[0]
            prev_output_2 = prev_output[1]

            node_name = "add_" + str(node_id)
            node_id += 1
            nodes = make_add(
                node_name,
                prev_output_1,
                prev_output_2,
                node_name + "_output"
            )
            created_nodes.extend(nodes)
            output_dict[cur_node_addr] = nodes[0].output[0]
            output_node = make_tensor_value_info(
                output_dict[cur_node_addr], 
                TensorProto.FLOAT, 
                [
                    1,  # batch size
                    op_info[cur_node_addr]["output_channel"],
                    op_info[cur_node_addr]["output_width"],
                    op_info[cur_node_addr]["output_height"],
                ]
            )
            #created_outputs.append(output_node)
            output_node_dict[cur_node_addr] = output_node
            prev_output_node = prev_output_node[0]
            #created_inputs.append(prev_output_node)

        elif cur_node_info["op"] == AST_OP.AVGPOOL:
            assert len(prev_output) == 1
            prev_output = prev_output[0]

            node_name = "avgpool_" + str(node_id)
            node_id += 1
            nodes = make_avgpool(
                node_name,
                prev_output,
                node_name + "_output",
                cur_node_info["kernel_shape"],
                cur_node_info["stride"],
            )
            created_nodes.extend(nodes)
            output_dict[cur_node_addr] = nodes[0].output[0]
            output_node = make_tensor_value_info(
                output_dict[cur_node_addr], 
                TensorProto.FLOAT, 
                [
                    1,  # batch size
                    op_info[cur_node_addr]["output_channel"],
                    op_info[cur_node_addr]["output_width"],
                    op_info[cur_node_addr]["output_height"],
                ]
            )
            #created_outputs.append(output_node)
            output_node_dict[cur_node_addr] = output_node
            prev_output_node = prev_output_node[0]
            #created_inputs.append(prev_output_node)

        elif cur_node_info["op"] == AST_OP.SOFTMAX:
            assert len(prev_output) == 1
            prev_output = prev_output[0]

            node_name = "softmax_" + str(node_id)
            node_id += 1
            nodes = make_softmax(node_name, prev_output, node_name + "_output")
            created_nodes.extend(nodes)
            output_dict[cur_node_addr] = nodes[0].output[0]
            output_node = make_tensor_value_info(
                output_dict[cur_node_addr], 
                TensorProto.FLOAT, [1, cur_node_info["output_size"]]
            )
            #created_outputs.append(output_node)
            output_node_dict[cur_node_addr] = output_node
            prev_output_node = prev_output_node[0]
            #created_inputs.append(prev_output_node)

        else:
            assert False

    assert len(incoming_edge_map) == 0

    # TODO: output node
    output_node = output_node_dict[cur_node_addr]
    created_outputs.append(output_node)
    #print("Nodes: ",created_nodes)
    #print("inputs: ",created_inputs)
    #print("outputs: ",created_outputs)
    graph = make_graph(
        created_nodes, "test", created_inputs, created_outputs, created_inits
    )

    check_graph(graph)
    print("pass graph-check")

    model = helper.make_model(graph, producer_name="onnx-builder")
    model = shape_inference.infer_shapes(model)
    check_model(model)
    print("pass model-check")
    print(model)

    onnx.save_model(model, filename)


def make_conv(
    node_name,
    input_name,
    output_name,
    in_w,
    in_h,
    batch,
    in_channel,
    out_channel,
    k_w,
    k_h,
    k_pad,
    k_stride,
    kernel_weight,
    bias,
):
    """
    make onnx for conv op
    """

    assert in_w == in_h
    assert k_w == k_h

    # calculate output attributes
    # out_w = (in_w - k_w + 2 * k_pad + 1) // k_stride
    # out_len = (in_h - k_h + 2 * k_pad + 1) // k_stride

    # init kernel, shape [batch, out_channel, in_channel, k_w, k_h]
    # if kernel_weight is None:
    #     W = (
    #         np.random.randn(batch, out_channel, in_channel, k_w, k_h)
    #         .astype(np.float32)
    #         .astype(np.float32)
    #         .flatten()
    #     )
    # else:
    #     assert kernel_weight.shape == (batch, out_channel, in_channel, k_w, k_h)
    #     W = kernel_weight.astype(np.float32).flatten()

    # node
    weight_init = numpy_helper.from_array(kernel_weight, name=node_name + "_weights")
    bias_init = numpy_helper.from_array(bias, name=node_name + "_bias")
    conv_node = helper.make_node(
        op_type="Conv",
        name=node_name,
        inputs=[input_name, node_name + "_weights", node_name + "_bias"],
        outputs=[output_name],
        kernel_shape=[k_w, k_h],
        pads=[k_pad, k_pad, k_pad, k_pad],
        strides=[k_stride, k_stride],
    )

    # weight
    #weight_input = make_tensor_value_info(
    #    node_name + "_weights",
    #    TensorProto.FLOAT,
    #    [out_channel, in_channel, k_w, k_h],
    #)
    #weight_init = numpy_helper.from_array(kernel_weight, name=node_name + "_weights")

    # bias
    #bias_input = make_tensor_value_info(
    #    node_name + "_bias",
    #    TensorProto.FLOAT,
    #    [out_channel],
    #)
    #bias_init = numpy_helper.from_array(bias, name=node_name + "_bias")

    #return [conv_node], [weight_input, bias_input], [weight_init, bias_init]
    return [conv_node], [weight_init, bias_init], [weight_init, bias_init]


def make_gemm(node_name, input_name, output_name, i, j, k, weights, bias):
    """
    make onnx for fc op
    input shape: [i, j]
    weight shape: [j, k]
    output shape: [i, k]
    """

    assert weights.shape == (j, k)
    #weight_input = make_tensor_value_info(
    #    node_name + "_weights",
    #    TensorProto.FLOAT,
    #    [j, k],
    #)
    weight_init = numpy_helper.from_array(weights, node_name + "_weights")

    if i == 1:
        assert bias.shape == (k,)
    else:
        assert False

    #bias_input = make_tensor_value_info(
    #    node_name + "_bias",
    #    TensorProto.FLOAT,
    #    [k],
    #)
    bias_init = numpy_helper.from_array(bias, node_name + "_bias")

    gemm_node = helper.make_node(
        op_type="Gemm",
        name=node_name,
        inputs=[input_name, node_name + "_weights", node_name + "_bias"],
        outputs=[output_name],
        alpha=1.0,
        beta=1.0,
    )

    return [gemm_node], [weight_init, bias_init], [weight_init, bias_init]


def make_relu(node_name, input_name, output_name):
    """
    make onnx for relu op
    """
    relu_node = helper.make_node(
        op_type="Relu",
        name=node_name,
        inputs=[input_name],
        outputs=[output_name],
    )

    return [relu_node]


def make_maxpool(node_name, input_name, output_name, kernel_shape, strides):
    maxpool_node = helper.make_node(
        op_type="MaxPool",
        name=node_name,
        inputs=[input_name],
        outputs=[output_name],
        kernel_shape=[kernel_shape, kernel_shape],
        strides=[strides, strides],
    )
    return [maxpool_node]


def make_add(node_name, input_name_1, input_name_2, output_name):
    add_node = helper.make_node(
        op_type="Add",
        name=node_name,
        inputs=[input_name_1, input_name_2],
        outputs=[output_name],
    )
    return [add_node]


def make_avgpool(node_name, input_name, output_name, kernel_shape, strides):
    avgpool_node = helper.make_node(
        op_type="AveragePool",
        name=node_name,
        inputs=[input_name],
        outputs=[output_name],
        kernel_shape=[kernel_shape, kernel_shape],
        strides=[strides, strides],
    )
    return [avgpool_node]


def make_softmax(node_name, input_name, output_name):
    softmax_node = helper.make_node(
        op_type="Softmax",
        name=node_name,
        inputs=[input_name],
        outputs=[output_name],
    )
    return [softmax_node]
