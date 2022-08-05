import onnx
from onnx import helper
from onnx import AttributeProto, TensorProto, GraphProto
import numpy as np


def make_conv(in_w,
              in_h,
              batch=1,
              in_channel=1,
              out_channel=1,
              k_w=1,
              k_h=1,
              k_pad=0,
              k_stride=1):
    '''
    make onnx for conv op
    '''

    # calculate output attributes
    out_w = (in_w - k_w + 2 * k_pad + 1) // k_stride
    out_len = (in_h - k_h + 2 * k_pad + 1) // k_stride

    # init kernel
    W = np.random.randn(batch, out_channel, in_channel, k_w,
                        k_h).astype(np.float32).astype(np.float32).flatten()

    conv_graph_def = helper.make_graph(
        # node
        [
            helper.make_node("Conv",
                             inputs=["X", "W"],
                             outputs=["Y"],
                             kernel_shape=[k_w, k_h],
                             pads=[k_pad, k_pad, k_pad, k_pad],
                             strides=[k_stride, k_stride])
        ],
        # name
        "Conv_deepwise",
        # input def
        [
            helper.make_tensor_value_info('X', TensorProto.FLOAT,
                                          [batch, in_channel, in_w, in_h]),
            helper.make_tensor_value_info('W', TensorProto.FLOAT,
                                          [in_channel, out_channel, k_w, k_h]),
        ],
        # output def
        [
            helper.make_tensor_value_info('Y', TensorProto.FLOAT,
                                          [batch, out_channel, out_w, out_len])
        ],
        # init
        [
            helper.make_tensor('W', TensorProto.FLOAT,
                               [out_channel, in_channel, k_w, k_h], W),
        ])

    onnx.checker.check_graph(conv_graph_def)
    print("pass graph-check")

    conv_model_def = helper.make_model(conv_graph_def,
                                       producer_name='onnx-builder')

    onnx.checker.check_model(conv_model_def)
    print("pass model-check")

    assert (in_w == in_h)
    assert (k_w == k_h)
    onnx.save_model(
        conv_model_def,
        './onnx/conv_%s_%s_%s_%s.onnx' % (in_channel, in_w, out_channel, k_w))
