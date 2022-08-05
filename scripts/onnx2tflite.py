import sys
import argparse
import onnx
import tensorflow as tf
from onnx_tf.backend import prepare
import os

def onnx2tflite(onnx_path, tflite_path):
    temp_dir = "tf_model_pb"

    # onnx to pb
    onnx_model = onnx.load(onnx_path)
    tf_rep = prepare(onnx_model)
    tf_rep.export_graph(temp_dir)

    # pb to tflite
    converter = tf.lite.TFLiteConverter.from_saved_model(temp_dir)
    converter.target_spec.supported_ops = [
        tf.lite.OpsSet.TFLITE_BUILTINS,  # enable TensorFlow Lite ops.
        tf.lite.OpsSet.SELECT_TF_OPS  # enable TensorFlow ops.
    ]
    tflite_model = converter.convert()
    open(tflite_path, "wb").write(tflite_model)

    # delete pb
    os.remove(temp_dir)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="onnx to tflite")
    parser.add_argument('onnx_path', type=str, help='the path of onnx file')
    parser.add_argument('tflite_path', type=str, help='the path of tflite')
    args = parser.parse_args()
    onnx_path = args.onnx_path
    tflite_path = args.tflite_path

    onnx2tflite(onnx_path, tflite_path)
