#!/usr/bin/env bash

# workon ml_decompiler

# with tf2onnx
python -m tf2onnx.convert --opset 13 --tflite ./CIFAR10_ResNetv1.tflite --output resnetv1.onnx

# with tflite2onnx
# it WORKS
tflite2onnx ./CIFAR10_ResNetv1.tflite ./resnet.onnx