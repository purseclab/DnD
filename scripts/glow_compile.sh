#!/bin/bash

compiler=/home/ruoyu/workspace/ml_decompiler/glow/model-compiler

$compiler -backend=CPU -target=arm -mcpu=cortex-m4 -network-name=$1 -model=/home/ruoyu/workspace/ml_decompiler/ml_decompiler_scripts/ml_decompiler/onnx_builder/onnx/$1.onnx -emit-bundle=/home/ruoyu/workspace/ml_decompiler/glow/bundles/$1

# --onnx-define-symbol=$sym,$val to define sym