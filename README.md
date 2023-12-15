# DnD: A Cross-Architecture Deep Neural Network Decompiler

DND is a deep neural network (DNN) decompiler capable of reverse engineering DNN models from compiled binaries.

### Environment  
1. Create a Python virtual environment
2. `pip install -r ./angr_env/requirements.txt `
3. Move `./angr_env/base.py` to overwrite the counterpart in the virtual environment `claripy` (usually in `$USERNAME/.virtualenvs/$VIRTUALENVNAME/lib/python$VERSION/site-packages/claripy/ast/base.py`) 

### Usage
Run `python decompiler.py <model_binary> <model_onnx>` to decompile a binary sample (`<model_binary>`) and export it into an ONNX file (`<model_onnx>`). Please check `decompiler.py` for more details.

Two samples are provided:
`./binary_samples/evkbimxrt1050_glow_lenet_mnist_release.axf`: a MNIST binary on NXP imrt1050-evk board
`./binary_samples/evkbimxrt1050_glow_cifar10.axf`: a Resnet binary on NXP imrt1050-evk board
