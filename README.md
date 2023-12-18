# DnD: A Cross-Architecture Deep Neural Network Decompiler

DND is a deep neural network (DNN) decompiler capable of reverse engineering DNN models from compiled binaries.

### Environment  
1. Create a Python virtual environment
2. `pip install -r ./angr_env/requirements.txt `
3. Move `./angr_env/base.py` to overwrite the counterpart in the virtual environment `claripy` (usually in `$USERNAME/.virtualenvs/$VIRTUALENVNAME/lib/python$VERSION/site-packages/claripy/ast/base.py`)

### Docker container
We provide a docker container. To use it, just run:
```bash
docker build . -t dnd
docker run -it dnd
```

### Usage
* Run `python decompiler.py <model_binary> <model_onnx>` to decompile a binary sample (`<model_binary>`) and export it into an ONNX file (`<model_onnx>`).For instance:
```bash binary_samples/evkbimxrt1050_glow_lenet_mnist_release.axf 
python ./decompiler.py binary_samples/evkbimxrt1050_glow_lenet_mnist_release.axf onnx_models/mnist.onnx
python ./decompiler.py binary_samples/evkbimxrt1050_glow_cifar10.axf onnx_models/resnet.onnx
```

* Two samples are provided:  
`./binary_samples/evkbimxrt1050_glow_lenet_mnist_release.axf`: a MNIST binary on NXP imrt1050-evk board  
`./binary_samples/evkbimxrt1050_glow_cifar10.axf`: a Resnet binary on NXP imrt1050-evk board

* The folder `onnx_models` containes ONNX models exported by DND for the binaries in `binary_samples`.

* The folder `patches` showcases how to patch binaries implementing DNNs.

* Please check `decompiler.py` for more details.

### Citing this work
```@inproceedings{wu2022dnd,
  title={$\{$DnD$\}$: A $\{$Cross-Architecture$\}$ deep neural network decompiler},
  author={Wu, Ruoyu and Kim, Taegyu and Tian, Dave Jing and Bianchi, Antonio and Xu, Dongyan},
  booktitle={31st USENIX Security Symposium (USENIX Security 22)},
  pages={2135--2152},
  year={2022}
}
```
