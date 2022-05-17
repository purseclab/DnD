### Hex-Rays (IDA Pro) decompiled code samples

We show the Hex-Rays' decompilation results of five binary functions.
We generate these five binary functions by compiling two convolution operator instances (i.e., ```Conv1``` and ```Conv2```) in ResNet neural network with two ISAs (i.e., Arm thumb and x86) and two DNN compilers (i.e., Glow and TVM). ```Conv1``` and ```Conv2``` have different attributes (e.g., kernel shape, padding size). 

We elaborate on how we generate these five binary functions as follows:

- ```Conv1_Arm_thumb_Glow.c```: ```Conv1``` compiled for Arm thumb by Glow 
- ```Conv1_Arm_thumb_TVM.c```: ```Conv1``` compiled for Arm thumb by TVM 
- ```Conv1_x86_Glow.c```: ```Conv1``` compiled for x86 by Glow 
- ```Conv1_x86_TVM.c```: ```Conv1``` compiled for x86 by TVM
- ```Conv2_x86_Glow.c```: ```Conv2``` compiled for x86 by Glow 



We have the following observations:

1. From every decompiled code samples, we learn that Hex-Rays do not recognize vectorized mathematical computations, leading to decompilation representations containing long loop bodies and excessive bitwise operations.
2. From the comparison between these decompilation results, for example, ```Conv1_x86_Glow.c``` and ```Conv1_Arm_thumb_TVM.c```, we learn that the control-/data- flows of their IDA Pro decompiled codes are completely different, depending on compilers/ISAs. 
3. From the comparison between ```Conv1_x86_Glow.c``` and ```Conv2_x86_Glow.c```, we learn that, even with the same compiler and ISAs, DNN operators of the same type but with different attributes have different decompilation representations, because they are *specialized*.



These limitations of existing general-purpose decompiler make simple pattern matching based on decompiled code difficult. 

