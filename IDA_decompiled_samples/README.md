### Comparison with IDA Pro decompiled code

We show the IDA Pro's decompilation results of four binary functions.
We generate those four binary functions by compiling a convolution operator instance in ResNet neural network with two ISAs (i.e., Arm thumb and x86) and two DNN compilers (i.e., Glow and TVM). 
The IDA Pro's decompilation results of these four binary functions are in the following files:  
  - Conv_Arm_thumb_Glow.c: a convolution operator instance compiled for Arm thumb by Glow 
  - Conv_Arm_thumb_TVM.c: a convolution operator instance compiled for Arm thumb by TVM 
  - Conv_x86_Glow.c: a convolution operator instance compiled for x86 by Glow 
  - Conv_x86_TVM.c: a convolution operator instance compiled for x86 by TVM 


By comparing these decompilation results, for example, Conv_Arm_thumb_Glow.c and Conv_Arm_thumb_TVM.c, we can clearly see that even they are implementing the same operator instance, the control-flow and data-flow structure of their IDA Pro decompiled codes are completely different, making pattern matching based on decompiled code difficult. 

