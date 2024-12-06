#include <inttypes.h>                                                            
#include <stdio.h>                                                               
#include <stdlib.h>                                                              
                                                                                 
                                                                                 
#include "Relu.h"

GLOW_MEM_ALIGN(RELU_MEM_ALIGN)
uint8_t constantWeight[RELU_CONSTANT_MEM_SIZE] = {
#include "Relu.weights.txt"
};

GLOW_MEM_ALIGN(RELU_MEM_ALIGN)
uint8_t mutableWeight[RELU_MUTABLE_MEM_SIZE];

GLOW_MEM_ALIGN(RELU_MEM_ALIGN)
uint8_t activations[RELU_ACTIVATIONS_MEM_SIZE];


int main(int argc, char **argv) {
  Relu(constantWeight, mutableWeight, activations);
}
