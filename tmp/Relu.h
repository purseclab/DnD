// Bundle API auto-generated header file. Do not edit!
// Glow Tools version: 2024-05-11 (05dd99b97) ()

#ifndef _GLOW_BUNDLE_RELU_H
#define _GLOW_BUNDLE_RELU_H

#include <stdint.h>

// ---------------------------------------------------------------
//                       Common definitions
// ---------------------------------------------------------------
#ifndef _GLOW_BUNDLE_COMMON_DEFS
#define _GLOW_BUNDLE_COMMON_DEFS

// Glow bundle error code for correct execution.
#define GLOW_SUCCESS 0

// Memory alignment definition with given alignment size
// for static allocation of memory.
#define GLOW_MEM_ALIGN(size)  __attribute__((aligned(size)))

// Macro function to get the absolute address of a
// placeholder using the base address of the mutable
// weight buffer and placeholder offset definition.
#define GLOW_GET_ADDR(mutableBaseAddr, placeholderOff)  (((uint8_t*)(mutableBaseAddr)) + placeholderOff)

#endif

// ---------------------------------------------------------------
//                          Bundle API
// ---------------------------------------------------------------
// Model name: "Relu"
// Total data size: 2048 (bytes)
// Activations allocation efficiency: 0.0000
// Placeholders:
//
//   Name: "inputs"
//   Type: float<1 x 16 x 4 x 4>
//   Size: 256 (elements)
//   Size: 1024 (bytes)
//   Offset: 0 (bytes)
//
//   Name: "relu_0_output"
//   Type: float<1 x 16 x 4 x 4>
//   Size: 256 (elements)
//   Size: 1024 (bytes)
//   Offset: 1024 (bytes)
//
// NOTE: Placeholders are allocated within the "mutableWeight"
// buffer and are identified using an offset relative to base.
// ---------------------------------------------------------------
#ifdef __cplusplus
extern "C" {
#endif

// Placeholder address offsets within mutable buffer (bytes).
#define RELU_inputs         0
#define RELU_relu_0_output  1024

// Memory sizes (bytes).
#define RELU_CONSTANT_MEM_SIZE     0
#define RELU_MUTABLE_MEM_SIZE      2048
#define RELU_ACTIVATIONS_MEM_SIZE  0

// Memory alignment (bytes).
#define RELU_MEM_ALIGN  64

// Bundle entry point (inference function). Returns 0
// for correct execution or some error code otherwise.
int Relu(uint8_t *constantWeight, uint8_t *mutableWeight, uint8_t *activations);

#ifdef __cplusplus
}
#endif
#endif
