#!/usr/bin/env python

#loadDNN("/home/soumya/DnD/binary_samples/evkbimxrt1050_glow_lenet_mnist_release.axf")

from patcherex2 import *
from patcherex2.targets import ElfArmMimxrt1052
import struct
import logging

BIN_PATH = "./evkbimxrt1050_glow_lenet_mnist_new.axf"

logging.getLogger("patcherex").setLevel("DEBUG")

p = Patcherex(BIN_PATH, target_cls=ElfArmMimxrt1052)

p.patches.append(ModifyDataPatch(0x800000a4, struct.pack("<f", -10000.0)))
p.patches.append(ModifyDataPatch(0x80000084, struct.pack("<f", 10000.0)))

p.apply_patches()
p.binfmt_tool.save_binary(f"{BIN_PATH}.patched")
