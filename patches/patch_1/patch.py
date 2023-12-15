#!/usr/bin/env python

from patcherex import *
from patcherex.targets import ElfArmMimxrt1052
from patcherex.allocation_management.allocation_management import *
import logging

BIN_PATH = "./evkbimxrt1050_glow_lenet_mnist_new.axf"

logging.getLogger("patcherex").setLevel("DEBUG")

p = Patcherex(BIN_PATH, target_cls=ElfArmMimxrt1052)

p.patches.append(ModifyDataPatch(0x800000a4, struct.pack("<f", -10000.0)))
p.patches.append(ModifyDataPatch(0x80000084, struct.pack("<f", 10000.0)))

p.apply_patches()
p.binfmt_tool.save_binary(f"{BIN_PATH}.patched")
