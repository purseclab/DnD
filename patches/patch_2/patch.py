#!/usr/bin/env python

from patcherex2 import *
from patcherex2.targets import ElfArmMimxrt1052
from patcherex2.allocation_management.allocation_management import *
import logging

BIN_PATH = "./evkbimxrt1050_glow_cifar10_new.axf"

logging.getLogger("patcherex2").setLevel("DEBUG")

p = Patcherex(BIN_PATH, target_cls=ElfArmMimxrt1052)

for i in range(0, 0x40):
    addr_a = p.binary_analyzer.mem_addr_to_file_offset(0x8004b480 + 0x28 * i)
    addr_b = p.binary_analyzer.mem_addr_to_file_offset(0x8004b488 + 0x28 * i)
    p.patches.append(ModifyDataPatch(0x8004b480 + 0x28 * i, p.binfmt_tool.get_binary_content(addr_b, 4)))
    p.patches.append(ModifyDataPatch(0x8004b488 + 0x28 * i, p.binfmt_tool.get_binary_content(addr_a, 4)))

p.apply_patches()
p.binfmt_tool.save_binary(f"{BIN_PATH}.patched")
