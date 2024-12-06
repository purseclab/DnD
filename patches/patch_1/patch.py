#!/usr/bin/env python

"""
This patch modifies the prob distribution at the last layer, 
making the p[1] always larger than p[10]. 
"""


from patcherex2 import *
from patcherex2.targets import ElfArmMimxrt1052
from patcherex2.components.allocation_managers.allocation_manager import *
import logging

BIN_PATH = "./evkbimxrt1050_glow_lenet_mnist_new.axf"

logging.getLogger("patcherex").setLevel("DEBUG")

p = Patcherex(BIN_PATH, target_cls=ElfArmMimxrt1052)

# unused_funcs = [{"addr": 0x600028DC, "size": 36, "flag": MemoryFlag.RX}]
unused_funcs = [
    {"addr": 0x600030F2, "size": 0x6000311E - 0x600030F2, "flag": MemoryFlag.RX}
]
for func in unused_funcs:
    block = MappedBlock(
        p.binary_analyzer.mem_addr_to_file_offset(func["addr"]),
        func["addr"],
        func["size"],
        is_free=True,
        flag=func["flag"],
    )
    p.allocation_manager.add_block(block)


p.patches.append(ModifyInstructionPatch(0x600030F0, "bx lr"))

injected_code = """
add  r4, r5, #0xc40
vldr s15, [r4, #0x24]
movw r6, 0x3126
movt r6, 0x3a83
vmov s0, r6
vadd.f32 s15, s15, s0
vstr s15, [r4, #0x4]
"""

p.patches.append(InsertInstructionPatch(0x60004504, injected_code))

p.apply_patches()
p.binfmt_tool.save_binary(f"{BIN_PATH}.patched")
