
import angr
from collections import defaultdict
import pickle
import sys
import os
import capstone

from src.loader import load
from src.iv_identify import identify_iv
from src.ast import extract_ast
from src.lifter import lift
from src.lifted_ast import LiftedAST, AST_OP
from src.timeout import timeout
from src.onnx_builder import export_onnx
from decompiler import lift_func_to_ast, recover_topology

from patcherex2 import *
from patcherex2.targets import ElfArmMimxrt1052
import struct
import logging
import numpy as np

from enum import Enum

def extractCodeBytes(path_to_obj,target_sym):
    obj = angr.Project(path_to_obj, auto_load_libs=False)
    
    main_obj = obj.loader.main_object
    
    text_section = None
    for section in main_obj.sections:
        if section.name == '.text':
            text_section = section
            break
    
    symbol = obj.loader.find_symbol(target_sym)
    #mask = 0xfffffffe
    sym_addr = symbol.rebased_addr
    
    asm = "extracted_code:\n"

    if symbol:
        print(f"Symbol {target_sym} found!")
        print(f"Address: {hex(sym_addr)}")
    else:
        print(f"Symbol {target_sym} not found.")
    
    block = obj.factory.block(sym_addr)
    for insn in block.capstone.insns:
        print(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
        if insn.mnemonic in ["bl", "blx"]:
            if insn.operands:
                for operand in insn.operands:
                    target_address = operand.imm
                    print("Found target: ",hex(target_address))
                    sym_addr = target_address
    
    if text_section is None:
        print(".text section not found.")
    else:
        start_addr = text_section.vaddr
        size = text_section.memsize
    
        # Extract the raw bytes from the memory using angr's memory object
        text_bytes = obj.loader.memory.load(start_addr, size)

        end_addr = start_addr + size
        i = 0
        while start_addr < end_addr:
            if start_addr == sym_addr:
                asm = asm + target_sym + ":\n"
            b = text_bytes[i];
            asm = asm + "  .byte " + str(b) + "\n"
            i += 1
            start_addr += 1

    print(asm)
    return asm

class POS(Enum):
    BEFORE = 1
    AFTER = 2

class Weight:
    def __init__(self,dimensions,values,addrs):
        self.dimensions = dimensions
        self.values = values
        self.address = addrs

class Bias:
    def __init__(self,size,values,addrs):
        self.size = size
        self.values = values
        self.address = addrs

class Operator:
    def __init__(self,id,addr,ast,info):
        self.id = id
        self.addr = addr
        self.child = set()
        self.parent = None
        self.info = info
        self.weight = None
        self.bias = None
        self.layer = None
        self.ast = ast
        self.readbuffer = None
        self.writebuffer = None
        if self.ast is not None:
            self.readbuffer = ast.get_mem_read_base_reg(),
            self.writebuffer = ast.get_mem_write_base_reg(),
            if self.ast.op_type == AST_OP.CONV:
                dimension = [ 
                    self.ast.output_channel_iv.size(),
                    self.ast.input_channel_iv.size(),
                    self.ast.kernel_height_iv.size(),
                    self.ast.kernel_width_iv.size(),
                ]
                self.weight = Weight(dimension,self.info["weights"],self.info["weights addrs"])
                self.bias = Bias(info["output_channel"],info["bias"],info["bias addrs"])
            elif self.ast.op_type == AST_OP.FC:
                dimension = [self.ast.row_idx_iv.size(), self.ast.col_idx_iv.size()]
                self.weight = Weight(dimension,self.info["weights"],self.info["weights addrs"])
                self.bias = Bias(info["output_size"],info["bias"],info["bias addrs"])


    def getLayer(self):
        if self.layer is None:
            if self.parent is not None:
                self.layer = self.parent.getLayer() + 1
            else:
                self.layer = 1
        return self.layer

    def getReadBuffer(self):
        print("getting read buffer for: ",self.id)
        if self.readbuffer[0] is None:
            print("parent: ",self.parent)
            if self.parent is not None:
                print("getting parents writebuffer")
                self.readbuffer = self.parent.getWritedBuffer()
        print("Read buffer of ",self.id," -> ",self.readbuffer)
        return self.readbuffer

    def getWriteBuffer(self):
        print("getting writebuffer: ",self.id)
        if self.writebuffer[0] is None:
            c = list(self.child)[0]
            if c is not None:
                self.writebuffer = c.getReadBuffer()
        print("Write buffer of ",self.id," -> ",self.writebuffer)
        return self.writebuffer

class NewOp:
    def __init__(self,name,op,onnx_file,obj_file):
        self.name = name
        self.op = op
        self.onnxfile = onnx_file
        self.objfile = obj_file

class Dnn:
    def __init__(self,bin_path,proj,adj_map,lifted_ast_map,op_info):
        self.bin_path = bin_path
        self.op_map = {}
        self.op_addr_map = {}
        self.layer_map = defaultdict(set)
        self.op_id_ctr = 1
        self.new_op_addr = 1
        self.proj = proj
        self.new_op = None
        for node,children in adj_map.items():
            op = None
            if node in self.op_addr_map:
                op = self.op_addr_map[node]
            else:
                op = Operator(self.op_id_ctr,node,lifted_ast_map[node],op_info[node])
                self.op_map[self.op_id_ctr] = op
                self.op_addr_map[node] = op
                self.op_id_ctr += 1

            for child in children:
                child_op = None
                if child in self.op_addr_map:
                    child_op = self.op_addr_map[child]
                else:
                    child_op = Operator(self.op_id_ctr,child,lifted_ast_map[child],op_info[child])
                    self.op_map[self.op_id_ctr] = child_op
                    self.op_addr_map[child] = child_op
                    self.op_id_ctr += 1
                op.child.add(child_op)
                child_op.parent = op
                child_id = child_op.id
                print("Child: ", child_id, " parent: ",self.op_map[child_id].parent.id)

        for id,op in self.op_map.items():
            layer = op.getLayer()
            self.layer_map[layer].add(id)

        self.op_type_map = {
            "Conv": AST_OP.CONV,
            "FC": AST_OP.FC,
            "Relu": AST_OP.RELU,
            "MaxPool": AST_OP.MAXPOOL,
            "Add": AST_OP.ADD,
            "AveragePool": AST_OP.AVGPOOL,
            "Softmax": AST_OP.SOFTMAX
        }

        logging.getLogger("patcherex").setLevel("DEBUG")
        
        self.patcher = Patcherex(self.bin_path, target_cls=ElfArmMimxrt1052)
            
    #def printDispatcherAssembly(self):
    #    dispatcher_func = self.proj.funcs[self.proj.dispatch_addr]
    #    op_call_sites = {}
    #    for block in dispatcher_func.blocks:
    #        for insn in block.capstone.insns:
    #            print(insn)
    #        if insn.mnemonic in ["bl", "blx"]:
    #            if insn.operands:
    #                for operand in insn.operands:
    #                    target_address = operand.imm
    #                    print(
    #                        "Found call at: ",
    #                        hex(insn.address), "target: ",
    #                        hex(target_address)
    #                    )
    #                    if target_address in self.op_addr_map.keys():
    #                        op_call_sites[insn.address] = self.op_addr_map[target_address]
    #    for addr,op in op_call_sites.items():
    #        print("Op call site at ",hex(addr),": ",op.id," ",op.ast.op_type)

    def getNewDispatcher(self,new_op_sym,predecessor_op):
        dispatcher_func = self.proj.funcs[self.proj.dispatch_addr]
        #op_call_sites = {}
        if predecessor_op is None:
            assert False
            #Need to add implementation for OP added at the beginning of DNN
        dispatcher_sym = "new_dispatcher"
        asm = "new_dispatcher:\n";
        for block in dispatcher_func.blocks:
            for insn in block.capstone.insns:
                asm = asm + "  " + insn.mnemonic + " " + insn.op_str + "\n"
                #print(insn)
                if insn.mnemonic in ["bl", "blx"]:
                    if insn.operands:
                        for operand in insn.operands:
                            target_address = operand.imm
                            print(
                                "Found call at: ",
                                hex(insn.address), "target: ",
                                hex(target_address)
                            )
                            if target_address == predecessor_op.addr:
                                asm = asm + "\tpush {R0-R12}\n"
                                asm = asm + "  bl " + new_op_sym + "\n"
                                asm = asm + "\tpop {R0-R12}\n"

        return dispatcher_sym, asm

    
    def applyPatches(self):
        file_name = os.path.splitext(self.bin_path)[0]
        ext = os.path.splitext(self.bin_path)[1]
        self.patcher.apply_patches()
        self.patcher.binfmt_tool.save_binary(f"{file_name}_patched{ext}")

    def display(self):
        print("layer\top id\top type")
        for layer,operators in self.layer_map.items():
            for op_id in operators:
                op = self.op_map[op_id]
                print(layer,"\t",op_id,"\t",op.info["op"])

    def getWeights(self,op_id):
        assert op_id in self.op_map
        op = self.op_map[op_id]
        return op.weight

    def getBias(self,op_id):
        assert op_id in self.op_map
        op = self.op_map[op_id]
        return op.bias

    def getAttributes(self,op_id,attr):
        assert op_id in self.op_map
        op = self.op_map[op_id]
        info = op.info
        if attr in info:
            return info[attr]
        else:
            print("Invalid attribute name...below are the valid attributes for operator ",op.ast.op_type)
            print(op.info.keys())
        return None
    

    def createOnnxModel(self, op_list, model_name, adj_map = defaultdict(set)):
        ast_map = {}
        op_info = {}
        for op in op_list:
            ast_map[op.addr] = op.ast
            op_info[op.addr] = op.info

        export_onnx(ast_map, adj_map, op_info, model_name)

    def createTrampForNewOp(self,predecessor_op, successor_op, target_sym):
        #currently on handle ARM and currently handling only input/output buffer
        #passing.
        #Needs to be improved to pass a generic list of arguments.

        input_buffer = predecessor_op.writebuffer[0]
        output_buffer = successor_op.readbuffer[0]

        if input_buffer is None and output_buffer is None:
            print("Input/Output buffer not available")
            assert False
        elif input_buffer is None:
            input_buffer = output_buffer
        elif output_buffer is None:
            output_buffer = input_buffer
       
        low_in = input_buffer[0] & 0xffff
        high_in = (input_buffer[0] >> 16) & 0xffff

        low_out = output_buffer[0] & 0xffff
        high_out = (output_buffer[0] >> 16) & 0xffff


        tramp_sym = target_sym + "_tramp"

        asm = tramp_sym + ":\n"
        asm = asm + "  movw R0, #" + str(low_in) + "\n"
        asm = asm + "  movt R0, #" + str(high_in) + "\n"
        asm = asm + "  movw R1, #" + str(low_out) + "\n"
        asm = asm + "  movt R1, #" + str(high_out) + "\n"
        asm = asm + "\tb " + target_sym + "\n"

        return tramp_sym,asm


    def createNewOp(self, new_op_type_str, predecessor_lst = [], successor_lst = [], new_op_attr = {}):
        if new_op_type_str not in self.op_type_map:
            print("Invalid operator type: ",new_op_type_str)
            print("Valid operator names: ",self.op_type_map.keys())
            assert False
        if len(predecessor_lst) == 0 or len(successor_lst) == 0:
            print("Support for adding OP at the beginning or end of DNN is not supported yet")
            print("please supply predecessor and successor")
            assert False

        parent_op = self.op_map[predecessor_lst[0]]
        child_op = self.op_map[successor_lst[0]]

        if child_op not in parent_op.child:
            print("Predecessor and successor are not adjacent. Cannot add a node")
            assert False

        new_op_type = self.op_type_map[new_op_type_str]
        required_attr = {}
        model_name = "tmp/" + new_op_type_str + ".onnx"

        if new_op_type == AST_OP.CONV:

            assert len(new_op_attr) > 0
            if "striding" not in new_op_attr.keys():
                new_op_attr["striding"] = 1
            if "padding" not in new_op_attr.keys():
                new_op_attr["padding"] = 2

            if "kernel_height" not in new_op_attr.keys():
                print("Attribute 'kernel_height' not provided...aborting")
                return None
            if "kernel_width" not in new_op_attr.keys():
                print("Attribute 'kernel_width' not provided...aborting")
                return None
            if "bias" not in new_op_attr.keys():
                print("Attribute 'bias' not provided...aborting")
                return None
            if "weights" not in new_op_attr.keys():
                print("Attribute 'weights' not provided...aborting")
                return None
            
            print("Conv: enforcing input/output channel to be same as predecessor output_channel: ", parent_op.info["output_channel"])
            new_op_attr["input_channel"] = parent_op.info["output_channel"]
            new_op_attr["output_channel"] = parent_op.info["output_channel"]

        elif new_op_type == AST_OP.MAXPOOL or new_op_type == AST_OP.AVGPOOL or new_op_type == AST_OP.FC:
            print(
                "This operator changes output dimensions and cannot be applied using 'add operator API'. Use the API to add new layer"
            )
            assert False
        else:
            new_op_attr["input_channel"] = parent_op.info["output_channel"]
            new_op_attr["output_channel"] = parent_op.info["output_channel"]

        new_op_attr["input_height"] = parent_op.info["output_height"]
        new_op_attr["input_width"] = parent_op.info["output_width"]
        new_op_attr["output_width"] = parent_op.info["output_width"] 
        new_op_attr["output_height"] = parent_op.info["output_width"] 
        new_op_attr["op"] = new_op_type
        op = Operator(
            self.op_id_ctr, 
            -1 * self.new_op_addr,
            None,
            new_op_attr
        )
        self.op_id_ctr += 1
        self.new_op_addr += 1

        if op is not None:
            self.createOnnxModel([op], model_name)
            print("Generated ONNX: ",model_name)
            op.parent = parent_op
            for id in successor_lst:
                if id in self.op_map.keys():
                    op.child.add(self.op_map[id])
            self.new_op = NewOp(new_op_type_str,op,model_name,"tmp/" + new_op_type_str + ".o")
        else:
            assert False
        return model_name

    def addNewOp(self):
        op_asm = extractCodeBytes(self.new_op.objfile, self.new_op.name)
        tramp_sym, tramp_asm = self.createTrampForNewOp(
            self.new_op.op.parent, 
            list(self.new_op.op.child)[0], 
            self.new_op.name
        )
        dispatcher_sym, dispatcher_asm = self.getNewDispatcher(
            tramp_sym,
            self.new_op.op.parent 
        )

        op_asm = dispatcher_asm + tramp_asm + op_asm

        #print(dispatcher_asm)
        print(op_asm)
        self.patcher.patches.append(
            InsertInstructionPatch("dispatch_new", op_asm, is_thumb=True)
        )
        dispatcher_caller = self.proj.funcs[self.proj.dispatch_caller_addr]
        dispatch_call_site = None
        for block in dispatcher_caller.blocks:
            for insn in block.capstone.insns:
                if insn.mnemonic in ["bl", "blx"]:
                    if insn.operands:
                        for operand in insn.operands:
                            target_address = operand.imm
                            print(
                                "Found call at: ",
                                hex(insn.address), "target: ",
                                hex(target_address)
                            )
                            if target_address == self.proj.dispatch_addr:
                                dispatch_call_site = insn.address

        print("Dispatch call site: ",hex(dispatch_call_site))

        mask = 0xfffffffe
        self.patcher.patches.append(
            ModifyInstructionPatch(
                dispatch_call_site & mask, 
                "bl {dispatch_new}"
            )
        )


    #def changeWeight(self,op_id,index,val):
    #    w = self.getWeights(op_id) 
    #    assert w is not None
    #    assert len(index) == len(w.dimensions)

    #    for i in range(0,len(w.dimensions)):
    #        assert index[i] >= 0 and index[i] < w.dimensions[i]

    #    addrs = w.addresses
    #    for i in index:
    #        addrs = addrs[i]
    #    print("Address of index ",index,":",addrs)
    def pack_floats(self,array):
        flat_array = array.flatten()
        return struct.pack(f'{len(flat_array)}f', *flat_array)

    def changeWeight(self,op_id,weight):
        dims = weight.shape
        w = self.getWeights(op_id)
        assert len(dims) == len(w.dimensions)
        for i in range(0,len(w.dimensions)):
            assert dims[i] >= 0 and dims[i] == w.dimensions[i]
        addrs = w.address[0,0,0,0].item()
        print("patching new weights at: ",hex(addrs))
        packed_bytes = self.pack_floats(weight)
        self.patcher.patches.append(ModifyDataPatch(addrs, packed_bytes))


    def changeBias(self,op_id,bias):
        dims = len(bias)
        b = self.getBias(op_id)
        assert dims == b.size
        addrs = b.address[0].item()
        print("patching new bias at: ",hex(addrs))
        packed_bytes = self.pack_floats(bias)
        self.patcher.patches.append(ModifyDataPatch(addrs, packed_bytes))

def loadDNN(path):
    # mnist sample
    # bin_path = "./binary_samples/mnist/evkbimxrt1050_glow_lenet_mnist_release.axf"
    proj = load(path)

    # AST
    lifted_ast_map = {}
    for f in proj.analysis_funcs:
        if f not in lifted_ast_map:
            lifted_ast = lift_func_to_ast(proj, f)
            if lifted_ast:
                lifted_ast_map[f] = lifted_ast

    # recover the info necessary for topology recovery
    for ast in lifted_ast_map.values():
        ast.recover()

    # recover topology
    adj_map = recover_topology(proj, lifted_ast_map)

    # recover attributes and weights
    op_info = {}
    state = proj.factory.blank_state()
    for ast_addr, ast in lifted_ast_map.items():
        prev_info = [
            op_info[addr] for addr in adj_map.keys() if ast_addr in adj_map[addr]
        ]

        info = ast.recover_attributes(prev_info)
        info["op"] = ast.op_type
        weights, bias, weights_addr, bias_addr = ast.extract_weights(state)
        info["weights"] = weights
        info["bias"] = bias
        info["weights addrs"] = weights_addr
        info["bias addrs"] = bias_addr
        op_info[ast_addr] = info

    dnn = Dnn(path,proj,adj_map,lifted_ast_map,op_info)
    return dnn
