#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from unicorn.arm64_const import *

reg_map = {
            "x0": UC_ARM64_REG_X0, 
            "x1": UC_ARM64_REG_X1, 
            "x2": UC_ARM64_REG_X2,
            "x3": UC_ARM64_REG_X3, 
            "x4": UC_ARM64_REG_X4, 
            "x5": UC_ARM64_REG_X5,
            "x6": UC_ARM64_REG_X6, 
            "x7": UC_ARM64_REG_X7, 
            "x8": UC_ARM64_REG_X8,
            "x9": UC_ARM64_REG_X9, 
            "x10": UC_ARM64_REG_X10, 
            "x11": UC_ARM64_REG_X11,
            "x12": UC_ARM64_REG_X12, 
            "x13": UC_ARM64_REG_X13, 
            "x14": UC_ARM64_REG_X14,
            "x15": UC_ARM64_REG_X15, 
            "x16": UC_ARM64_REG_X16, 
            "x17": UC_ARM64_REG_X17,
            "x18": UC_ARM64_REG_X18, 
            "x19": UC_ARM64_REG_X19, 
            "x20": UC_ARM64_REG_X20,
            "x21": UC_ARM64_REG_X21, 
            "x22": UC_ARM64_REG_X22, 
            "x23": UC_ARM64_REG_X23,
            "x24": UC_ARM64_REG_X24, 
            "x25": UC_ARM64_REG_X25, 
            "x26": UC_ARM64_REG_X26,
            "x27": UC_ARM64_REG_X27, 
            "x28": UC_ARM64_REG_X28, 
            "x29": UC_ARM64_REG_X29,
            "x30": UC_ARM64_REG_X30, 
            "w0" : UC_ARM64_REG_W0,
            "w1" : UC_ARM64_REG_W1,
            "w2" : UC_ARM64_REG_W2,
            "w3" : UC_ARM64_REG_W3,
            "w4" : UC_ARM64_REG_W4,
            "w5" : UC_ARM64_REG_W5,
            "w6" : UC_ARM64_REG_W6,
            "w7" : UC_ARM64_REG_W7,
            "w8" : UC_ARM64_REG_W8,
            "w9" : UC_ARM64_REG_W9,
            "w10" : UC_ARM64_REG_W10,
            "w11" : UC_ARM64_REG_W11,
            "w12" : UC_ARM64_REG_W12,
            "w13" : UC_ARM64_REG_W13,
            "w14" : UC_ARM64_REG_W14,
            "w15" : UC_ARM64_REG_W15,
            "w16" : UC_ARM64_REG_W16,
            "w17" : UC_ARM64_REG_W17,
            "w18" : UC_ARM64_REG_W18,
            "w19" : UC_ARM64_REG_W19,
            "w20" : UC_ARM64_REG_W20,
            "w21" : UC_ARM64_REG_W21,
            "w22" : UC_ARM64_REG_W22,
            "w23" : UC_ARM64_REG_W23,
            "w24" : UC_ARM64_REG_W24,
            "w25" : UC_ARM64_REG_W25,
            "w26" : UC_ARM64_REG_W26,
            "w27" : UC_ARM64_REG_W27,
            "w28" : UC_ARM64_REG_W28,
            "w29" : UC_ARM64_REG_W29,
            "w30" : UC_ARM64_REG_W30,
            "sp": UC_ARM64_REG_SP, 
            "pc": UC_ARM64_REG_PC,
            "cpacr_el1": UC_ARM64_REG_CPACR_EL1,
            "tpidr_el0": UC_ARM64_REG_TPIDR_EL0,
}