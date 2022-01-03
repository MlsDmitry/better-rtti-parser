import idaapi
import ida_typeinf

info = idaapi.get_inf_structure()

BIT64_MODE = info.is_64bit()

if BIT64_MODE:
    PTR_SIZE = 8
else:
    PTR_SIZE = 4
    
BAD_RET = 0xffffffffffffffff