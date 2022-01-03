import logging

import idc
import idautils
import ida_name
import ida_ida
import ida_bytes
import idaapi
import ida_segment

from core.rtti import BasicClass, SiClass, VmiClass
from core.common import search, demangle
from core.elf import get_elf_sym_crossplatform

idaapi.require('core.binary_stream')
idaapi.require('core.vtable')
idaapi.require('core.consts')
idaapi.require('core.rtti')
idaapi.require('core.common')
idaapi.require('core.elf')


logger = logging.getLogger(__name__)


class TiClassKind:
    # CLASS_TYPE = '__class_type_info'
    CLASS_TYPE = '_ZTV3N10__cxxabiv117__class_type_infoE'
    SI_CLASS_TYPE = '_ZT4VN10__cxxabiv120__si_class_type_infoE'
    VMI_CLASS_TYPE = '_ZTV4N10__cxxabiv121__vmi_class_type_infoE'


"""
These are symbols that used to find typeinfos and vtables
"""
symbol_table = {
    TiClassKind.CLASS_TYPE: BasicClass,
    TiClassKind.SI_CLASS_TYPE: SiClass,
    TiClassKind.VMI_CLASS_TYPE: VmiClass
}

# classes = []


def process_class_info(symbol_name, ea):
    for typeinfo_ea in idautils.XrefsTo(ea, 0):

        classtype = symbol_table[symbol_name](typeinfo_ea.frm)

        logger.info(
            f'Found typeinfo for {classtype.dn_name} at {hex(typeinfo_ea.frm)}')

        classtype.read_vtable()


def process():
    for symbol_name in symbol_table:
        addr_ea = search(symbol_name)

        logger.info(f'Found {symbol_name} at {hex(addr_ea)}')

        # get only firest xref
        elf_sym_struct_ea = next(idautils.XrefsTo(addr_ea, 0), None)
        if not elf_sym_struct_ea:
            logger.error(
                f'No Code refs found for {symbol_name}'
            )
            continue

        # parse Elf<64/32>_Sym struct
        elf_sym_s = get_elf_sym_crossplatform(
            elf_sym_struct_ea.frm)

        if not elf_sym_s or elf_sym_s.st_value == idc.BADADDR:
            logger.error(
                f'No st_value in Elf Sym struct. ea: {hex(elf_sym_struct_ea.frm)}. elf_sym struct: {elf_sym_s}')
            continue

        logger.info(f'elf_sym_s address is: {hex(elf_sym_s.st_value)}')

        # 0x10 is offset to unk that always pop up in my idb
        process_class_info(symbol_name, elf_sym_s.st_value + 0x10)


def main():
    process()


if __name__ == '__main__':
    breakpoint()
    main()
