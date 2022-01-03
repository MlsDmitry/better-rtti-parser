import logging

import idc
import ida_name
import idautils
import idaapi
import ida_typeinf

from core.common import create_find_struct, demangle, get_function_name, get_ida_bit_depended_stream, is_in_text_segment, is_vtable_entry, make_class_method, simplify_demangled_name
from core import consts
from core.vtable import Vtable

logger = logging.getLogger(__name__)


class BasicClass:
    """
    Basic class does not inherit from any class

    :ivar ea:           Location of typeinfo for this class
    :ivar type_name:    Type name in mangled form
    :ivar dn_name:      Demangled type name
    :ivar vtable:       Vtable object. See core.vtable.Vtable for more details
    :ivar cls_sid:      Class struct ID from idc.add_struc
    :ivar vtable_sid:   Vtable struct ID from idc.add_struc
    """

    def __init__(self, ea):
        self.ea = ea
        assert self.ea != idc.BADADDR

        # TODO add support for 32 binary stream
        self.stream = get_ida_bit_depended_stream(ea)
        # there is offset to class table. just ignore it by reading extra pointer ( size depended )
        self.stream.read_pointer()

        self.type_name = None
        self.dn_name = None
        self.vtable = None
        self.cls_sid = None
        self.vtable_sid = None

        self.read_name()

    def read_name(self):
        mangled_name_ea = self.stream.read_pointer()

        name = idc.get_strlit_contents(
            mangled_name_ea)
        if not name:
            logger.error(f'Could not read C-string at {hex(mangled_name_ea)}')
            return

        # we need _ZTS prefix to make this name demanglable as string for typeinfo
        # https://github.com/gcc-mirror/gcc/blob/16e2427f50c208dfe07d07f18009969502c25dc8/gcc/cp/mangle.c#L4082 <-- code
        self.type_name = '_ZTS' + name.decode('ascii')

        self.dn_name = demangle(self.type_name)

        if not self.dn_name:
            logger.error(f'Could not demangle {self.type_name}')
            return

        # if 'name' in self.dn_name:
        self.dn_name = self.dn_name.replace(
            "`typeinfo name for", '').replace('\'', '')

    def read_vtable(self):
        for ref in idautils.DataRefsTo(self.ea):
            stream = get_ida_bit_depended_stream(ref - consts.PTR_SIZE)

            if stream.read_pointer() != 0:
                continue

            # ignore. typeinfo address
            stream.read_pointer()

            self.vtable = Vtable(self.type_name, stream.get_current_position())

            while True:
                pointer = stream.read_pointer()

                if not is_vtable_entry(pointer):
                    break

                logger.info(
                    f'New vtable entry {self.dn_name}::{get_function_name(pointer)}')

                self.vtable.add_entry(pointer, get_function_name(pointer))

    def read_typeinfo(self):
        """
        No additional typeinfo is present in Basic class
        """
        pass

    def create_class_struct(self):
        # remove everything before :: and inside <>
        typename = simplify_demangled_name(self.dn_name)

        self.cls_sid = create_find_struct(typename)

        return self.cls_sid

    def create_vtable_struct(self):
        # remove everything before :: and inside <>
        typename = simplify_demangled_name(self.dn_name)

        self.vtable_sid = create_find_struct(typename)

        return self.vtable_sid

    def retype_vtable_functions(self):
        for func_ea, func_name in self.vtable.entries.items():
            if not func_name or '_ZN' in func_name:
                continue

            # TODO change to something cross-platform
            if self.vtable_sid == 0xffffffffffffffff:
                logger.error(
                    'No structure has been created by code. Try to delete it manually for this class')
                break

            typename = idc.get_struc_name(self.vtable_sid)

            new_name = f'_ZN' + str(len(typename)) + typename + \
                str(len(func_name)) + func_name + 'Ev'

            # rename function
            idc.set_name(func_ea, new_name)
            # apply type name to function
            if make_class_method(func_ea, typename):
                logger.info(f'Applied signature to {func_name}')


class SiClassFlags:
    virtual_mask = 0x1
    public_mask = 0x2
    offset_shift = 0x8


class SiClass(BasicClass):
    """
    Single-inherited class 

    :ivar base_ea:          Address to typeinfo of inherited class
    """

    def __init__(self, ea):
        super().__init__(ea)

        self.base_ea = None

        self.read_typeinfo()

    def read_typeinfo(self):
        self.base_ea = self.stream.read_pointer()


class VmiClassFlags:
    non_diamond_repeat_mask = 0x1
    diamond_shaped_mask = 0x2
    flags_unknown_mask = 0x8


class VmiClass(BasicClass):
    """
    Multi-inherited class
    """

    def __init__(self, ea):
        super().__init__(ea)

        self.flags = None
        self.base_count = 0
        self.bases = {}

        self.read_typeinfo()

    def read_typeinfo(self):
        self.flags = self.stream.read_uint()
        self.base_count = self.stream.read_uint()

        for _ in range(self.base_count):
            base_ea = self.stream.read_pointer()
            flags = self.stream.read_pointer()

            name = get_typeinfo_dn_name(base_ea)

            logger.info(f'[{self.dn_name}] Found base class at {hex(base_ea)}')

            # self.bases[base_ea] = idc.get_strlit_contents(base_ea + 8).decode('ascii')

            # demangled_name = demangle(self.bases[base_ea])
            logger.info(
                f'[{self.dn_name}] Found {name} base class at {hex(base_ea)}')


def get_typeinfo_dn_name(typeinfo_ea):
    classtype = BasicClass(typeinfo_ea)
    return classtype.dn_name
