import logging

import idc
import ida_name
import idautils
import idaapi
import ida_typeinf

from core.common import create_find_struct, demangle, get_function_name, get_ida_bit_depended_stream, is_in_text_segment, is_vtable_entry, make_class_method, make_class_symbol_name, simplify_demangled_name
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

        # TODO add support for 32 binary stream
        self.stream = get_ida_bit_depended_stream(ea)
        # there is offset to class table. just ignore it by reading extra pointer ( size depended )
        self.stream.read_pointer()

        self.type_name = None
        self.dn_name = None
        self.vtable = None
        self.cls_sid = None
        self.vtable_sid = None

    def read_name(self):
        mangled_name_ea = self.stream.read_pointer()

        name = idc.get_strlit_contents(
            mangled_name_ea)
        if not name:
            logger.error(f'Could not read C-string at {hex(mangled_name_ea)}')
            return None

        # we need _ZTS prefix to make this name demanglable as string for typeinfo
        # https://github.com/gcc-mirror/gcc/blob/16e2427f50c208dfe07d07f18009969502c25dc8/gcc/cp/mangle.c#L4082 <-- code
        self.type_name = '_ZTS' + name.decode('ascii')

        self.dn_name = demangle(self.type_name)

        if not self.dn_name:
            logger.error(f'Could not demangle {self.type_name}')
            return None

        # if 'name' in self.dn_name:
        self.dn_name = self.dn_name.replace(
            "`typeinfo name for", '').replace('\'', '')

        return self.dn_name

    def read_vtable(self):
        for ref in idautils.DataRefsTo(self.ea):
            stream = get_ida_bit_depended_stream(ref - consts.PTR_SIZE)

            if stream.read_pointer() != 0:
                continue

            # ignore. typeinfo address
            stream.read_pointer()

            # get rid of off_xxx
            idc.set_name(stream.get_current_position(),
                         self.dn_name + '_vtable')

            self.vtable = Vtable(self.type_name, self.dn_name,
                                 stream.get_current_position())

            self.vtable.read()

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

    def get_class_name(self):
        return [simplify_demangled_name(self.dn_name)]

    def retype_vtable_function(self, typename, func_ea, func_name):
        new_name = make_class_symbol_name(
            func_ea, [*self.get_class_name(), func_name])
        # rename function
        idc.set_name(func_ea, new_name)
        # apply type name to function
        if make_class_method(func_ea, typename):
            logger.info(f'Applied signature to {func_name}')

    def retype_vtable_functions(self):
        for func_ea, _ in self.vtable.entries.items():

            # TODO change to something cross-platform
            if self.vtable_sid == consts.BAD_RET:
                logger.error(
                    'No structure has been created by code. Try to delete it manually for this class')
                break

            typename = idc.get_struc_name(self.vtable_sid)

            custom_name = f'sub_{func_ea:X}'
            self.retype_vtable_function(typename, func_ea, custom_name)


class SiClassFlags:
    virtual_mask = 0x1
    public_mask = 0x2
    offset_shift = 0x8


class SiClass(BasicClass):
    """
    Single-inherited class 

    :ivar base_ea:          Address to typeinfo of inherited class
    :ivar base_typename:    Demangled typename of inherited(base) class
    """

    def __init__(self, ea):
        super().__init__(ea)

        self.base_ea = None
        self.base_typename = None

    def read_typeinfo(self):
        self.base_ea = self.stream.read_pointer()
        self.base_typename = get_typeinfo_dn_name(self.base_ea)

    def get_class_name(self):
        return [
            simplify_demangled_name(self.base_typename),
            simplify_demangled_name(self.dn_name)
        ]


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

    def read_typeinfo(self):
        self.flags = self.stream.read_uint()
        self.base_count = self.stream.read_uint()

        for _ in range(self.base_count):
            base_ea = self.stream.read_pointer()
            flags = self.stream.read_pointer()

            name = get_typeinfo_dn_name(base_ea)

            logger.info(f'[{self.dn_name}] Found base class at {hex(base_ea)}')

            self.bases[base_ea] = get_typeinfo_dn_name(base_ea)

            # demangled_name = demangle(self.bases[base_ea])
            logger.info(
                f'[{self.dn_name}] Found {name} base class at {hex(base_ea)}')

    def get_class_name(self):
        parts = [simplify_demangled_name(dn_name)
                 for dn_name in self.bases.values()]
        return [*parts, simplify_demangled_name(self.dn_name)]


def get_typeinfo_dn_name(typeinfo_ea):
    classtype = BasicClass(typeinfo_ea)
    classtype.read_name()
    return classtype.dn_name
