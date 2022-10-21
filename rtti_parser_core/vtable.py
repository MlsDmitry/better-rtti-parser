import logging

from collections import namedtuple

from rtti_parser_core.common import get_function_name, get_ida_bit_depended_stream, is_vtable_entry, demangle

logger = logging.getLogger(__name__)


class Vtable:
    """
    Vtable class represents vtable type in ida

    :param type_name:   Name of type which corresponds to this vtable
    :param ea:          Address of start of vtable

    :ivar entries:      Represents pointers to class virtual methods
    :ivar dn_name:      Demangled type name
    """

    def __init__(self, type_name, dn_name, ea):
        self.type_name = type_name
        self.dn_name = dn_name
        self.ea = ea

        self.stream = get_ida_bit_depended_stream(ea)
        self.entries = {}

    def add_entry(self, func_ea, func_name):
        self.entries[func_ea] = func_name

    def read(self):
        while True:
            pointer = self.stream.read_pointer()

            if not is_vtable_entry(pointer):
                break

            logger.info(
                f'New vtable entry {self.dn_name}::{demangle(get_function_name(pointer))}'
            )

            self.add_entry(pointer, get_function_name(pointer))


class TypeInfoVtable(Vtable):
    def __init__(self, type_name, dn_name, ea):
        super().__init__(type_name, dn_name, ea)

        self.typeinfo_ea = None
        self.typeinfo_offset_ea = None
        self.vfuncs = []

    def read(self):
        # skip base offset and virtual base offset
        self.stream.read_pointer()
        # read typeinfo address
        self.typeinfo_ea = self.stream.read_pointer()
        # there is offset that used in all other typeinfos
        self.typeinfo_offset_ea = self.stream.get_current_position()
        # destructor
        self.stream.read_pointer()

        while True:
            func_ea = self.stream.read_pointer()

            if not is_vtable_entry(func_ea):
                break

            self.vfuncs.append(func_ea)
