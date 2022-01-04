import logging

from collections import namedtuple

from core.common import get_function_name, get_ida_bit_depended_stream, is_vtable_entry

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
                f'New vtable entry {self.dn_name}::{get_function_name(pointer)}'
            )

            self.add_entry(pointer, get_function_name(pointer))
