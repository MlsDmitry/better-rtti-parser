from io import BytesIO
from collections import namedtuple
import logging

from core.binary_stream import Ida64BinaryStream
from core.consts import BIT64_MODE

import idaapi
import idautils
import ida_bytes
import ida_segment

from core.common import get_ida_bit_depended_stream

logger = logging.getLogger(__name__)


ElfSym = namedtuple('Elf_Sym', [
    'st_name',
    'st_info',
    'st_other',
    'st_shndx',
    'st_value',
    'st_size'
])


def get_elf_sym_crossplatform(ea):
    """
    :param ea:  Address of Elf<64/32>_Sym struct.
    :rval:      Return Elf64_Sym struct 

    References:
    https://docs.oracle.com/cd/E19683-01/816-1386/chapter6-79797/index.html
    http://web.mit.edu/freebsd/head/sys/sys/elf64.h
    """

    stream = get_ida_bit_depended_stream(ea)

    return ElfSym(
        stream.read_uint(),
        stream.read_byte(),
        stream.read_byte(),
        stream.read_ushort(),
        stream.read_pointer(),
        stream.read_pointer()
    )
