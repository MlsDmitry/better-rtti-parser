import logging

from io import BytesIO
from dataclasses import dataclass

from rtti_parser_core.binary_stream import Ida64BinaryStream
from rtti_parser_core.consts import BIT64_MODE

import idaapi
import idautils
import ida_bytes
import ida_segment

from rtti_parser_core.common import get_ida_bit_depended_stream

logger = logging.getLogger(__name__)


@dataclass()
class Elf_Sym:
    st_name = 0
    st_info = 0
    st_other = 0
    st_shndx = 0
    st_value = 0
    st_size = 0


def read_elf_sym_crossplatform(ea):
    """
    :param ea:  Address of Elf<64/32>_Sym struct.
    :rval:      Return Elf64_Sym struct 

    References:
    https://docs.oracle.com/cd/E19683-01/816-1386/chapter6-79797/index.html
    http://web.mit.edu/freebsd/head/sys/sys/elf64.h
    """

    stream = get_ida_bit_depended_stream(ea)
    logger.info(f'mode {BIT64_MODE}')
    if BIT64_MODE:
        return read_elf64_sym(stream)
    else:
        return read_elf32_sym(stream)


def read_elf64_sym(stream):
    elfsym = Elf_Sym()

    elfsym.st_name = stream.read_uint()
    elfsym.st_info = stream.read_byte()
    elfsym.st_other = stream.read_byte()
    elfsym.st_shndx = stream.read_ushort()
    elfsym.st_value = stream.read_pointer()
    elfsym.st_size = stream.read_pointer()

    return elfsym


def read_elf32_sym(stream):
    elfsym = Elf_Sym()

    elfsym.st_name = stream.read_uint()
    elfsym.st_value = stream.read_pointer()
    elfsym.st_size = stream.read_uint()
    elfsym.st_info = stream.read_byte()
    elfsym.st_other = stream.read_byte()
    elfsym.st_shndx = stream.read_ushort()

    return elfsym


"""
32-bit

/* ELF standard typedefs (yet more proof that <stdint.h> was way overdue) */
typedef uint16_t Elf32_Half;
typedef int16_t Elf32_SHalf;
typedef uint32_t Elf32_Word;
typedef int32_t Elf32_Sword;
typedef uint64_t Elf32_Xword;
typedef int64_t Elf32_Sxword;

typedef uint32_t Elf32_Off;
typedef uint32_t Elf32_Addr;
typedef uint16_t Elf32_Section;

typedef struct elf32_sym {
    Elf32_Word st_name;
    Elf32_Addr st_value;
    Elf32_Word st_size;
    unsigned char st_info;
    unsigned char st_other;
    Elf32_Half st_shndx;
} Elf32_Sym;

64-bit

/* ELF standard typedefs (yet more proof that <stdint.h> was way overdue) */
typedef uint16_t Elf64_Half;
typedef int16_t Elf64_SHalf;
typedef uint32_t Elf64_Word;
typedef int32_t Elf64_Sword;
typedef uint64_t Elf64_Xword;
typedef int64_t Elf64_Sxword;

typedef uint64_t Elf64_Off;
typedef uint64_t Elf64_Addr;
typedef uint16_t Elf64_Section;

typedef struct elf64_sym {
    Elf64_Word st_name;
    unsigned char st_info;
    unsigned char st_other;
    Elf64_Half st_shndx;
    Elf64_Addr st_value;
    Elf64_Xword st_size;
} Elf64_Sym;
"""
