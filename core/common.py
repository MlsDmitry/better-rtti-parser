import logging

import ida_bytes
import ida_typeinf
import idc
import ida_segment
import ida_name
import idaapi

from core.binary_stream import Ida64BinaryStream, Ida32BinaryStream
from core.consts import BIT64_MODE

logger = logging.getLogger(__name__)


def string2hex(string, encoding='ascii'):
    """
    String to hex string with space seperation for each byte. Ex: '54 64 0A'
    """
    return bytearray(string, encoding=encoding).hex(' ')


def prepare_data_for_search(data):
    if isinstance(data, str):
        hexstr = string2hex(data)
    elif isinstance(data, bytearray) or isinstance(data, bytes):
        hexstr = data.hex(' ')
    else:
        logger.error(f'Unsupported type of data {type(data)}')

    return hexstr


def search(data, start_ea=None, end_ea=None, search_flags=None) -> int:
    """
    Search data throughout idb. 

    Currently only str and bytes/bytearray types are supported!

    :param data:            data to be converted to ida_bytes.compiled_binpat_vec_t obj
    :param start_ea:        Address to start searching from
    :param end_ea:          End address
    :param search_flags:    Search flags to be passed to ida_bytes.bin_search. Default is idc.SEARCH_DOWN
    :rval:                  Address where pattern has been found as int. Be carefull, check for idc.BADADDR
    """

    if start_ea is None:
        start_ea = idc.get_inf_attr(idc.INF_MIN_EA)
    if end_ea is None:
        end_ea = idc.get_inf_attr(idc.INF_MAX_EA)
    if search_flags is None:
        search_flags = idc.SEARCH_DOWN

    pattern_obj = ida_bytes.compiled_binpat_vec_t()

    hexstr = prepare_data_for_search(data)
    logger.debug(f'Searching {data} as hexstr {hexstr}')

    ida_bytes.parse_binpat_str(pattern_obj, 0, hexstr, 16)

    return ida_bytes.bin_search(start_ea, end_ea, pattern_obj, search_flags)


def check_compiler_support():
    """
    Check if compiler is supported.

    Currently only GNU C++ is supported
    """
    return ida_typeinf.is_gcc32() or ida_typeinf.is_gcc64()


def is_in_text_segment(ea):
    text_segment = ida_segment.get_segm_by_name('.text')
    if not text_segment:
        raise Exception(
            'No text segment found thus cannot determine is address is in range of executable segment.')
    return text_segment.start_ea <= ea <= text_segment.end_ea


def get_ida_bit_depended_stream(start_ea):
    if BIT64_MODE:
        return Ida64BinaryStream(start_ea)
    else:
        return Ida32BinaryStream(start_ea)


def demangle(mangled_name):
    return ida_name.demangle_name(mangled_name, idc.get_inf_attr(idc.INF_LONG_DEMNAMES))


def get_function_name(ea):
    return idaapi.get_func_name(ea)


def is_vtable_entry(pointer):
    return is_in_text_segment(pointer)


