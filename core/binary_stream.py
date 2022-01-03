
import ida_bytes


class IdaBinaryStreamBase:
    def __init__(self, start_ea):
        self.start_ea = start_ea
        self.offset = 0

    def read_byte(self) -> int:
        byte = ida_bytes.get_db_byte(self.start_ea + self.offset)
        self.offset += 1
        return byte

    def read_ushort(self) -> int:
        ushort = ida_bytes.get_word(self.start_ea + self.offset)
        self.offset += 2
        return ushort

    def read_uint(self) -> int:
        uint = ida_bytes.get_dword(self.start_ea + self.offset)
        self.offset += 4
        return uint

    def reset(self) -> None:
        self.offset = 0

    def get_current_position(self) -> int:
        return self.start_ea + self.offset


class Ida64BinaryStream(IdaBinaryStreamBase):
    def __init__(self, start_ea):
        super().__init__(start_ea)

    def read_pointer(self) -> int:
        pointer = ida_bytes.get_qword(self.start_ea + self.offset)
        self.offset += 8
        return pointer


class Ida32BinaryStream(IdaBinaryStreamBase):
    def __init__(self, start_ea):
        super().__init__(start_ea)

    def read_pointer(self) -> int:
        return self.read_uint()
