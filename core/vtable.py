

class Vtable:
    """
    Vtable class represents vtable type in ida

    :param type_name:   Name of type which corresponds to this vtable
    :param ea:          Address of start of vtable

    :ivar entries:      Represents pointers to class virtual methods
    """
    def __init__(self, type_name, ea):
        self.type_name = type_name
        self.ea = ea
        self.entries = {}
    
    def add_entry(self, func_ea, func_name):
        self.entries[func_ea] = func_name 