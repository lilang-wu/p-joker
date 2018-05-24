

class Ext_Reloc(object):


    def __init__(self):
        self.r_address = 0 # 32 bit
        self.r_symbol_index = 0 # 24 bit

        self.r_pc_rel = 0 # 1 bit was relocated pc relative already
        self.r_len = 0 # 2 bit ,0=byte, 1=word, 2=long, 3=quad
        self.r_extern = 0 # 1 bit, does not include value of sym referenced
        self.r_type = 0 # 4 bit, if not 0, machine specific relocation type


    def construct_ExtReloc(self, data):
        data_str = hex(data).replace("0x", "")
        # print data_str
        self.r_address = int(data_str[-8:], 16)
        self.r_symbol_index = int(data_str[-14:-8], 16)




