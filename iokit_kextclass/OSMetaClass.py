
class OSMetaClass(object):

    def __init__(self):

        self.class_self_addr = 0
        self.class_super_addr = 0
        self.class_size = 0

        self.class_name = ""
        self.class_super_name = ""

        self.metaclass_vt_vm = 0
        self.metaclass_vt_f = 0

        self.object_vt_vm = 0
        self.object_vt_f = 0

        self.instance_list = list()
        self.metaclass_list = list()
