from capstone import x86_const


class x_reg_manager(object):

    def __init__(self):
        self.x = [1]*234
        for i in range(234):
            self.x[i] = 0


    def get_actual_value_by_regN(self, reg):
        #global x0
        return self.x[reg]



    def set_actual_value_by_regN(self, reg, reg_val):
        self.x[reg] = reg_val



