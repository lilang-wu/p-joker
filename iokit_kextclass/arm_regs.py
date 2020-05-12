
from capstone import arm64_const

#there are 32 registers
x0 = 0
x1 = 0
x2 = 0
x3 = 0
x4 = 0
x5 = 0
x6 = 0
x7 = 0
x8 = 0
x9 = 0
x10 = 0
x11 = 0
x12 = 0
x13 = 0
x14 = 0
x15 = 0
x16 = 0
x17 = 0
x18 = 0
x19 = 0
x20 = 0
x21 = 0
x22 = 0
x23 = 0
x24 = 0
x25 = 0
x26 = 0
x27 = 0
x28 = 0
x29 = 0
x30 = 0
xzr = 0


def get_actual_value_by_regN(reg):
    #global x0
    if reg == arm64_const.ARM64_REG_X0:
        return x0
    elif reg == arm64_const.ARM64_REG_X1:
        return x1
    elif reg == arm64_const.ARM64_REG_X2:
        return x2
    elif reg == arm64_const.ARM64_REG_X3:
        return x3
    elif reg == arm64_const.ARM64_REG_X4:
        return x4
    elif reg == arm64_const.ARM64_REG_X5:
        return x5
    elif reg == arm64_const.ARM64_REG_X6:
        return x6
    elif reg == arm64_const.ARM64_REG_X7:
        return x7
    elif reg == arm64_const.ARM64_REG_X8:
        return x8
    elif reg == arm64_const.ARM64_REG_X9:
        return x9
    elif reg == arm64_const.ARM64_REG_X10:
        return x10
    elif reg == arm64_const.ARM64_REG_X11:
        return x11
    elif reg == arm64_const.ARM64_REG_X12:
        return x12
    elif reg == arm64_const.ARM64_REG_X13:
        return x13
    elif reg == arm64_const.ARM64_REG_X14:
        return x14
    elif reg == arm64_const.ARM64_REG_X15:
        return x15
    elif reg == arm64_const.ARM64_REG_X16:
        return x16
    elif reg == arm64_const.ARM64_REG_X17:
        return x17
    elif reg == arm64_const.ARM64_REG_X18:
        return x18
    elif reg == arm64_const.ARM64_REG_X19:
        return x19
    elif reg == arm64_const.ARM64_REG_X20:
        return x20
    elif reg == arm64_const.ARM64_REG_X21:
        return x21
    elif reg == arm64_const.ARM64_REG_X22:
        return x22
    elif reg == arm64_const.ARM64_REG_X23:
        return x23
    elif reg == arm64_const.ARM64_REG_X24:
        return x24
    elif reg == arm64_const.ARM64_REG_X25:
        return x25
    elif reg == arm64_const.ARM64_REG_X26:
        return x26
    elif reg == arm64_const.ARM64_REG_X27:
        return x27
    elif reg == arm64_const.ARM64_REG_X28:
        return x28
    elif reg == arm64_const.ARM64_REG_X29:
        return x29
    elif reg == arm64_const.ARM64_REG_X30:
        return x30
    elif reg == arm64_const.ARM64_REG_XZR:
        return xzr
    elif reg == arm64_const.ARM64_REG_W0:
        return x0
    elif reg == arm64_const.ARM64_REG_W1:
        return x1
    elif reg == arm64_const.ARM64_REG_W2:
        return x2
    elif reg == arm64_const.ARM64_REG_W3:
        return x3
    elif reg == arm64_const.ARM64_REG_W4:
        return x4
    elif reg == arm64_const.ARM64_REG_W5:
        return x5
    elif reg == arm64_const.ARM64_REG_W6:
        return x6
    elif reg == arm64_const.ARM64_REG_W7:
        return x7
    elif reg == arm64_const.ARM64_REG_W8:
        return x8
    elif reg == arm64_const.ARM64_REG_W9:
        return x9
    elif reg == arm64_const.ARM64_REG_W10:
        return x10
    elif reg == arm64_const.ARM64_REG_W11:
        return x11
    elif reg == arm64_const.ARM64_REG_W12:
        return x12
    elif reg == arm64_const.ARM64_REG_W13:
        return x13
    elif reg == arm64_const.ARM64_REG_W14:
        return x14
    elif reg == arm64_const.ARM64_REG_W15:
        return x15
    elif reg == arm64_const.ARM64_REG_W16:
        return x16
    elif reg == arm64_const.ARM64_REG_W17:
        return x17
    elif reg == arm64_const.ARM64_REG_W18:
        return x18
    elif reg == arm64_const.ARM64_REG_W19:
        return x19
    elif reg == arm64_const.ARM64_REG_W20:
        return x20
    elif reg == arm64_const.ARM64_REG_W21:
        return x21
    elif reg == arm64_const.ARM64_REG_W22:
        return x22
    elif reg == arm64_const.ARM64_REG_W23:
        return x23
    elif reg == arm64_const.ARM64_REG_W24:
        return x24
    elif reg == arm64_const.ARM64_REG_W25:
        return x25
    elif reg == arm64_const.ARM64_REG_W26:
        return x26
    elif reg == arm64_const.ARM64_REG_W27:
        return x27
    elif reg == arm64_const.ARM64_REG_W28:
        return x28
    elif reg == arm64_const.ARM64_REG_W29:
        return x29
    elif reg == arm64_const.ARM64_REG_W30:
        return x30
    elif reg == arm64_const.ARM64_REG_WZR:
        return xzr
    else:
        return None


def set_actual_value_by_regN(reg, reg_val):
    global x0
    global x1
    global x2
    global x3
    global x4
    global x5
    global x6
    global x7
    global x8
    global x9
    global x10
    global x11
    global x12
    global x13
    global x14
    global x15
    global x16
    global x17
    global x18
    global x19
    global x20
    global x21
    global x22
    global x23
    global x24
    global x25
    global x26
    global x27
    global x28
    global x29
    global x30
    global xzr

    if reg == arm64_const.ARM64_REG_X0:
        x0 = reg_val
    elif reg == arm64_const.ARM64_REG_X1:
        x1 = reg_val
    elif reg == arm64_const.ARM64_REG_X2:
        x2 = reg_val
    elif reg == arm64_const.ARM64_REG_X3:
        x3 = reg_val
    elif reg == arm64_const.ARM64_REG_X4:
        x4 = reg_val
    elif reg == arm64_const.ARM64_REG_X5:
        x5 = reg_val
    elif reg == arm64_const.ARM64_REG_X6:
        x6 = reg_val
    elif reg == arm64_const.ARM64_REG_X7:
        x7 = reg_val
    elif reg == arm64_const.ARM64_REG_X8:
        x8 = reg_val
    elif reg == arm64_const.ARM64_REG_X9:
        x9 = reg_val
    elif reg == arm64_const.ARM64_REG_X10:
        x10 = reg_val
    elif reg == arm64_const.ARM64_REG_X11:
        x11 = reg_val
    elif reg == arm64_const.ARM64_REG_X12:
        x12 = reg_val
    elif reg == arm64_const.ARM64_REG_X13:
        x13 = reg_val
    elif reg == arm64_const.ARM64_REG_X14:
        x14 = reg_val
    elif reg == arm64_const.ARM64_REG_X15:
        x15 = reg_val
    elif reg == arm64_const.ARM64_REG_X16:
        x16 = reg_val
    elif reg == arm64_const.ARM64_REG_X17:
        x17 = reg_val
    elif reg == arm64_const.ARM64_REG_X18:
        x18 = reg_val
    elif reg == arm64_const.ARM64_REG_X19:
        x19 = reg_val
    elif reg == arm64_const.ARM64_REG_X20:
        x20 = reg_val
    elif reg == arm64_const.ARM64_REG_X21:
        x21 = reg_val
    elif reg == arm64_const.ARM64_REG_X22:
        x22 = reg_val
    elif reg == arm64_const.ARM64_REG_X23:
        x23 = reg_val
    elif reg == arm64_const.ARM64_REG_X24:
        x24 = reg_val
    elif reg == arm64_const.ARM64_REG_X25:
        x25 = reg_val
    elif reg == arm64_const.ARM64_REG_X26:
        x26 = reg_val
    elif reg == arm64_const.ARM64_REG_X27:
        x27 = reg_val
    elif reg == arm64_const.ARM64_REG_X28:
        x28 = reg_val
    elif reg == arm64_const.ARM64_REG_X29:
        x29 = reg_val
    elif reg == arm64_const.ARM64_REG_X30:
        x30 = reg_val
    elif reg == arm64_const.ARM64_REG_XZR:
        xzr = reg_val
    elif reg == arm64_const.ARM64_REG_W0:
        x0 = reg_val
    elif reg == arm64_const.ARM64_REG_W1:
        x1 = reg_val
    elif reg == arm64_const.ARM64_REG_W2:
        x2 = reg_val
    elif reg == arm64_const.ARM64_REG_W3:
        x3 = reg_val
    elif reg == arm64_const.ARM64_REG_W4:
        x4 = reg_val
    elif reg == arm64_const.ARM64_REG_W5:
        x5 = reg_val
    elif reg == arm64_const.ARM64_REG_W6:
        x6 = reg_val
    elif reg == arm64_const.ARM64_REG_W7:
        x7 = reg_val
    elif reg == arm64_const.ARM64_REG_W8:
        x8 = reg_val
    elif reg == arm64_const.ARM64_REG_W9:
        x9 = reg_val
    elif reg == arm64_const.ARM64_REG_W10:
        x10 = reg_val
    elif reg == arm64_const.ARM64_REG_W11:
        x11 = reg_val
    elif reg == arm64_const.ARM64_REG_W12:
        x12 = reg_val
    elif reg == arm64_const.ARM64_REG_W13:
        x13 = reg_val
    elif reg == arm64_const.ARM64_REG_W14:
        x14 = reg_val
    elif reg == arm64_const.ARM64_REG_W15:
        x15 = reg_val
    elif reg == arm64_const.ARM64_REG_W16:
        x16 = reg_val
    elif reg == arm64_const.ARM64_REG_W17:
        x17 = reg_val
    elif reg == arm64_const.ARM64_REG_W18:
        x18 = reg_val
    elif reg == arm64_const.ARM64_REG_W19:
        x19 = reg_val
    elif reg == arm64_const.ARM64_REG_W20:
        x20 = reg_val
    elif reg == arm64_const.ARM64_REG_W21:
        x21 = reg_val
    elif reg == arm64_const.ARM64_REG_W22:
        x22 = reg_val
    elif reg == arm64_const.ARM64_REG_W23:
        x23 = reg_val
    elif reg == arm64_const.ARM64_REG_W24:
        x24 = reg_val
    elif reg == arm64_const.ARM64_REG_W25:
        x25 = reg_val
    elif reg == arm64_const.ARM64_REG_W26:
        x26 = reg_val
    elif reg == arm64_const.ARM64_REG_W27:
        x27 = reg_val
    elif reg == arm64_const.ARM64_REG_W28:
        x28 = reg_val
    elif reg == arm64_const.ARM64_REG_W29:
        x29 = reg_val
    elif reg == arm64_const.ARM64_REG_W30:
        x30 = reg_val
    elif reg == arm64_const.ARM64_REG_WZR:
        xzr = reg_val
    else:
        return

