

def get_metaclass_name(clazz_name, prefix="__ZN"):
    name_len = 0
    method_len = 0
    m_index = 0

    for i in range(len(clazz_name)):
        index_1 = clazz_name[i]
        if index_1.isdigit():
            name_len = int(index_1)
            index_2 = clazz_name[i+1]
            if index_2.isdigit():
                name_len = int(name_len)*10 + int(index_2)
            break

    c_name = clazz_name[len(prefix) + len(str(name_len)): len(prefix) + len(str(name_len)) + name_len]

    m_index = len(prefix) + len(str(name_len)) + name_len
    for i in range(m_index, len(clazz_name)):
        index_1 = clazz_name[i]
        if index_1.isdigit():
            method_len = int(index_1)
            index_2 = clazz_name[i + 1]
            if index_2.isdigit():
                method_len = int(method_len) * 10 + int(index_2)
            break

    m_name = clazz_name[m_index+len(str(method_len)):m_index+method_len+len(str(method_len))]

    if m_name:
        return c_name + "::" + m_name
    else:
        return c_name


if __name__ == '__main__':
    str1 = "__ZTV13IOAudioEngine15dfaasdddddddddd"
    print get_metaclass_name(str1, prefix="__ZTV")