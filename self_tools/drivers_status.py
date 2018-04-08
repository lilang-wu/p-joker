
class drivers(object):
    name = ""
    valid = False
    spawn = False

with open("/home/wdy/ipsw/ipsw-tools/driver_services_list_status_ipadair.txt", 'r') as driver_status:
    all_drivers = driver_status.readlines()
    for i in range(len(all_drivers)):
        if i == 0:
            continue
        each_status = all_drivers[i]
        each = each_status.split("\t")
        #print each
        if each[2].strip('\r\n') == "yes":
            print each[0]
            print each[0], each[1], each[2]
