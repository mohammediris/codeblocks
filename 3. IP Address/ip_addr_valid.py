import sys

#Checking octets
def ip_addr_valid(ip):
"""
This function will take ip address as a string, 
split it into 4 octets and check the conditions.
if conditions are not True, it will exit the program,
if they are true it will return the boolean True
"""

    octet_list = ip.split('.')
    
    if (
        len(octet_list) == 4) and 
        1 <= int(octet_list[0]) <= 223 
        and int(octet_list[0]) != 127 
        and (int(octet_list[0]) != 169 or int(octet_list[1]) != 254)
        and 0 <= int(octet_list[1]) <= 255 
        and 0 <= int(octet_list[2]) <= 255 
        and 0 <= int(octet_list[3]) <= 255:
        continue
        return True 
    else:
        print(f"\n* The IP address {ip} is INVALID")
        sys.exit()