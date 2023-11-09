"""This code is for establishing SSH connection 
to network devices such as Arista, CISCO etc"""
import paramiko
import time
import sys

username='admin'
password='python'
ip = "192.168.2.13"
commands = [] # if commands are in a text file, open then and read them to a list 
def establish_SSH(username, password, ip, commands):
    final_output = []
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, port=22, username=username, password=password)
    shell_session = client.invoke_shell()
    output = shell_session.recv(65535)
    output.decode()

    for command in commands:
        shell_session.send(command +'\n')
        time.sleep(1)
        op = shell_session.recv(65535)
        #output.append(str(op.decode()))
        final_output.append(op.decode())
        

    shell_session.close()
    shell_session.closed
    client.close()
    return final_output

outputs = establish_SSH(username, password, ip,["enable","configure terminal","show run","end"])
with open (r"D:\PyCharmCodes\Working Code Blocks\1. SSH Session\ssh_output.txt",'w') as file:
    for x in outputs:
        file.write(x)
        print(x)

sys.exit()   
    



