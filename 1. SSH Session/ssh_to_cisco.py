import paramiko
import time

# Connect to switch via ssh
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect("switch_ip", username="user", password="pass")

# Invoke shell and send commands
connection = client.invoke_shell()
connection.send("enable\n")
time.sleep(1)
connection.send("pass\n")
time.sleep(1)
connection.send("terminal length 0\n")
time.sleep(1)
connection.send("show running-config\n")
time.sleep(2)

# Receive output and close connection
output = connection.recv(10000).decode()
connection.close()
client.close()

# Save output to a file
with open("config.txt", "w") as f:
    f.write(output)