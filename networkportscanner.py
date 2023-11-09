import customtkinter
import socket
import threading
from queue import Queue

target = ''


port_list = []
queue = Queue()
open_ports = []
closed_ports = []

def button_function():
    label_status.configure(text="Program Running")
    app.update()
    global target
    global port_list
    global open_ports
    global closed_ports
    target = entry_target_host.get()
    from_port = entry_port_range_from.get()
    to_port = entry_port_range_to.get()
    port_list = list(range(int(from_port),int(to_port)))

    fill_queue(port_list)

    """
    Following code block is for creating multiple threads of the same function 
    This code block can be used seperately for other projects 
    number of threads can be specified in the range parameter 
    """
    thread_list = []

    for t in range (len(port_list)):
        thread = threading.Thread(target=worker)
        thread_list.append(thread)

    for thread in thread_list:
        thread.start()

    for thread in thread_list:
        thread.join()

    print('open ports are ', open_ports)
    print('closed ports are ',closed_ports)
    print('\n'.join(str(e) for e in open_ports))
    # app.update()
    textbox.delete("0.0", "end")
    textbox.insert("0.0", '\n'.join(str(e) for e in open_ports))
    label_status.configure(text="Program Completed")
    app.update()
def portscan(target,port):
    try:
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.connect((target,port))
        return True
    except:
        return False    
        
def fill_queue(port_list):
    for port in port_list:
        queue.put(port)

def worker():
    while not queue.empty():
        port = queue.get()
        if portscan(target,port):
            # print (f'port {port} is open\n')
            open_ports.append(port)
        else:
            # print(f'\nport {port} is closed')
            closed_ports.append(port)


customtkinter.set_appearance_mode("system")  # Modes: system (default), light, dark
customtkinter.set_default_color_theme("blue")  # Themes: blue (default), dark-blue, green

app = customtkinter.CTk()  # create CTk window like you do with the Tk window
app.geometry("350x370")
app.title("Port Scanner - schoolofiris.com")

button_start = customtkinter.CTkButton(master=app, text="START", command=button_function, width=200)
button_start.grid(row=2,column=1,columnspan=3,pady=10)
entry_target_host = customtkinter.CTkEntry(app, placeholder_text="Target host", width=200)
entry_target_host.grid(row=0,column=1,columnspan=4)
label_host_name = customtkinter.CTkLabel(app, text="Target Host", fg_color="transparent", width=100)
label_host_name.grid(row=0,column=0,pady=10)
label_port_range_from = customtkinter.CTkLabel(app, text="Port Range", fg_color="transparent", width=100)
label_port_range_from.grid(row=1,column=0,pady=10,padx=10)
entry_port_range_from = customtkinter.CTkEntry(app, width=85)
entry_port_range_from.grid(row=1,column=1,pady=10)
label_port_range_to = customtkinter.CTkLabel(app, text="To", fg_color="transparent")
label_port_range_to.grid(row=1,column=2,pady=10,padx=5)
entry_port_range_to = customtkinter.CTkEntry(app, width=90)
entry_port_range_to.grid(row=1,column=3,pady=10)
label_port_range_from = customtkinter.CTkLabel(app, text="Open Ports", fg_color="transparent", width=100)
label_port_range_from.grid(row=3,column=0,pady=10,padx=10)
textbox = customtkinter.CTkTextbox(app,height=150)
textbox.grid(row=3,column=1,columnspan=4,pady=10)
textbox.delete("0.0", "end")
label_4 = customtkinter.CTkLabel(app, text="Status", fg_color="transparent", width=100)
label_4.grid(row=4,column=0,pady=10)
label_status = customtkinter.CTkLabel(app, text="Press Start To Run", fg_color="transparent", width=100)
label_status.grid(row=4,column=1,pady=10,columnspan=3)
# textbox.configure(state="disabled")
app.mainloop()