from tkinter import *
from tkinter import filedialog

root = Tk()
root.title("test app for tkinter")
root.geometry("800x600")

file_name = ''
# opening a file in tkinter. this will open a file explorer window, once you select a file, it will return the path to the file 
def open_file():
    global file_name
    global label1
    # file_loc = filedialog.askopenfile(initialdir = "C:",title="Select a file",filetypes=(("jpeg files","*.jpg"),("all files","*.*")))
    file_loc = filedialog.askopenfile(initialdir = "C:",title="Select a file")
    file_name = file_loc.name
    file_mode = file_loc.mode
    label1.destroy()
    label1 = Label(root,text="Selected Files is : "+file_name+"  "+file_mode).grid(row=1,column=0,padx=20,pady=20)
    # print(file_loc.name)

button1 = Button(root,text="open file",command=open_file)
button1.grid(row=0,column=0,padx=200,pady=50)

label1 = Label(root,text="Selected Files is : ")
label1.grid(row=1,column=0,padx=25,pady=25)



# print(file_loc)




root.mainloop()