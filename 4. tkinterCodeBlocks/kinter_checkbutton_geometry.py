from tkinter import *

def print_var():
    print(checkbutton_var.get())
    print(clicked.get())

root = Tk()
root.title('checkbox')
root.geometry('800x400')
checkbutton_var = IntVar()
c = Checkbutton(root,text="this is a checkbox",variable=checkbutton_var,command=print_var)
c.grid(row=0,column=0)

print(checkbutton_var.get())
clicked = StringVar()
drop = OptionMenu(root, clicked, "monday","tuesday","wednesday","thursday","friday")
# drop = OptionMenu(root, clicked, options ,command=print_var)

drop.grid(row=1,column=0)
root.mainloop()