from tkinter import *
import sqlite3


def printdrop(self):
    global clicked
    a = clicked.get() # reading the current selected value
    b = clicked2.get()
    print(a)
    print(b)


root = Tk()
root.title("database practice")
clicked = StringVar()
clicked2 = StringVar()
clicked.set("Select any item") # setting the initial text
clicked2.set("Select a day")
# Drop Down Boxes
listmenu = ["mon","tue","wed"]
drop = OptionMenu(root, clicked, "monday","tuesday","friday",command=printdrop)
drop2 = OptionMenu(root, clicked2, *listmenu,command=printdrop)
drop.pack()
drop2.pack()


root.mainloop()