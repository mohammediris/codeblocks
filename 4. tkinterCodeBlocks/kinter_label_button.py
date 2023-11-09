from tkinter import *
from tkinter import ttk
root = Tk()

def myButton1Click():
    
    myLabel7 = Label(root,text="sample").grid(column=1,row=3)
    myLabel8 = Label(root,text= input1.get()).grid(column=1,row=5)
    


# creating a label widget
myLabel1 = Label(root, text = "Hello World!")
myLabel1.grid(column=0,row=0)
myLabel2 = Label(root, text = "My name is Mohammed Iris")
myLabel2.grid(column=2,row=0)
myLabel3 = Label(root, text = "           ")
myLabel3.grid(column=1,row=0)
# myLabel.pack()# shoving it on to the screen, 
# this just places the label in the center of the windows

myLabel4 = Label(root, text = "another way").grid(column=0,row=1)
myLabel5 = Label(root, text = "second column").grid(column=1,row=1)
myLabel6 = Label(root, text = "last column").grid(column=2,row=1)

# creating a button widget
myButton1 = Button(root,text="Click Me!",command=myButton1Click,fg="red",bg="black").grid(column=1,row=2)

# creating Entry widget
input1 = Entry(root,width=100) # use grid in seperate line for Entry
input1.insert(0,"Enter Something Here")
input1.grid(column=1,row=4)



root.mainloop()