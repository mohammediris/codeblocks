from tkinter import *
import sqlite3

# create function to delete 
def delete():
    # creating a database or connect to existing
    conn = sqlite3.connect('address_book.db')
    # create CURSOR. any connection to db request or pull is done via the cursor
    c = conn.cursor()

    # c.execute("DELETE from addresses WHERE oid=PLACEHOLDER")
    c.execute("DELETE from addresses WHERE oid=" +delete_box.get())

    # commit changes
    conn.commit()

    # close connection
    conn.close()


# create submit function
def submit():
    # creating a database or connect to existing
    conn = sqlite3.connect('address_book.db')
    # create CURSOR. any connection to db request or pull is done via the cursor
    c = conn.cursor()
    #Insert into table
    c.execute("INSERT INTO addresses VALUES (:f_name, :l_name, :address, :city, :state, :zipcode)",
            {
                'f_name': f_name.get(),
                'l_name': l_name.get(),
                'address' : address.get(),
                'city' :city.get(),
                'state':state.get(),
                'zipcode':zipcode.get()
            })
    # clear texboxes
    f_name.delete(0,END)
    l_name.delete(0,END)
    address.delete(0,END)
    city.delete(0,END)
    state.delete(0,END)
    zipcode.delete(0,END)
    
    # commit changes
    conn.commit()

    # close connection
    conn.close()

def query():
    # creating a database or connect to existing
    conn = sqlite3.connect('address_book.db')
    # create CURSOR. any connection to db request or pull is done via the cursor
    c = conn.cursor()

    # query the database
    c.execute("SELECT *, oid FROM addresses")
    records = c.fetchall()
    print(records)

    # Loop through results 
    print_record = ''
    for record in records:
        for single_record in record:
            # print(str(single_record))
            print_record += str(single_record)+'\n'
            show_rec_label = Label(root, text=print_record)
            show_rec_label.grid(row=12,column=0,columnspan=2)

    # commit changes
    conn.commit()

    # close connection
    conn.close()

    return

root = Tk()

# creating a database or connect to existing
conn = sqlite3.connect('address_book.db')

# create CURSOR. any connection to db request or pull is done via the cursor
c = conn.cursor()

# # create TABLE
# c.execute("""CREATE TABLE addresses (
#     firstName text,
#     lastName text,
#     address text,
#     city text,
#     state text,
#     zipcode integer
# )""")

# create texboxes
f_name = Entry(root,width=30)
f_name.grid(row=0,column=1,padx=20)
l_name = Entry(root,width=30)
l_name.grid(row=1,column=1,padx=20)
address = Entry(root,width=30)
address.grid(row=2,column=1,padx=20)
city = Entry(root,width=30)
city.grid(row=3,column=1,padx=20)
state = Entry(root,width=30)
state.grid(row=4,column=1,padx=20)
zipcode = Entry(root,width=30)
zipcode.grid(row=5,column=1,padx=20)

#create labels for textboxes
f_name_label = Label(root,text="First Name")
f_name_label.grid(row=0,column=0)
l_name_label = Label(root,text="Second Name")
l_name_label.grid(row=1,column=0)
address_label = Label(root,text="Address")
address_label.grid(row=2,column=0)
city_label = Label(root,text="City")
city_label.grid(row=3,column=0)
state_label = Label(root,text="State")
state_label.grid(row=4,column=0)
zipcode_label = Label(root,text="zipcode")
zipcode_label.grid(row=5,column=0)

delete_box = Entry(root,width=30)
delete_box.grid(row=10,column=1,pady=10)
delete_box_label = Label(root, text="ID Number")
delete_box_label.grid(row=10,column=0)

# create a delete button

delete_button = Button(root, text="delete records",command=delete)
delete_button.grid(row=11,column=0,columnspan=2,pady=10,padx=10,ipadx=125)

# create submit button
submit_button = Button(root, text="add record to database",command=submit)
submit_button.grid(row=6,column=0,columnspan=2,pady=10,padx=10,ipadx=100)

# create a qurey button
query_button = Button(root, text="show records",command=query)
query_button.grid(row=7,column=0,columnspan=2,pady=10,padx=10,ipadx=125)

# commit changes
conn.commit()

# close connection
conn.close()

root.mainloop()