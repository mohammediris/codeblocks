from tkinter import *
import sqlite3

# create function to update record
def update():
    # creating a database or connect to existing
    conn = sqlite3.connect('address_book.db')
    # create CURSOR. any connection to db request or pull is done via the cursor
    c = conn.cursor()
    record_id = delete_box.get()

    c.execute("""UPDATE addresses SET 
        firstname = :first,
        lastname = :last,
        city = :city,
        state = :state,
        zipcode = :zipcode

        WHERE oid = :oid """,
            {
                'first':f_name_editor.get(),
                'last':l_name_editor.get(),
                'address':address_editor.get(),
                'city':city_editor.get(),
                'state':state_editor.get(),
                'zipcode':zipcode_editor.get(),
                'oid':record_id
            })    

    # commit changes
    conn.commit()
    # close connection
    conn.close()
    # clear texboxes
    f_name_editor.delete(0,END)
    l_name_editor.delete(0,END)
    address_editor.delete(0,END)
    city_editor.delete(0,END)
    state_editor.delete(0,END)
    zipcode_editor.delete(0,END)

# create function to edit record
def edit_record():
    editor = Tk()
    editor.title("edit records")
    editor.geometry("400x400")

    # create global variables 
    global f_name_editor
    global l_name_editor
    global address_editor
    global city_editor
    global state_editor
    global zipcode_editor
    # create texboxes
    f_name_editor = Entry(editor,width=30)
    f_name_editor.grid(row=0,column=1,padx=20)
    l_name_editor = Entry(editor,width=30)
    l_name_editor.grid(row=1,column=1,padx=20)
    address_editor = Entry(editor,width=30)
    address_editor.grid(row=2,column=1,padx=20)
    city_editor = Entry(editor,width=30)
    city_editor.grid(row=3,column=1,padx=20)
    state_editor = Entry(editor,width=30)
    state_editor.grid(row=4,column=1,padx=20)
    zipcode_editor = Entry(editor,width=30)
    zipcode_editor.grid(row=5,column=1,padx=20)

    #create labels for textboxes
    f_name_label = Label(editor,text="First Name")
    f_name_label.grid(row=0,column=0)
    l_name_label = Label(editor,text="Second Name")
    l_name_label.grid(row=1,column=0)
    address_label = Label(editor,text="Address")
    address_label.grid(row=2,column=0)
    city_label = Label(editor,text="City")
    city_label.grid(row=3,column=0)
    state_label = Label(editor,text="State")
    state_label.grid(row=4,column=0)
    zipcode_label = Label(editor,text="zipcode")
    zipcode_label.grid(row=5,column=0)
    # create save button
    save_button = Button(editor, text="save record to database",command=update)
    save_button.grid(row=6,column=0,columnspan=2,pady=10,padx=10,ipadx=100)

    # creating a database or connect to existing
    conn = sqlite3.connect('address_book.db')
    # create CURSOR. any connection to db request or pull is done via the cursor
    c = conn.cursor()
    record_id = delete_box.get()
    # query the database
    c.execute("SELECT * FROM addresses WHERE oid = "+ record_id)
    records = c.fetchall()
    # loop through results 
    for record in records:
        f_name_editor.insert(0,record[0])
        l_name_editor.insert(0,record[1])
        address_editor.insert(0,record[2])
        city_editor.insert(0,record[3])
        state_editor.insert(0,record[4])
        zipcode_editor.insert(0,record[5])

   
    # commit changes
    conn.commit()
    # close connection
    conn.close()

# create function to delete 
def delete():
    # creating a database or connect to existing
    conn = sqlite3.connect('address_book.db')
    # create CURSOR. any connection to db request or pull is done via the cursor
    c = conn.cursor()

    # c.execute("DELETE from addresses WHERE oid=PLACEHOLDER")
    c.execute("DELETE from addresses WHERE oid=" + delete_box.get())

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
root.geometry("400x600")
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
delete_box_label = Label(root, text="Select ID")
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

# create an update button
edit_button = Button(root, text="update records",command=edit_record)
edit_button.grid(row=13,column=0,columnspan=2,pady=10,padx=10,ipadx=125)

# commit changes
conn.commit()

# close connection
conn.close()

root.mainloop()