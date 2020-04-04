from tkinter import *
import hashlib
import random
from os import path
from simplecrypt import encrypt,decrypt
from cryptography.fernet import Fernet

wrong_pass_counter = 2
eye_state = True
key = b'VI-l1WNEucqblYY7R5Pvkl7BfSS5wRQu_zodUf_TiE4='

def random_pass_gen():
    char_count = 0
    f_password = ""
    upper = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
             'V', 'W', 'X', 'Y', 'Z']
    lower = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
             'v', 'w', 'x', 'y', 'z']
    num = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    symbol = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '+', '=', '|', '{', '}', '[', ']', '?', '<',
              '>', ',', '.', ':', ';']
    for character in range(12):
        if char_count<2:
            r = random.randint(0, 3)
        else:
            r = random.randint(0, 2)

        if r == 0:
            f_password += upper[random.randint(0, (len(upper) - 1))]
        elif r == 1:
            f_password += lower[random.randint(0, (len(lower) - 1))]
        elif r == 2:
            f_password += num[random.randint(0, (len(num) - 1))]
        elif r == 3:
            char_count += 1
            f_password += symbol[random.randint(0, (len(symbol) - 1))]
    return f_password


def deduct(val):
    return val - 1


def read(wc):
    def destroy_selection():
        root.destroy()
        selection()

    global wrong_pass_counter
    hash = "ab706ef3eeb56a0e81ea68995414acb9da1a3b1af7df5bce26233b771e674fff16005e632a3d8f5b5dd65d8c22fa7f8b0129ea0c8a16d3d8e78fc7f358bf5ce5"
    ueval = username.get()
    peval = password.get()
    text = str(wrong_pass_counter) + " attempts left"
    if ueval == "root" and hashlib.sha512(peval.encode()).hexdigest() == hash:
        login = Button(root, text="Login Successful", command=read, state=DISABLED)
        login.grid(column=0, row=6, columnspan=2)
        spacer = Label(root, text="                                                ")
        spacer.grid(column=0, row=7, columnspan=2)
        spacer2 = Label(root, text="                               ")
        spacer2.grid(column=0, row=8, columnspan=2)
        root.after(1000, destroy_selection)

    elif wrong_pass_counter == 0:
        login = Button(root, text="Login Failure :(", command=read, state=DISABLED)
        login.grid(column=0, row=6, columnspan=2)
        spacer = Label(root, text="                               ")
        spacer.grid(column=0, row=8, columnspan=2)
        root.after(3000, root.destroy)
    else:
        error1 = Label(root, text="Sorry that didn't work :(")
        error2 = Label(root, text=text)
        wrong_pass_counter = deduct(wc)
        error1.grid(column=0, row=7, columnspan=2)
        error2.grid(column=0, row=8, columnspan=2)


def gen_pass():
    def back():
        pgen.destroy()
        selection()
    def eye(es):
        global eye_state
        if es == False:
            pass_entry.configure(state="disabled")
            pass_entry.update()
            eye_state = True
        elif es == True:
            pass_entry.configure(state="normal")
            pass_entry.update()
            eye_state = False
    '''
    def hide(event):
        pass_entry.configure(state="disabled")
        pass_entry.update()
        #eye_state = True
    def show(event):
        pass_entry.configure(state="normal")
        pass_entry.update()
        #eye_state = False
    '''
    def Exit():
        pgen.destroy()

    def validate():
        return False

    def save_pass():
        save_button.configure(state=DISABLED)
        save_button.update()
        f = Fernet(key)
        service = f.encrypt(service_entry.get().encode()).decode()
        gpass = f.encrypt(pass_entry.get().encode()).decode()
        file = open("data.iso", "a")
        file.write(service)
        file.write(":")
        file.write(gpass)
        file.write("\n")
        file.close()

    def exec_pass():
        save_button.configure(state=NORMAL)
        save_button.update()
        passw = random_pass_gen()
        pass_entry.configure(validate="none")
        pass_entry_var.set(passw)
        pass_entry.configure(validate="key")

    pgen = Tk()
    pgen.geometry("418x278")
    pgen.title("Password Generator")
    vcmd = (pgen.register(validate))

    mainframe = Frame(pgen, borderwidth=2, highlightbackground="black", highlightthickness=1, )
    gen_button = Button(mainframe, text="Generate", padx=30, command=exec_pass)
    save_button = Button(mainframe, text="Save", padx=44, command=save_pass, state="disabled")
    exit_button = Button(mainframe, text="Exit", padx=48, command=Exit)
    back_button = Button(mainframe, text="Back", command=back)
    service_label = Label(mainframe, text="Service Name : ")
    service_entry = Entry(mainframe, width=20, borderwidth=2)
    pass_label = Label(mainframe, text="Password : ")
    pass_entry_var = StringVar(pgen, value="==Click Generate==")
    pass_entry = Entry(mainframe, width=20, borderwidth=2, state="disabled", textvariable=pass_entry_var, validatecommand=vcmd, disabledforeground="grey", disabledbackground="grey")
    eye_button = Button(mainframe, text=chr(128065), command=lambda: eye(eye_state))

    #eye_button.bind('<ButtonPress-1>', show)
    #eye_button.bind('<ButtonRelease-1>', hide)

    pass_entry.update()
    pass_entry.configure(validate="key")
    spacer = Label(pgen, text="     ")
    spacer2 = Label(mainframe, text="     ", font=16)
    spacer3 = Label(mainframe, text="     ", font=16)

    spacer.grid(column=0, row=0)
    mainframe.grid(column=1, row=1)
    spacer2.grid(column=0, row=0)
    #
    service_label.grid(column=0, row=1)
    service_entry.grid(column=1, row=1, ipady=3)
    pass_label.grid(column=0, row=2)
    pass_entry.grid(column=1, row=2, ipady=3)
    eye_button.grid(column=2, row=2)
    gen_button.grid(column=0, row=3, columnspan=3, padx=120)
    save_button.grid(column=0, row=4, columnspan=3, padx=120)
    exit_button.grid(column=0, row=5, columnspan=3, padx=120)
    spacer3.grid(column=0, row=6)
    back_button.grid(column=0, row=7, columnspan=2, sticky=SW)
    '''
    service_label.grid(column=0, row=0)
    service_entry.grid(column=1, row=0, ipady=3)
    pass_label.grid(column=0, row=1)
    pass_entry.grid(column=1, row=1, ipady=3)
    eye_button.grid(column=2, row=1)
    gen_button.grid(column=0, row=2, columnspan=3, padx=120)
    save_button.grid(column=0, row=3, columnspan=3, padx=120)
    exit_button.grid(column=0, row=4, columnspan=3, padx=120)
    #spacer2.grid(column=0, row=5)
    back_button.grid(column=0, row=6, columnspan=2, sticky=SW)
    '''

    pgen.mainloop()


def view_pass():
    vp = Tk()
    vp.geometry("400x400")
    vp.title("View Passwords")

    f = Fernet(key)
    file = open("data.iso", "r")
    data = file.readlines()
    col, row = 0, 0
    for i in range(len(data)):
        data[i] = data[i].strip()
    for each in data:
        service_hash = each[:-101]
        pass_hash = each[-100:]
        raw_service = f.decrypt(service_hash.encode()).decode()
        raw_pass = f.decrypt(pass_hash.encode()).decode()
        tcol = col + 1
        Label(vp, text=raw_service+" : ", font=12).grid(column=col, row=row)
        Label(vp, text=raw_pass, font=12).grid(column=tcol, row=row)
        row += 1

    file.close()

    vp.mainloop()


def selection():
    def kill_selection_start_gen_pass():
        choice.destroy()
        gen_pass()

    def kill_selection_start_view_pass():
        choice.destroy()
        view_pass()

    choice = Tk()
    choice.title("Landing Page")
    choice.geometry("350x250")

    select = Label(choice, text="Please select what you want to do :", font=12)
    mainframe = Frame(choice, borderwidth=2, highlightbackground="black", highlightthickness=1, padx=30, pady=35)
    spacer = Label(mainframe, text="     ")
    pass_gen = Button(mainframe, text="Generate New Password", pady=10, padx=20, command=kill_selection_start_gen_pass)
    if path.exists("data.iso"):
        pass_view = Button(mainframe, text="View Generated Password", pady=10, padx=20,
                       command=kill_selection_start_view_pass)
    elif not path.exists("data.iso"):
        pass_view = Button(mainframe, text="View Generated Password", pady=10, padx=20,
                           command=kill_selection_start_view_pass,state=DISABLED)

    select.pack()
    mainframe.pack(side=TOP, expand=YES)
    pass_gen.pack(side=TOP, expand=YES)
    spacer.pack(side=TOP, expand=YES)
    pass_view.pack(side=TOP, expand=YES)

    choice.mainloop()


root = Tk()
root.title("Login Password Manager(c0ld_z3r0)")
root.geometry("400x170")

spacer = Label(root, text="     ")
spacer2 = Label(root, text="     ")
title = Label(root, text="Master Login Password Manager", font=12)
user_label = Label(root, text="Username : ", font=10)
pass_label = Label(root, text="Password : ", font=10)
login = Button(root, text="Login", command=lambda: read(wrong_pass_counter))
username = Entry(root, width=30, borderwidth=2)
password = Entry(root, width=30, borderwidth=2, show="*")

title.grid(column=0, row=0, columnspan=2, padx=70)
spacer.grid(column=0, row=1)
user_label.grid(column=0, row=3)
username.grid(column=1, row=3, padx=0)
pass_label.grid(column=0, row=5, pady=3)
password.grid(column=1, row=5, pady=3)
login.grid(column=0, row=6, columnspan=2)

root.mainloop()
