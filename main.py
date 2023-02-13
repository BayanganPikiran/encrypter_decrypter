from tkinter import *
from tkinter import messagebox
import pybase64

# -----------------------------ROOT WINDOW------------------------------ #
window = Tk()
window.geometry = "600x400"
window.resizable(width=False, height=False)
window.configure(background="#EFF5F5", highlightthickness=3, highlightcolor="green", padx=20, pady=20)
window.title("Andre's Encrypter-Decrypter")

# -------------------------------FUNCTIONS------------------------------ #


def encrypt():
    # get the message
    secret = message.get(1.0, END)
    # clear the message textbox
    message.delete(1.0, END)

    # logic for password
    if password_entry.get() == "password":
        # convert to byte
        secret = secret.encode("ascii")
        # convert to base64
        secret = pybase64.b64encode(secret)
        # convert it back to ascii
        secret = secret.decode("ascii")
        # print to textbox
        message.insert(END, secret)
    else:
        # flashes a message if the password is wrong
        messagebox.showwarning("Password Error", "Incorrect password, try again.")


def decrypt():
    # get text from message textbox
    secret = message.get(1.0, END)
    # clear message
    message.delete(1.0, END)
    if password_entry.get() == "password":
        # convert to byte
        secret = secret.encode("ascii")
        # convert to base64
        secret = pybase64.b64decode(secret)
        # convert it back to ascii
        secret = secret.decode("ascii")
        # print to textbox
        message.insert(END, secret)
    else:
        messagebox.showwarning("Password Error", "Incorrect password, try again.")


def clear():
    message.delete(1.0, END)
    password_entry.delete(0, END)


# --------------------------------LABELS-------------------------------- #
header_label = Label(text="Dre's Encrypter-Decrypter", background="#EFF5F5", font=("helvetica", 16))
password_label = Label(text="Password", background="#EFF5F5", font=("helvetica", 14))
message_label = Label(text="Message", background="#EFF5F5", font=("helvetica", 14))

# --------------------------------FRAME--------------------------------- #
frame = Frame(window, width=200, height=80)

encrypt_btn = Button(frame, text="Encrypt", font=("helvetica", 14, "bold"), padx=10, command=encrypt)
decrypt_btn = Button(frame, text="Decrypt", font=("helvetica", 14, "bold"), padx=10, command=decrypt)
clear_btn = Button(frame, text="Clear", font=("helvetica", 14, "bold"), padx=10, command=clear)

encrypt_btn.grid(row=0, column=0)
decrypt_btn.grid(row=0, column=1)
clear_btn.grid(row=0, column=2)

# ---------------------------------TEXT---------------------------------- #
message = Text(window, width=50, height=10)


# ---------------------------------ENTRY--------------------------------- #

password_entry = Entry(width=50, show="*")


# ---------------------------------PACKS--------------------------------- #
header_label.pack(pady=5)
frame.pack(pady=5)
message_label.pack(pady=5)
message.pack(pady=5)
password_label.pack(pady=5)
password_entry.pack()


window.mainloop()