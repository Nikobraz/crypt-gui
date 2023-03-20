import binascii
from tkinter import *
from crypt import encrypt, decrypt
import base64
from tkinter.messagebox import showerror


def copy(event):
    event.widget.event_generate("<<Copy>>")


def paste(event):
    event.widget.event_generate("<<Paste>>")


def cut(event):
    event.widget.event_generate("<<Cut>>")


def b64encode():
    encrypted_text.delete("1.0", 'end-1c')
    input_data = decrypted_text.get("1.0", 'end-1c')
    output_data = base64.b64encode(input_data.encode())
    encrypted_text.insert("1.0", output_data.decode('utf8'))


def b64decode():
    decrypted_text.delete("1.0", 'end-1c')
    input_data = encrypted_text.get("1.0", 'end-1c')
    try:
        output_data = base64.b64decode(input_data.encode())
    except binascii.Error:
        showerror('Error', 'Некорректные данные для расшифровки')
    decrypted_text.insert("1.0", output_data.decode('utf8'))


def aes_encode():
    encrypted_text.delete("1.0", 'end-1c')
    password = password_text.get("1.0", 'end-1c')
    input_data = decrypted_text.get("1.0", 'end-1c')
    output_data = encrypt(password, input_data.encode()).decode('utf-8')
    encrypted_text.insert("1.0", output_data)


def aes_decode():
    decrypted_text.delete("1.0", 'end-1c')
    password = password_text.get("1.0", 'end-1c')
    input_data = encrypted_text.get("1.0", 'end-1c')
    output_data = decrypt(password, input_data.encode()).decode('utf-8')
    decrypted_text.insert("1.0", output_data)


root = Tk()

# specify size of window.
root.geometry("1200x300")
root.resizable(False, False)
root.title("Crypt-GUI")

# Create text widget and specify size.
password_text = Text(root, height=1, width=32)
decrypted_text = Text(root, height=20, width=80)
encrypted_text = Text(root, height=20, width=64)

button_frame = Frame(root)
# Create button for next text.
decode_b64_button = Button(button_frame, text="Decode base64 ⬅", command=b64decode)
encode_b64_button = Button(button_frame, text="Encode base64 ➡", command=b64encode)
decode_aes_button = Button(button_frame, text="Decode AES ⬅", command=aes_decode)
encode_aes_button = Button(button_frame, text="Encode AES ➡", command=aes_encode)

password_text.grid(column=0, row=0)
decrypted_text.grid(column=0, row=1)
button_frame.grid(column=1, row=1)
decode_b64_button.pack(side="top")
encode_b64_button.pack(side="top")
decode_aes_button.pack(side="top")
encode_aes_button.pack(side="top")
encrypted_text.grid(column=2, row=1)

password_text.insert(END, "Password")
decrypted_text.insert(END, "Decrypted data")
encrypted_text.insert(END, "Encrypted data")

root.bind('<Control-c>', copy)
root.bind('<Control-v>', paste)
root.bind('<Control-x>', cut)

root.bind('<Control-Cyrillic_es>', copy)
root.bind('<Control-Cyrillic_em>', paste)
root.bind('<Control-Cyrillic_che>', cut)

if __name__ == "__main__":
    mainloop()
