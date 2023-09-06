import tkinter as tk
from tkinter import filedialog
import aes256
import fileOs

root = tk.Tk()
root.withdraw()  


def encrypt_files(file_paths: []):
    key = aes256.generate_key()
    
    total = len(file_paths)
    count = 1
    processed = 0

    for i in file_paths:
        print("Encrypt: ", f"{count}/{total}", end='\r')

        byte_data = fileOs.file_read_bytes(i)
        
        if byte_data.data is None:
            print("file error: ", byte_data.error)
            print(i)
        else:
            encrypted_data = aes256.encrypt(key, byte_data.data)
            
            if encrypted_data.data is None:
                print("enc error: ", encrypted_data.error)
                print(i)
            else:
                fileOs.file_write_bytes(encrypted_data.data, i)
                processed += 1
        count += 1
    print("\n\n=== Complete ===\n")

    if processed > 0:
        print("\033[41m\033[97m Warning \033[0m :", "\033[38;2;255;165;0mThis key is required to decrypt your encrypted files. Keep your key safe... :)\033[0m \n")
        print("\033[41m\033[97m Your Key \033[0m :", "\033[38;2;0;255;0m", key, "\033[0m \n")


def decrypt_files(file_paths: [], key: str):
    total = len(file_paths)
    count = 1

    for i in file_paths:
        print("Decrypt: ", f"{count}/{total}", end="\r")

        byte_data = fileOs.file_read_bytes(i)
        
        if byte_data.data is None:
            print("file error: ", byte_data.error)
            print(i)
        else:
            decrypted_data = aes256.decrypt(key, byte_data.data)
            
            if decrypted_data.data is None:
                print("dec error: ", decrypted_data.error)
                print(i)
            else:
                fileOs.file_write_bytes(decrypted_data.data, i)
        
        count += 1
    print("\n\n=== Complete ===")


def select_files():
    file_paths = filedialog.askopenfilenames(
        title="Select the files",
        filetypes=(("All Files", "*.*"), ),
        initialdir="/home"
    )

    if file_paths:
        print("\nSelected files: ", len(file_paths))
        return file_paths
        
    else:
        print("No files selected")
        return False

    root.destroy()


def choose_mode():
    while True:
        mode = input("\n=== Choose Mode === \n\n To Encrypt: Type 0 and then press Enter\n To Decrypt: Type 1 and then press Enter\n To Exit: Type 2 and then press Enter \n >>>")
        if mode == "0" or mode == "1" or mode == "2":
            return mode
        else:
            print("\n--- Invalid parameter ---")

def input_key():
    return input("Input Your Key: ")


mode = choose_mode()

if mode == "0":
    print("\nEncrypt Mode Selected")

    files = select_files()

    if files is not False:
        encrypt_files(files)

elif mode == "1":
    print("\nDecrypt Mode Selected")

    key = input_key()
    files = select_files()

    if files is not False:
        decrypt_files(files, key)

elif mode == "2":
    print("See You :)")
    