import tkinter as tk
from tkinter import ttk, messagebox
import math

# Baconian Cipher
def baconian_encrypt(plaintext):
    baconian_dict = {
        'A': 'AAAAA', 'B': 'AAAAB', 'C': 'AAABA', 'D': 'AAABB', 'E': 'AABAA',
        'F': 'AABAB', 'G': 'AABBA', 'H': 'AABBB', 'I': 'ABAAA', 'J': 'ABAAB',
        'K': 'ABABA', 'L': 'ABABB', 'M': 'ABBAA', 'N': 'ABBAB', 'O': 'ABBBA',
        'P': 'ABBBB', 'Q': 'BAAAA', 'R': 'BAAAB', 'S': 'BAABA', 'T': 'BAABB',
        'U': 'BABAA', 'V': 'BABAB', 'W': 'BABBA', 'X': 'BABBB', 'Y': 'BBAAA',
        'Z': 'BBAAB'
    }
    ciphertext = ''
    for char in plaintext.upper():
        if char.isalpha():
            ciphertext += baconian_dict[char]
        else:
            ciphertext += char
    return ciphertext

def baconian_decrypt(ciphertext):
    baconian_dict = {
        'AAAAA': 'A', 'AAAAB': 'B', 'AAABA': 'C', 'AAABB': 'D', 'AABAA': 'E',
        'AABAB': 'F', 'AABBA': 'G', 'AABBB': 'H', 'ABAAA': 'I', 'ABAAB': 'J',
        'ABABA': 'K', 'ABABB': 'L', 'ABBAA': 'M', 'ABBAB': 'N', 'ABBBA': 'O',
        'ABBBB': 'P', 'BAAAA': 'Q', 'BAAAB': 'R', 'BAABA': 'S', 'BAABB': 'T',
        'BABAA': 'U', 'BABAB': 'V', 'BABBA': 'W', 'BABBB': 'X', 'BBAAA': 'Y',
        'BBAAB': 'Z'
    }
    plaintext = ''
    for i in range(0, len(ciphertext), 5):
        group = ciphertext[i:i+5]
        if group in baconian_dict:
            plaintext += baconian_dict[group]
    return plaintext

# One Time Pad Cipher
def one_time_pad_encrypt(plaintext, key):
    encrypted_message = ''
    for i in range(len(plaintext)):
        encrypted_char = chr((ord(plaintext[i]) + ord(key[i])) % 256)
        encrypted_message += encrypted_char
    return encrypted_message

def one_time_pad_decrypt(ciphertext, key):
    decrypted_message = ''
    for i in range(len(ciphertext)):
        decrypted_char = chr((ord(ciphertext[i]) - ord(key[i])) % 256)
        decrypted_message += decrypted_char
    return decrypted_message

# Caesar Cipher
def caesar_encrypt(plaintext, key):
    ctext = ''
    j = 0
    for i in plaintext:
        c = (ord(i) + key) % 256
        ctext = ctext + chr(c)
        j = j + 1
    return ctext

def caesar_decrypt(ciphertext, key):
    ctext = ''
    j = 0
    for i in ciphertext:
        c = (ord(i) - key) % 256
        ctext = ctext + chr(c)
        j = j + 1
    return ctext

# Columnar Transposition Cipher
def columnar_encrypt(plaintext, key):
    cipher = ""
    col = len(key)
    msg_len = len(plaintext)
    row = math.ceil(msg_len / col)
    fill_null = int((row * col) - msg_len)
    plaintext += '_' * fill_null
   
    matrix = [plaintext[i:i+col] for i in range(0, len(plaintext), col)]
   
    for i in range(col):
        idx = key.index(sorted(key)[i])
        cipher += ''.join(row[idx] for row in matrix)
   
    return cipher

def columnar_decrypt(ciphertext, key):
    msg = ""
    col = len(key)
    row = math.ceil(len(ciphertext) / col)
    key_sorted = sorted(key)
   
    dec_cipher = [[None] * col for _ in range(row)]
   
    idx = 0
    for i in range(col):
        curr_idx = key.index(key_sorted[i])
        for j in range(row):
            dec_cipher[j][curr_idx] = ciphertext[idx]
            idx += 1
   
    msg = ''.join(''.join(row) for row in dec_cipher)
    msg = msg.rstrip('_')
   
    return msg

# Rail Fence Cipher
def rail_encrypt(plaintext, key):
 
    rail = [['\n' for i in range(len(plaintext))] for j in range(key)]
     
    dir_down = False
    row, col = 0, 0
     
    for i in range(len(plaintext)):
         
        if (row == 0) or (row == key - 1):
            dir_down = not dir_down
         
        rail[row][col] = plaintext[i]
        col += 1
         
        if dir_down:
            row += 1
        else:
            row -= 1

    result = []

    for i in range(key):
        for j in range(len(plaintext)):
            if rail[i][j] != '\n':
                result.append(rail[i][j])

    return("" . join(result))
     
def rail_decrypt(ciphertext, key):
 
    rail = [['\n' for i in range(len(ciphertext))] for j in range(key)]
     
    dir_down = None
    row, col = 0, 0
     
    for i in range(len(ciphertext)):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False
         
        rail[row][col] = '*'
        col += 1
         
        if dir_down:
            row += 1
        else:
            row -= 1
             
    index = 0

    for i in range(key):
        for j in range(len(ciphertext)):
            if ((rail[i][j] == '*') and
            (index < len(ciphertext))):
                rail[i][j] = ciphertext[index]
                index += 1
         
    result = []
    row, col = 0, 0

    for i in range(len(ciphertext)):
        if row == 0:
            dir_down = True
        if row == key-1:
            dir_down = False
             
        if (rail[row][col] != '*'):
            result.append(rail[row][col])
            col += 1
             
        if dir_down:
            row += 1
        else:
            row -= 1
    return("".join(result))

# GUI
def encrypt_button_click():
    plaintext = plaintext_text.get("1.0", "end-1c")
    key = key_text.get("1.0", "end-1c")
    selected_algorithm = algorithm_combobox.get()
    
    if not plaintext:
        messagebox.showwarning("Warning", "Please enter text to encrypt.")
        return

    if selected_algorithm == "Baconian Cipher":
        if not plaintext.isalpha():
            messagebox.showwarning("Warning", "Baconian Cipher cannot represent spaces or special characters.")
            return
        cipher_text = baconian_encrypt(plaintext)
    elif selected_algorithm == "One Time Pad Cipher":
        if not isinstance(key, str) or not key.strip():
            messagebox.showwarning("Warning", "The key for One Time Pad Cipher must be a string.")
            return
        if len(plaintext) != len(key):
            messagebox.showwarning("Warning", "The length of the key must be the same as the length of the message.")
            return
        cipher_text = one_time_pad_encrypt(plaintext, key)
    elif selected_algorithm == "Caesar Cipher":
        if not key.isdigit():
            messagebox.showwarning("Warning", "The key for Caesar Cipher must be a number.")
            return
        cipher_text = caesar_encrypt(plaintext, int(key))
    elif selected_algorithm == "Columnar Transposition Cipher":
        if not isinstance(key, str) or not key.strip():
            messagebox.showwarning("Warning", "The key for Columnar Transposition Cipher must be a string.")
            return
        cipher_text = columnar_encrypt(plaintext, key)
    elif selected_algorithm == "Rail Fence Cipher":
        if not key.isdigit():
            messagebox.showwarning("Warning", "The key for Rail Fence Cipher must be a number.")
            return
        cipher_text = rail_encrypt(plaintext, int(key))

    result_text.config(state=tk.NORMAL)
    result_text.delete('1.0', tk.END)
    result_text.insert(tk.END, f"{selected_algorithm} Encrypted: {cipher_text}\n\n")
    result_text.config(state=tk.DISABLED)

def decrypt_button_click():
    ciphertext = plaintext_text.get("1.0", "end-1c")
    key = key_text.get("1.0", "end-1c")
    selected_algorithm = algorithm_combobox.get()
    
    if not ciphertext:
        messagebox.showwarning("Warning", "Please enter text to decrypt.")
        return

    if selected_algorithm == "Baconian Cipher":
        if not ciphertext.isalpha():
            messagebox.showwarning("Warning", "Baconian Cipher cannot represent spaces or special characters.")
            return
        decrypted_text = baconian_decrypt(ciphertext)
    elif selected_algorithm == "One Time Pad Cipher":
        if not isinstance(key, str) or not key.strip():
            messagebox.showwarning("Warning", "The key for One Time Pad Cipher must be a string.")
            return
        decrypted_text = one_time_pad_decrypt(ciphertext, key)
    elif selected_algorithm == "Caesar Cipher":
        if not key.isdigit():
            messagebox.showwarning("Warning", "The key for Caesar Cipher must be a number.")
            return
        decrypted_text = caesar_decrypt(ciphertext, int(key))
    elif selected_algorithm == "Columnar Transposition Cipher":
        if not isinstance(key, str) or not key.strip():
            messagebox.showwarning("Warning", "The key for Columnar Transposition Cipher must be a string.")
            return
        decrypted_text = columnar_decrypt(ciphertext, key)
    elif selected_algorithm == "Rail Fence Cipher":
        if not key.isdigit():
            messagebox.showwarning("Warning", "The key for Rail Fence Cipher must be a number.")
            return
        decrypted_text = rail_decrypt(ciphertext, int(key))

    result_text.config(state=tk.NORMAL)
    result_text.delete('1.0', tk.END)
    result_text.insert(tk.END, f"{selected_algorithm} Decrypted: {decrypted_text}\n\n")
    result_text.config(state=tk.DISABLED)

def clear_button_click():
    plaintext_text.delete("1.0", tk.END)
    key_text.delete("1.0", tk.END)
    algorithm_combobox.set('')  
    result_text.config(state=tk.NORMAL)
    result_text.delete("1.0", tk.END)
    result_text.config(state=tk.DISABLED)

root = tk.Tk()
root.title("Cryptography Toolbox")
root.geometry("600x400")  # Set the smaller window size

style = ttk.Style()
style.configure("TLabel", font=("Arial", 12))
style.configure("TButton", font=("Arial", 12))
style.configure("TCombobox", font=("Arial", 12))
style.configure("TText", font=("Arial", 12))

main_frame = ttk.Frame(root, padding=10)
main_frame.pack(fill=tk.BOTH, expand=True)

algorithm_label = ttk.Label(main_frame, text="Select Algorithm:")
algorithm_label.pack(pady=5)

algorithms = [
    "Baconian Cipher",
    "One Time Pad Cipher",
    "Caesar Cipher",
    "Columnar Transposition Cipher",
    "Rail Fence Cipher"
]

algorithm_combobox = ttk.Combobox(main_frame, values=algorithms, width=40)
algorithm_combobox.pack(pady=5)

plaintext_label = ttk.Label(main_frame, text="Enter Text:")
plaintext_label.pack(pady=5)

plaintext_text = tk.Text(main_frame, width=60, height=2, font=("Arial", 12))
plaintext_text.pack(pady=5)

key_label = ttk.Label(main_frame, text="Enter Key:")
key_label.pack(pady=5)

key_text = tk.Text(main_frame, width=60, height=2, font=("Arial", 12))
key_text.pack(pady=5)

buttons_frame = ttk.Frame(main_frame)
buttons_frame.pack(pady=10)

encrypt_button = ttk.Button(buttons_frame, text="Encrypt", command=encrypt_button_click)
encrypt_button.pack(side=tk.LEFT, padx=5)

decrypt_button = ttk.Button(buttons_frame, text="Decrypt", command=decrypt_button_click)
decrypt_button.pack(side=tk.LEFT, padx=5)

clear_button = ttk.Button(buttons_frame, text="Clear", command=clear_button_click)
clear_button.pack(side=tk.LEFT, padx=5)

result_text = tk.Text(main_frame, height=8, width=70, font=("Arial", 12), state=tk.DISABLED, bg="#f0f0f0")
result_text.pack(pady=10)

root.mainloop()