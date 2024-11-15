from tkinter import *
from tkinter import filedialog, messagebox
from tkinter.ttk import Frame, Label, Entry, Button, Combobox
from Crypto.Cipher import DES, AES
from Crypto.Random import get_random_bytes
import base64
import math
import os

# Funkcje szyfrowania i deszyfrowania tekstu

# Monoalfabetyczny szyfr
def monoalphabetic_cipher(text, key):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    key = ''.join(sorted(set(key), key=lambda x: key.index(x)))  # Usuwamy duplikaty z klucza, aby uzyskać unikalny ciąg
    permuted_alphabet = key + ''.join([c for c in alphabet if c not in key])
    cipher_text = ''
    for char in text.upper():
        if char in alphabet:
            cipher_text += permuted_alphabet[alphabet.index(char)]
        else:
            cipher_text += char
    return cipher_text

def monoalphabetic_decipher(text, key):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    # Tworzenie unikalnego klucza
    key = ''.join(sorted(set(key), key=lambda x: key.index(x)))
    if not key or not all(c.isalpha() for c in key):
        raise ValueError("Nieprawidłowy klucz: musi zawierać wyłącznie litery alfabetu.")

    # Generowanie permutowanego alfabetu
    permuted_alphabet = key + ''.join([c for c in alphabet if c not in key])

    deciphered_text = ''
    for char in text.upper():
        if char in permuted_alphabet:
            deciphered_text += alphabet[permuted_alphabet.index(char)]
        else:
            deciphered_text += char  # Zostawiamy znaki spoza alfabetu bez zmian
    return deciphered_text
# Polialfabetyczny szyfr (np. Vigenere)
def polyalphabetic_cipher(text, key):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    cipher_text = ''
    key_index = 0
    for char in text.upper():
        if char in alphabet:
            shift = alphabet.index(key[key_index % len(key)].upper())
            cipher_text += alphabet[(alphabet.index(char) + shift) % 26]
            key_index += 1
        else:
            cipher_text += char
    return cipher_text

def polyalphabetic_decipher(text, key):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    deciphered_text = ''
    key_index = 0
    for char in text.upper():
        if char in alphabet:
            shift = alphabet.index(key[key_index % len(key)].upper())
            deciphered_text += alphabet[(alphabet.index(char) - shift) % 26]
            key_index += 1
        else:
            deciphered_text += char
    return deciphered_text

# Transpozycja spiralna
def circular_spiral_transposition(text):
    n = math.ceil(math.sqrt(len(text)))
    grid = [['' for _ in range(n)] for _ in range(n)]
    idx = 0
    
    # Wypełniamy siatkę znakami tekstu
    for i in range(n):
        for j in range(n):
            if idx < len(text):
                grid[i][j] = text[idx]
                idx += 1
            else:
                grid[i][j] = ' '  # Uzupełniamy siatkę spacjami
    
    cipher_text = ""

    # Odczytujemy znaki w spiralnej kolejności
    left, right, top, bottom = 0, n - 1, 0, n - 1
    while left <= right and top <= bottom:
        # Góra (od lewej do prawej)
        for i in range(left, right + 1):
            if grid[top][i] != ' ':
                cipher_text += grid[top][i]
        top += 1
        # Prawa (od góry do dołu)
        for i in range(top, bottom + 1):
            if grid[i][right] != ' ':
                cipher_text += grid[i][right]
        right -= 1
        # Dół (od prawej do lewej)
        if top <= bottom:
            for i in range(right, left - 1, -1):
                if grid[bottom][i] != ' ':
                    cipher_text += grid[bottom][i]
            bottom -= 1
        # Lewa (od dołu do góry)
        if left <= right:
            for i in range(bottom, top - 1, -1):
                if grid[i][left] != ' ':
                    cipher_text += grid[i][left]
            left += 1

    return cipher_text

def circular_spiral_detransposition(cipher_text):
    n = math.ceil(math.sqrt(len(cipher_text)))
    grid = [['' for _ in range(n)] for _ in range(n)]
    idx = 0

    # Wypełniamy siatkę w kolejności spiralnej
    left, right, top, bottom = 0, n - 1, 0, n - 1
    while left <= right and top <= bottom:
        # Góra (od lewej do prawej)
        for i in range(left, right + 1):
            if idx < len(cipher_text):
                grid[top][i] = cipher_text[idx]
                idx += 1
        top += 1
        # Prawa (od góry do dołu)
        for i in range(top, bottom + 1):
            if idx < len(cipher_text):
                grid[i][right] = cipher_text[idx]
                idx += 1
        right -= 1
        # Dół (od prawej do lewej)
        if top <= bottom:
            for i in range(right, left - 1, -1):
                if idx < len(cipher_text):
                    grid[bottom][i] = cipher_text[idx]
                    idx += 1
            bottom -= 1
        # Lewa (od dołu do góry)
        if left <= right:
            for i in range(bottom, top - 1, -1):
                if idx < len(cipher_text):
                    grid[i][left] = cipher_text[idx]
                    idx += 1
            left += 1

    # Odczytujemy tekst wierszami, aby go zdeszyfrować
    deciphered_text = ''.join([''.join(row) for row in grid]).replace(' ', '')
    return deciphered_text

# Funkcje DES i AES (blokowe i strumieniowe)
def des_encrypt_block(data, key):
    des = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    padding_length = 8 - (len(data) % 8)
    padded_data = data + bytes([padding_length]) * padding_length
    cipher_text = des.encrypt(padded_data)
    return base64.b64encode(cipher_text).decode('utf-8')

def des_decrypt_block(data, key):
    des = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    decoded_data = base64.b64decode(data)
    decrypted_data = des.decrypt(decoded_data)
    padding_length = decrypted_data[-1]
    return decrypted_data[:-padding_length].decode('utf-8')

def aes_encrypt_block(data, key):
    aes = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    padding_length = 16 - (len(data) % 16)
    padded_data = data + bytes([padding_length]) * padding_length
    cipher_text = aes.encrypt(padded_data)
    return base64.b64encode(cipher_text).decode('utf-8')

def aes_decrypt_block(data, key):
    aes = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    decoded_data = base64.b64decode(data)
    decrypted_data = aes.decrypt(decoded_data)
    padding_length = decrypted_data[-1]
    return decrypted_data[:-padding_length].decode('utf-8')

def des_encrypt_stream(data, key):
    iv = get_random_bytes(8)
    des = DES.new(key.encode('utf-8'), DES.MODE_CFB, iv=iv)
    cipher_text = iv + des.encrypt(data)
    return base64.b64encode(cipher_text).decode('utf-8')

def des_decrypt_stream(data, key):
    decoded_data = base64.b64decode(data)
    iv = decoded_data[:8]
    encrypted_data = decoded_data[8:]
    des = DES.new(key.encode('utf-8'), DES.MODE_CFB, iv=iv)
    return des.decrypt(encrypted_data) 

def aes_encrypt_stream(data, key):
    iv = get_random_bytes(16)
    aes = AES.new(key.encode('utf-8'), AES.MODE_CFB, iv=iv)
    cipher_text = iv + aes.encrypt(data)
    return base64.b64encode(cipher_text).decode('utf-8')

def aes_decrypt_stream(data, key):
    decoded_data = base64.b64decode(data)
    iv = decoded_data[:16]
    encrypted_data = decoded_data[16:]
    aes = AES.new(key.encode('utf-8'), AES.MODE_CFB, iv=iv)
    return aes.decrypt(encrypted_data) 
    
# Funkcje do szyfrowania i deszyfrowania tekstu
def encrypt_text():
    text = text_box.get("1.0", END).strip()
    key = key_entry.get().strip()
    encryption_type = encryption_var.get()

    if encryption_type == "Monoalfabetyczna":
        result = monoalphabetic_cipher(text, key)
    elif encryption_type == "Polialfabetyczna":
        result = polyalphabetic_cipher(text, key)
    elif encryption_type == "DES - blokowy":
        if len(key) != 8:
            messagebox.showerror("Błąd", "Klucz DES musi mieć dokładnie 8 znaków.")
            return
        result = des_encrypt_block(text.encode('utf-8'), key)
    elif encryption_type == "AES - blokowy":
        if len(key) not in [16, 24, 32]:
            messagebox.showerror("Błąd", "Klucz AES musi mieć 16, 24 lub 32 znaki.")
            return
        result = aes_encrypt_block(text.encode('utf-8'), key)
    elif encryption_type == "DES - strumieniowy":
        if len(key) != 8:
            messagebox.showerror("Błąd", "Klucz DES musi mieć dokładnie 8 znaków.")
            return
        result = des_encrypt_stream(text.encode('utf-8'), key)
    elif encryption_type == "AES - strumieniowy":
        if len(key) not in [16, 24, 32]:
            messagebox.showerror("Błąd", "Klucz AES musi mieć 16, 24 lub 32 znaki.")
            return
        result = aes_encrypt_stream(text.encode('utf-8'), key)
    elif encryption_type == "TranspozycjaKoło":
        result = circular_spiral_transposition(text)
    else:
        messagebox.showerror("Błąd", "Wybierz odpowiedni tryb szyfrowania.")
        return

    messagebox.showinfo("Zaszyfrowany tekst", result)

def decrypt_text():
    text = text_box.get("1.0", END).strip()
    key = key_entry.get().strip()
    encryption_type = encryption_var.get()

    if encryption_type == "Monoalfabetyczna":
        result = monoalphabetic_decipher(text, key)
    elif encryption_type == "Polialfabetyczna":
        result = polyalphabetic_decipher(text, key)
    elif encryption_type == "DES - blokowy":
        result = des_decrypt_block(text, key)
    elif encryption_type == "AES - blokowy":
        result = aes_decrypt_block(text, key)
    elif encryption_type == "DES - strumieniowy":
        result = des_decrypt_stream(text, key)
    elif encryption_type == "AES - strumieniowy":
        result = aes_decrypt_stream(text, key)
    elif encryption_type == "TranspozycjaKoło":
        result = circular_spiral_detransposition(text)
    else:
        messagebox.showerror("Błąd", "Wybierz odpowiedni tryb szyfrowania.")
        return

    messagebox.showinfo("Deszyfrowany tekst", result)

# Funkcje do szyfrowania i deszyfrowania plików
def encrypt_file():
    file_path = filedialog.askopenfilename()
    key = key_entry.get().strip()
    encryption_type = encryption_var.get()

    if not file_path or not key:
        messagebox.showerror("Błąd", "Proszę wybrać plik i podać klucz.")
        return

    with open(file_path, "r", encoding="utf-8") as f:
        data = f.read()

    try:
        if encryption_type == "DES - blokowy":
            encrypted_data = des_encrypt_block(data.encode('utf-8'), key)
        elif encryption_type == "AES - blokowy":
            encrypted_data = aes_encrypt_block(data.encode('utf-8'), key)
        elif encryption_type == "DES - strumieniowy":
            encrypted_data = des_encrypt_stream(data.encode('utf-8'), key)
        elif encryption_type == "AES - strumieniowy":
            encrypted_data = aes_encrypt_stream(data.encode('utf-8'), key)
        elif encryption_type == "Monoalfabetyczna":
            encrypted_data = monoalphabetic_cipher(data, key)
        elif encryption_type == "Polialfabetyczna":
            encrypted_data = polyalphabetic_cipher(data, key)
        elif encryption_type == "TranspozycjaKoło":
            encrypted_data = circular_spiral_transposition(data)
        else:
            messagebox.showerror("Błąd", "Wybierz odpowiedni tryb szyfrowania.")
            return
    except Exception as e:
        messagebox.showerror("Błąd", f"Nie udało się zaszyfrować pliku: {e}")
        return

    new_file_path = file_path + ".enc"
    with open(new_file_path, "w", encoding="utf-8") as f:
        f.write(encrypted_data)

    messagebox.showinfo("Szyfrowanie zakończone", f"Plik zaszyfrowano pomyślnie jako {new_file_path}")

def decrypt_file():
    file_path = filedialog.askopenfilename()
    key = key_entry.get().strip()
    encryption_type = encryption_var.get()

    if not file_path or not key:
        messagebox.showerror("Błąd", "Proszę wybrać plik i podać klucz.")
        return

    with open(file_path, "r", encoding="utf-8") as f:
        data = f.read()

    try:
        if encryption_type == "DES - blokowy":
            decrypted_data = des_decrypt_block(data, key)
        elif encryption_type == "AES - blokowy":
            decrypted_data = aes_decrypt_block(data, key)
        elif encryption_type == "DES - strumieniowy":
            decrypted_data = des_decrypt_stream(data, key)
        elif encryption_type == "AES - strumieniowy":
            decrypted_data = aes_decrypt_stream(data, key)
        elif encryption_type == "Monoalfabetyczna":
            decrypted_data = monoalphabetic_decipher(data, key)
        elif encryption_type == "Polialfabetyczna":
            decrypted_data = polyalphabetic_decipher(data, key)
        elif encryption_type == "TranspozycjaKoło":
            decrypted_data = circular_spiral_detransposition(data)
        else:
            messagebox.showerror("Błąd", "Wybierz odpowiedni tryb deszyfrowania.")
            return
    except Exception as e:
        messagebox.showerror("Błąd", f"Nie udało się zdeszyfrować pliku: {e}")
        return

    new_file_path = file_path.replace(".enc", "_dec")
    with open(new_file_path, "w", encoding="utf-8") as f:
        f.write(decrypted_data)

    messagebox.showinfo("Deszyfrowanie zakończone", f"Plik deszyfrowano pomyślnie jako {new_file_path}")
# Interfejs graficzny (GUI)

root = Tk()
root.title("Aplikacja Szyfrowania i Deszyfrowania")
root.geometry("600x700")

frame = Frame(root, padding="15", relief="ridge", borderwidth=3)
frame.pack(fill=BOTH, expand=True, padx=20, pady=20)

header_label = Label(frame, text="Aplikacja Szyfrowania i Deszyfrowania", font=("Arial", 16, "bold"))
header_label.pack(pady=(0, 10))

text_label = Label(frame, text="Tekst:", font=("Arial", 10))
text_label.pack(anchor=W)
text_box = Text(frame, height=8, width=50, font=("Arial", 10))
text_box.pack(pady=(0, 10))

key_label = Label(frame, text="Klucz:", font=("Arial", 10))
key_label.pack(anchor=W)
key_entry = Entry(frame, font=("Arial", 10))
key_entry.pack(fill=X, pady=(0, 10))

encryption_var = StringVar(root)
encryption_var.set("DES - blokowy")
encryption_label = Label(frame, text="Rodzaj szyfrowania:", font=("Arial", 10))
encryption_label.pack(anchor=W)
encryption_options = Combobox(frame, textvariable=encryption_var, font=("Arial", 10), state="readonly")
encryption_options["values"] = [
    "Monoalfabetyczna", "Polialfabetyczna",
    "DES - blokowy", "AES - blokowy",
    "DES - strumieniowy", "AES - strumieniowy",
    "Transpozycja spiralna"
]
encryption_options.pack(fill=X, pady=(0, 10))

encrypt_button = Button(frame, text="Szyfruj tekst", command=encrypt_text)
encrypt_button.pack(pady=(5, 10))

decrypt_button = Button(frame, text="Deszyfruj tekst", command=decrypt_text)
decrypt_button.pack(pady=(5, 10))

encrypt_file_button = Button(frame, text="Szyfruj plik", command=encrypt_file)
encrypt_file_button.pack(pady=(5, 10))

decrypt_file_button = Button(frame, text="Deszyfruj plik", command=decrypt_file)
decrypt_file_button.pack(pady=(5, 10))

root.mainloop()
