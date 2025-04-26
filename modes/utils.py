
import base64
import math
from cryptography.fernet import Fernet
from flask import flash
# Caesar Cipher
def caesar_encrypt(text, shift=3):
    return ''.join(chr((ord(char) + shift) % 256) for char in text)

def caesar_decrypt(text, shift=3):
    return ''.join(chr((ord(char) - shift) % 256) for char in text)

# Vigenère Cipher
def vigenere_encrypt(text, key):
    key = (key * (len(text) // len(key))) + key[:len(text) % len(key)]
    return ''.join(chr((ord(t.upper()) - 65 + ord(k.upper()) - 65) % 26 + 65) for t, k in zip(text, key))

def vigenere_decrypt(text, key):
    key = (key * (len(text) // len(key))) + key[:len(text) % len(key)]
    return ''.join(chr((ord(t.upper()) - ord(k.upper()) + 26) % 26 + 97) for t, k in zip(text, key))

# AES Encryption (Fernet)
def aes_encrypt(text, key=None):
    if key is None:
        key = Fernet.generate_key()  # Generate a new key if not provided
    else:
        key = base64.urlsafe_b64decode(key)  # Decode base64 key if provided

    cipher = Fernet(key)
    encrypted_text = cipher.encrypt(text.encode())

    return encrypted_text.decode(), base64.urlsafe_b64encode(key).decode()  # Return encrypted text and encoded key

def aes_decrypt(encrypted_text, key):
    try:
        key = base64.urlsafe_b64decode(key)  # Decode the base64 key
        cipher = Fernet(key)
        decrypted_text = cipher.decrypt(encrypted_text.encode()).decode()
        return decrypted_text
    except Exception:
        return "Decryption failed (invalid key or data)"

# Columnar Transposition Cipher
def columnar_encrypt(text, key):
    key_order = sorted(list(key))  # Sorting the key to determine column order
    col_order = [key.index(k) for k in key_order]  # Getting index positions of key letters

    num_cols = len(key)
    num_rows = math.ceil(len(text) / num_cols)

    # Create an empty grid
    grid = [['' for _ in range(num_cols)] for _ in range(num_rows)]

    # Fill the grid row-wise
    index = 0
    for r in range(num_rows):
        for c in range(num_cols):
            if index < len(text):
                grid[r][c] = text[index]
                index += 1

    # Read columns in key order
    ciphertext = ''.join(''.join([row[c] for row in grid]) for c in col_order)
    return ciphertext

def columnar_decrypt(ciphertext, key):
    if key=='':
        #flash("Columnar cipher key is required!", "error")
        key="key"
    key_order = sorted(list(key))  
    col_order = [key.index(k) for k in key_order]  

    num_cols = len(key)
    num_rows = math.ceil(len(ciphertext) / num_cols)

    # Create an empty grid for decryption
    grid = [['' for _ in range(num_cols)] for _ in range(num_rows)]

    # Fill the grid column-wise
    index = 0
    for c in col_order:  
        for r in range(num_rows):
            if index < len(ciphertext):
                grid[r][c] = ciphertext[index]
                index += 1

    # Read row-wise to reconstruct the original message
    plaintext = ''.join(''.join(row) for row in grid)
    return plaintext