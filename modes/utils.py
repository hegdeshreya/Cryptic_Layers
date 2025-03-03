import base64
from cryptography.fernet import Fernet

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

