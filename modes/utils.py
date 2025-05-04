import base64
import math
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Existing ciphers (unchanged)
def caesar_encrypt(text, shift=3):
    return ''.join(chr((ord(char) + shift) % 256) for char in text)

def caesar_decrypt(text, shift=3):
    return ''.join(chr((ord(char) - shift) % 256) for char in text)

def vigenere_encrypt(text, key):
    key = (key * (len(text) // len(key))) + key[:len(text) % len(key)]
    return ''.join(chr((ord(t.upper()) - 65 + ord(k.upper()) - 65) % 26 + 65) for t, k in zip(text, key))

def vigenere_decrypt(text, key):
    key = (key * (len(text) // len(key))) + key[:len(text) % len(key)]
    return ''.join(chr((ord(t.upper()) - ord(k.upper()) + 26) % 26 + 97) for t, k in zip(text, key))

def aes_encrypt(text, key=None):
    if key is None:
        key = Fernet.generate_key()
    else:
        key = base64.urlsafe_b64decode(key)
    cipher = Fernet(key)
    encrypted_text = cipher.encrypt(text.encode())
    return encrypted_text.decode(), base64.urlsafe_b64encode(key).decode()

def aes_decrypt(encrypted_text, key):
    try:
        key = base64.urlsafe_b64decode(key)
        cipher = Fernet(key)
        decrypted_text = cipher.decrypt(encrypted_text.encode()).decode()
        return decrypted_text
    except Exception:
        return "Decryption failed (invalid key or data)"

def columnar_encrypt(text, key):
    key_order = sorted(list(key))
    col_order = [key.index(k) for k in key_order]
    num_cols = len(key)
    num_rows = math.ceil(len(text) / num_cols)
    grid = [['' for _ in range(num_cols)] for _ in range(num_rows)]
    index = 0
    for r in range(num_rows):
        for c in range(num_cols):
            if index < len(text):
                grid[r][c] = text[index]
                index += 1
    ciphertext = ''.join(''.join([row[c] for row in grid]) for c in col_order)
    return ciphertext

def columnar_decrypt(ciphertext, key):
    if key == '':
        key = "key"
    key_order = sorted(list(key))
    col_order = [key.index(k) for k in key_order]
    num_cols = len(key)
    num_rows = math.ceil(len(ciphertext) / num_cols)
    grid = [['' for _ in range(num_cols)] for _ in range(num_rows)]
    index = 0
    for c in col_order:
        for r in range(num_rows):
            if index < len(ciphertext):
                grid[r][c] = ciphertext[index]
                index += 1
    plaintext = ''.join(''.join(row) for row in grid)
    return plaintext

# ECC Asymmetric Encryption
def ecc_generate_keys():
    """
    Generate ECC public and private key pair using SECP256R1 curve.
    Returns: (public_key_pem, private_key_pem) as base64-encoded strings.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    
    # Serialize private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Encode as base64 for easy handling
    return (base64.urlsafe_b64encode(public_pem).decode(),
            base64.urlsafe_b64encode(private_pem).decode())

def ecc_encrypt(text, public_key):
    """
    Encrypt text using ECC public key (ECIES: ECC + AES).
    Args:
        text: Plaintext string to encrypt.
        public_key: Base64-encoded PEM public key.
    Returns: Base64-encoded (ephemeral_public_key, iv, ciphertext, tag).
    """
    try:
        # Decode base64 public key
        public_pem = base64.urlsafe_b64decode(public_key)
        recipient_public_key = serialization.load_pem_public_key(public_pem)
        
        # Generate ephemeral ECC key pair for encryption
        ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
        ephemeral_public_key = ephemeral_private_key.public_key()
        
        # Perform key exchange to derive shared secret
        shared_secret = ephemeral_private_key.exchange(ec.ECDH(), recipient_public_key)
        
        # Derive AES key using HKDF
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'encryption',
        ).derive(shared_secret)
        
        # Generate random IV
        iv = os.urandom(12)
        
        # Encrypt the text using AES-GCM
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(text.encode()) + encryptor.finalize()
        
        # Serialize ephemeral public key
        ephemeral_public_pem = ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Combine all components (ephemeral public key, IV, ciphertext, tag)
        result = {
            'ephemeral_public_key': base64.urlsafe_b64encode(ephemeral_public_pem).decode(),
            'iv': base64.urlsafe_b64encode(iv).decode(),
            'ciphertext': base64.urlsafe_b64encode(ciphertext).decode(),
            'tag': base64.urlsafe_b64encode(encryptor.tag).decode()
        }
        
        # Return as a single base64-encoded string (for simplicity)
        return base64.urlsafe_b64encode(str(result).encode()).decode()
    except Exception as e:
        return f"Encryption failed: {str(e)}"

def ecc_decrypt(encrypted_text, private_key):
    """
    Decrypt text using ECC private key (ECIES: ECC + AES).
    Args:
        encrypted_text: Base64-encoded string containing (ephemeral_public_key, iv, ciphertext, tag).
        private_key: Base64-encoded PEM private key.
    Returns: Decrypted plaintext or error message.
    """
    try:
        # Decode encrypted text and private key
        encrypted_data = eval(base64.urlsafe_b64decode(encrypted_text).decode())
        private_pem = base64.urlsafe_b64decode(private_key)
        private_key = serialization.load_pem_private_key(private_pem, password=None)
        
        # Extract components
        ephemeral_public_pem = base64.urlsafe_b64decode(encrypted_data['ephemeral_public_key'])
        iv = base64.urlsafe_b64decode(encrypted_data['iv'])
        ciphertext = base64.urlsafe_b64decode(encrypted_data['ciphertext'])
        tag = base64.urlsafe_b64decode(encrypted_data['tag'])
        
        # Load ephemeral public key
        ephemeral_public_key = serialization.load_pem_public_key(ephemeral_public_pem)
        
        # Perform key exchange to derive shared secret
        shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)
        
        # Derive AES key using HKDF
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'encryption',
        ).derive(shared_secret)
        
        # Decrypt using AES-GCM
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext.decode()
    except Exception as e:
        return f"Decryption failed: {str(e)}"