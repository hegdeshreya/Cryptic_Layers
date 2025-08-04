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
    """
    Encrypt text using Vigenère Cipher, preserving spaces, non-alphabetic characters, and exact case.
    Only alphabetic characters (a-z, A-Z) are encrypted.
    Key is sanitized to contain only alphabetic characters, preserving their case.
    """
    # Sanitize key: keep only alphabetic characters, preserve case
    key = ''.join(c for c in key if c.isalpha())
    if not key:
        return "Invalid key: Key must contain at least one letter."

    result = []
    key_index = 0
    key_length = len(key)

    for char in text:
        if char.isalpha():
            # Determine base and modulo based on character case
            base = 65 if char.isupper() else 97
            # Get key character, preserving its case
            key_char = key[key_index % key_length]
            # Determine shift based on key character's case
            key_base = 65 if key_char.isupper() else 97
            shift = ord(key_char) - key_base
            # Apply Vigenère shift, preserving case
            encrypted_char = chr((ord(char) - base + shift) % 26 + base)
            result.append(encrypted_char)
            key_index += 1
        else:
            # Preserve non-alphabetic characters (e.g., spaces)
            result.append(char)

    return ''.join(result)

def vigenere_decrypt(text, key):
    """
    Decrypt text encrypted with Vigenère Cipher, preserving spaces, non-alphabetic characters, and exact case.
    Only alphabetic characters (a-z, A-Z) are decrypted.
    Key is sanitized to contain only alphabetic characters, preserving their case.
    """
    # Sanitize key: keep only alphabetic characters, preserve case
    key = ''.join(c for c in key if c.isalpha())
    if not key:
        return "Invalid key: Key must contain at least one letter."

    result = []
    key_index = 0
    key_length = len(key)

    for char in text:
        if char.isalpha():
            # Determine base and modulo based on character case
            base = 65 if char.isupper() else 97
            # Get key character, preserving its case
            key_char = key[key_index % key_length]
            # Determine shift based on key character's case
            key_base = 65 if key_char.isupper() else 97
            shift = ord(key_char) - key_base
            # Reverse Vigenère shift, preserving case
            decrypted_char = chr((ord(char) - base - shift + 26) % 26 + base)
            result.append(decrypted_char)
            key_index += 1
        else:
            # Preserve non-alphabetic characters (e.g., spaces)
            result.append(char)

    return ''.join(result)

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

def columnar_encrypt(message, key):
    """
    Encrypt message using Columnar Transposition Cipher with the given key.
    Preserves spaces and case, only transposes alphabetic characters.
    Key is sanitized to contain only alphabetic characters, preserving case.
    Uses 'X' for padding instead of spaces.
    """
    # Sanitize key: keep only alphabetic characters, preserve case
    key = ''.join(c for c in key if c.isalpha())
    if not key:
        return "Invalid key: Key must contain at least one letter."

    n_cols = len(key)
    # Count only alphabetic characters for grid size
    alpha_count = sum(1 for c in message if c.isalpha())
    n_rows = (alpha_count + n_cols - 1) // n_cols  # Ceiling division for alphabetic chars

    # Create grid, preserving spaces
    grid = []
    alpha_chars = [c for c in message if c.isalpha()]
    spaces = [(i, c) for i, c in enumerate(message) if not c.isalpha()]  # Track spaces and other non-alpha chars

    # Pad alphabetic characters with 'X' if needed
    while len(alpha_chars) < n_rows * n_cols:
        alpha_chars.append('X')

    # Build grid row-wise with only alphabetic characters
    for i in range(n_rows):
        row = alpha_chars[i * n_cols:(i + 1) * n_cols]
        grid.append(row)

    # Determine column order from sorted key
    key_order = sorted([(char, idx) for idx, char in enumerate(key)])
    col_indices = [idx for _, idx in key_order]

    # Create ciphertext by reading columns in key order
    alpha_ciphertext = ''
    for idx in col_indices:
        for row in grid:
            if idx < len(row):
                alpha_ciphertext += row[idx]

    # Reinsert spaces and non-alphabetic characters
    result = list(alpha_ciphertext)
    alpha_pos = 0
    final_result = [''] * len(message)
    for i in range(len(message)):
        if (i, message[i]) in spaces:
            final_result[i] = message[i]
        else:
            final_result[i] = result[alpha_pos]
            alpha_pos += 1

    return ''.join(final_result)

def columnar_encrypt(message, key):
    """
    Encrypt message using Columnar Transposition Cipher with the given key.
    Preserves spaces and non-alphabetic characters, only transposes alphabetic characters.
    Key is sanitized to contain only alphabetic characters, preserving case.
    Uses 'X' for padding instead of spaces.
    """
    # Sanitize key: keep only alphabetic characters, preserve case
    key = ''.join(c for c in key if c.isalpha())
    if not key:
        return "Invalid key: Key must contain at least one letter."

    n_cols = len(key)
    # Count only alphabetic characters for grid size
    alpha_count = sum(1 for c in message if c.isalpha())
    n_rows = (alpha_count + n_cols - 1) // n_cols  # Ceiling division for alphabetic chars

    # Track spaces and non-alphabetic characters
    spaces = [(i, c) for i, c in enumerate(message) if not c.isalpha()]
    alpha_chars = [c for c in message if c.isalpha()]

    # Pad alphabetic characters with 'X' if needed
    while len(alpha_chars) < n_rows * n_cols:
        alpha_chars.append('X')

    # Build grid row-wise with only alphabetic characters
    grid = [alpha_chars[i * n_cols:(i + 1) * n_cols] for i in range(n_rows)]

    # Determine column order from sorted key
    key_order = sorted([(char, idx) for idx, char in enumerate(key)])
    col_indices = [idx for _, idx in key_order]

    # Create ciphertext by reading columns in key order
    alpha_ciphertext = ''
    for idx in col_indices:
        for row in grid:
            if idx < len(row):
                alpha_ciphertext += row[idx]

    # Reinsert spaces and non-alphabetic characters
    result = [''] * len(message)
    alpha_pos = 0
    for i in range(len(message)):
        if (i, message[i]) in spaces:
            result[i] = message[i]
        else:
            if alpha_pos < len(alpha_ciphertext):
                result[i] = alpha_ciphertext[alpha_pos]
                alpha_pos += 1

    return ''.join(result)

def columnar_decrypt(ciphertext, key):
    """
    Decrypt message encrypted with Columnar Transposition Cipher and given key.
    Preserves spaces and non-alphabetic characters, only transposes alphabetic characters.
    Key is sanitized to contain only alphabetic characters, preserving case.
    """
    # Sanitize key: keep only alphabetic characters, preserve case
    key = ''.join(c for c in key if c.isalpha())
    if not key:
        return "Invalid key: Key must contain at least one letter."

    n_cols = len(key)
    # Count only alphabetic characters for grid size
    alpha_count = sum(1 for c in ciphertext if c.isalpha())
    n_rows = (alpha_count + n_cols - 1) // n_cols  # Ceiling division for alphabetic chars

    # Track spaces and non-alphabetic characters
    spaces = [(i, c) for i, c in enumerate(ciphertext) if not c.isalpha()]
    alpha_chars = [c for c in ciphertext if c.isalpha()]

    # Determine column order from sorted key
    key_order = sorted([(char, idx) for idx, char in enumerate(key)])
    col_indices = [idx for _, idx in key_order]

    # Calculate column lengths (accounting for padding)
    col_lengths = [n_rows] * n_cols
    extra_chars = alpha_count % n_cols if alpha_count % n_cols != 0 else n_cols
    for i in range(n_cols):
        if i >= extra_chars:
            col_lengths[col_indices[i]] -= 1

    # Build columns from ciphertext
    cols = [''] * n_cols
    pos = 0
    for i, idx in enumerate(col_indices):
        cols[idx] = alpha_chars[pos:pos + col_lengths[idx]]
        pos += col_lengths[idx]

    # Rebuild plaintext by reading row-wise
    alpha_plaintext = ''
    for i in range(n_rows):
        for j in range(n_cols):
            if i < len(cols[j]):
                alpha_plaintext += cols[j][i]

    # Remove padding 'X' characters
    alpha_plaintext = alpha_plaintext.rstrip('X')

    # Reinsert spaces and non-alphabetic characters
    result = [''] * len(ciphertext)
    alpha_pos = 0
    for i in range(len(ciphertext)):
        if (i, ciphertext[i]) in spaces:
            result[i] = ciphertext[i]
        else:
            if alpha_pos < len(alpha_plaintext):
                result[i] = alpha_plaintext[alpha_pos]
                alpha_pos += 1

    return ''.join(result)

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