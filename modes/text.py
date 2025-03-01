import os
from PIL import Image
import stepic
from flask import Blueprint, current_app, render_template, request, flash, redirect, url_for, send_from_directory
from flask_login import login_required
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet

text_bp = Blueprint("text", __name__, template_folder="templates/text")

# Encryption Functions (simplified from your earlier code)
def caesar_encrypt(text, shift=3):
    return ''.join(chr((ord(char) + shift) % 256) for char in text)

def caesar_decrypt(text, shift=3):
    return ''.join(chr((ord(char) - shift) % 256) for char in text)

def vigenere_encrypt(text, key):
    key = (key * (len(text) // len(key))) + key[:len(text) % len(key)]
    return ''.join(chr((ord(t) + ord(k)) % 256) for t, k in zip(text, key))

def vigenere_decrypt(text, key):
    key = (key * (len(text) // len(key))) + key[:len(text) % len(key)]
    return ''.join(chr((ord(t) - ord(k)) % 256) for t, k in zip(text, key))

def aes_encrypt(text, key=None):
    cipher = Fernet(key if key else Fernet.generate_key())
    encrypted = cipher.encrypt(text.encode()).decode()
    return encrypted, cipher._encryption_key.decode()  # Return encrypted text and key

def aes_decrypt(text, key):
    try:
        cipher = Fernet(key.encode())
        return cipher.decrypt(text.encode()).decode()
    except:
        return "Decryption failed (invalid key or data)"

@text_bp.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(current_app.config['UPLOAD_TEXT_FOLDER'], filename)

@text_bp.route("/text_encode", methods=['GET'])
@login_required
def text_encode():
    return render_template("text/encode-text.html")

@text_bp.route("/text_encode", methods=['POST'])
@login_required
def text_encode_post():
    message = request.form.get('message', '')
    encrypt = request.form.get('encrypt', 'no')
    encryption_method = request.form.get('encryption_method', '')
    key = request.form.get('encryption_key', 'SECRETKEY')

    if not message:
        flash("Message cannot be empty!", "error")
        return redirect(url_for('text.text_encode'))

    file = request.files.get('image')
    if not file or file.filename == '':
        flash("No image selected!", "error")
        return redirect(url_for('text.text_encode'))

    filename = secure_filename(file.filename)
    upload_folder = current_app.config['UPLOAD_TEXT_FOLDER']
    os.makedirs(upload_folder, exist_ok=True)
    file_path = os.path.join(upload_folder, filename)
    file.save(file_path)

    # Handle encryption if selected
    encrypted_message = message
    aes_key = None
    if encrypt == 'yes' and encryption_method:
        if encryption_method == 'caesar':
            encrypted_message = caesar_encrypt(message)
        elif encryption_method == 'vigenere':
            encrypted_message = vigenere_encrypt(message, key)
        elif encryption_method == 'aes':
            encrypted_message, aes_key = aes_encrypt(message)
    else:
        encryption_method = 'none'

    # Embed message into image
    try:
        im = Image.open(file_path)
        im_encoded = stepic.encode(im, bytes(encrypted_message, encoding='utf-8'))
        output_filename = f"encoded_{filename}"
        output_path = os.path.join(upload_folder, output_filename)
        im_encoded.save(output_path)
    except Exception as e:
        flash(f"Error encoding message: {e}", "error")
        return redirect(url_for('text.text_encode'))

    return render_template("text/encode-text-result.html",
                          file=output_filename,
                          message=message,
                          encrypted_message=encrypted_message,
                          encryption_method=encryption_method,
                          aes_key=aes_key)