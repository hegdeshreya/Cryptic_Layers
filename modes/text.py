import os
from PIL import Image
import stepic
from flask import Blueprint, current_app, render_template, request, flash, redirect, url_for, send_file
from flask_login import login_required
from werkzeug.utils import secure_filename
from .utils import caesar_encrypt, caesar_decrypt, vigenere_encrypt, vigenere_decrypt, aes_encrypt, aes_decrypt

text_bp = Blueprint("text", __name__, template_folder="templates/text")

@text_bp.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    file_path = os.path.join(current_app.config['UPLOAD_TEXT_FOLDER'], filename)
    return send_file(file_path, as_attachment=True, download_name=filename)

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

    # Validate file format for encoding (accept common image formats, but save as PNG)
    filename = secure_filename(file.filename)
    if not filename.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp')):
        flash(f"Unsupported image format. Use PNG, JPG, or BMP.", "error")
        return redirect(url_for('text.text_encode'))

    upload_folder = current_app.config['UPLOAD_TEXT_FOLDER']
    os.makedirs(upload_folder, exist_ok=True)
    file_path = os.path.join(upload_folder, filename)
    file.save(file_path)

    # Convert image to PNG if not already
    im = Image.open(file_path)
    if im.format != 'PNG':
        png_filename = f"{os.path.splitext(filename)[0]}_converted.png"
        png_path = os.path.join(upload_folder, png_filename)
        im.save(png_path, 'PNG')
        file_path = png_path
        filename = png_filename

    encrypted_message = message
    aes_key = None
    if encrypt == 'yes' and encryption_method:
        if encryption_method == 'caesar':
            encrypted_message = caesar_encrypt(message)
        elif encryption_method == 'vigenere':
            encrypted_message = vigenere_encrypt(message, key)
        elif encryption_method == 'aes':
            encrypted_message, aes_key = aes_encrypt(message)
            print(f"Encoded - Encrypted: {encrypted_message}, AES Key: {aes_key}")
    else:
        encryption_method = 'none'

    try:
        im = Image.open(file_path)
        im_encoded = stepic.encode(im, bytes(encrypted_message, encoding='utf-8'))
        output_filename = f"encoded_{os.path.splitext(filename)[0]}.png"
        output_path = os.path.join(upload_folder, output_filename)
        im_encoded.save(output_path, 'PNG')
    except Exception as e:
        flash(f"Error encoding message: {e}", "error")
        return redirect(url_for('text.text_encode'))

    return render_template("text/encode-text-result.html",
                          file=output_filename,
                          message=message,
                          encrypted_message=encrypted_message,
                          encryption_method=encryption_method,
                          aes_key=aes_key)

@text_bp.route("/text_decode", methods=['GET'])
@login_required
def text_decode():
    return render_template("text/decode-text.html")

@text_bp.route("/text_decode", methods=['POST'])
@login_required
def text_decode_post():
    file = request.files.get('image')
    if not file or file.filename == '':
        flash("No image selected!", "error")
        return redirect(url_for('text.text_decode'))

    filename = secure_filename(file.filename)
    if not filename.lower().endswith('.png'):
        flash("Only PNG images are supported for decoding.", "error")
        return redirect(url_for('text.text_decode'))

    upload_folder = current_app.config['UPLOAD_TEXT_FOLDER']
    os.makedirs(upload_folder, exist_ok=True)
    file_path = os.path.join(upload_folder, filename)
    file.save(file_path)

    try:
        im = Image.open(file_path)
        extracted_message = stepic.decode(im)
        if not extracted_message:
            flash("No message found in the image!", "error")
            return redirect(url_for('text.text_decode'))
        print(f"Decoded - Extracted: {extracted_message}")
    except Exception as e:
        flash(f"Error decoding image: {e}", "error")
        return redirect(url_for('text.text_decode'))

    decrypt = request.form.get('decrypt', 'no')
    encryption_method = request.form.get('encryption_method', '')
    key = request.form.get('encryption_key', '')
    aes_key = request.form.get('aes_key', '')
    print(f"Decrypt: {decrypt}, Method: {encryption_method}, AES Key: {aes_key}")

    decrypted_message = extracted_message
    if decrypt == 'yes' and encryption_method:
        if encryption_method == 'caesar':
            decrypted_message = caesar_decrypt(extracted_message)
        elif encryption_method == 'vigenere':
            if not key:
                flash("Vigenère key is required!", "error")
                return redirect(url_for('text.text_decode'))
            decrypted_message = vigenere_decrypt(extracted_message, key)
        elif encryption_method == 'aes':
            if not aes_key:
                flash("AES key is required!", "error")
                return redirect(url_for('text.text_decode'))
            decrypted_message = aes_decrypt(extracted_message, aes_key)
            print(f"Decrypted: {decrypted_message}")
    else:
        encryption_method = 'none'

    return render_template("text/decode-text-result.html",
                          file=filename,
                          extracted_message=extracted_message,
                          decrypted_message=decrypted_message,
                          encryption_method=encryption_method)