import os
from PIL import Image
import stepic
from flask import Blueprint, current_app, render_template, request, flash, redirect, url_for, send_file
from flask_login import login_required
from werkzeug.utils import secure_filename
from .utils import caesar_encrypt, caesar_decrypt, vigenere_encrypt, vigenere_decrypt, aes_encrypt, aes_decrypt, columnar_encrypt, columnar_decrypt, ecc_generate_keys, ecc_encrypt, ecc_decrypt

text_bp = Blueprint("text", __name__, template_folder="templates/text")

@text_bp.route('/Uploads/<filename>')
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
    ecc_private_key = None
    if encrypt == 'yes' and encryption_method:
        try:
            if encryption_method == 'caesar':
                encrypted_message = caesar_encrypt(message)
            elif encryption_method == 'vigenere':
                if not key:
                    flash("Vigenère key is required!", "error")
                    return redirect(url_for('text.text_encode'))
                encrypted_message = vigenere_encrypt(message, key)
            elif encryption_method == 'aes':
                encrypted_message, aes_key = aes_encrypt(message)
                print(f"Encoded - Encrypted: {encrypted_message}, AES Key: {aes_key}")
            elif encryption_method == 'columnar':
                if not key:
                    flash("Columnar key is required!", "error")
                    return redirect(url_for('text.text_encode'))
                encrypted_message = columnar_encrypt(message, key)
            elif encryption_method == 'ecc':
                public_key, private_key = ecc_generate_keys()
                encrypted_message = ecc_encrypt(message, public_key)
                if "Encryption failed" in encrypted_message:
                    flash(encrypted_message, "error")
                    return redirect(url_for('text.text_encode'))
                ecc_private_key = private_key
                print(f"Encoded - Encrypted: {encrypted_message}, ECC Private Key: {ecc_private_key}")
        except Exception as e:
            flash(f"Encryption failed: {str(e)}", "error")
            return redirect(url_for('text.text_encode'))
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
                          aes_key=aes_key,
                          ecc_private_key=ecc_private_key)

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
    vigenere_key = request.form.get('vigenere_key', '')
    aes_key = request.form.get('aes_key', '')
    columnar_key = request.form.get('columnar_key', '')
    ecc_key = request.form.get('ecc_key', '')
    print(f"Decrypt: {decrypt}, Method: {encryption_method}, Vigenère Key: {vigenere_key}, AES Key: {aes_key}, Columnar Key: {columnar_key}, ECC Key: {ecc_key}")

    decrypted_message = extracted_message
    if decrypt == 'yes' and encryption_method:
        try:
            if encryption_method == 'caesar':
                decrypted_message = caesar_decrypt(extracted_message)
            elif encryption_method == 'vigenere':
                if not vigenere_key:
                    flash("Vigenère key is required!", "error")
                    return redirect(url_for('text.text_decode'))
                decrypted_message = vigenere_decrypt(extracted_message, vigenere_key)
            elif encryption_method == 'aes':
                if not aes_key:
                    flash("AES key is required!", "error")
                    return redirect(url_for('text.text_decode'))
                decrypted_message = aes_decrypt(extracted_message, aes_key)
                if "Decryption failed" in decrypted_message:
                    flash(decrypted_message, "error")
                    return redirect(url_for('text.text_decode'))
            elif encryption_method == 'columnar':
                if not columnar_key:
                    flash("Columnar key is required!", "error")
                    return redirect(url_for('text.text_decode'))
                decrypted_message = columnar_decrypt(extracted_message, columnar_key)
            elif encryption_method == 'ecc':
                if not ecc_key:
                    flash("ECC private key is required!", "error")
                    return redirect(url_for('text.text_decode'))
                decrypted_message = ecc_decrypt(extracted_message, ecc_key)
                if "Decryption failed" in decrypted_message:
                    flash(decrypted_message, "error")
                    return redirect(url_for('text.text_decode'))
        except Exception as e:
            flash(f"Decryption failed: {str(e)}", "error")
            return redirect(url_for('text.text_decode'))
    else:
        encryption_method = 'none'

    return render_template("text/decode-text-result.html",
                          file=filename,
                          extracted_message=extracted_message,
                          decrypted_message=decrypted_message,
                          encryption_method=encryption_method)