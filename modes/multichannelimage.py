import os
import cv2
import numpy as np
from flask import Blueprint, current_app, render_template, request, flash, redirect, url_for, send_file
from flask_login import login_required
from werkzeug.utils import secure_filename
from .utils import caesar_encrypt, caesar_decrypt, vigenere_encrypt, vigenere_decrypt, aes_encrypt, aes_decrypt

multichannelimage_bp = Blueprint('multichannelimage', __name__, template_folder='templates/multichannelimage')

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
BITS_PER_CHANNEL = 2  # Using 2 bits per channel for more capacity

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@multichannelimage_bp.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    file_path = os.path.join(current_app.config['UPLOAD_MULTICHANNELIMAGE_FOLDER'], filename)
    return send_file(file_path, as_attachment=True, download_name=filename)

@multichannelimage_bp.route('/multichannelimage_encode', methods=['GET', 'POST'])
@login_required
def multichannelimage_encode():
    if request.method == 'POST':
        file = request.files.get('image')
        text = request.form.get('text', '').strip()
        encrypt = request.form.get('encrypt', 'no')
        encryption_method = request.form.get('encryption_method', '')
        key = request.form.get('encryption_key', 'SECRETKEY')

        if not file or not allowed_file(file.filename):
            flash("Invalid file format. Use PNG or JPG.", "error")
            return redirect(url_for('multichannelimage.multichannelimage_encode'))

        if not text:
            flash("Message cannot be empty!", "error")
            return redirect(url_for('multichannelimage.multichannelimage_encode'))

        filename = secure_filename(file.filename)
        upload_folder = current_app.config['UPLOAD_MULTICHANNELIMAGE_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        file_path = os.path.join(upload_folder, filename)
        file.save(file_path)

        image = cv2.imread(file_path)
        if image is None:
            flash("Failed to load image file.", "error")
            return redirect(url_for('multichannelimage.multichannelimage_encode'))

        max_capacity = (image.size * BITS_PER_CHANNEL) // 8  # bytes
        if len(text) > max_capacity:
            flash(f"Message too long! Maximum capacity: {max_capacity} characters", "error")
            return redirect(url_for('multichannelimage.multichannelimage_encode'))

        encrypted_text = text
        aes_key = None
        if encrypt == 'yes' and encryption_method:
            if encryption_method == 'caesar':
                encrypted_text = caesar_encrypt(text)
            elif encryption_method == 'vigenere':
                encrypted_text = vigenere_encrypt(text, key)
            elif encryption_method == 'aes':
                encrypted_text, aes_key = aes_encrypt(text)
        else:
            encryption_method = 'none'
        encoded_image = encode_text_in_image(image, encrypted_text)
        # Force PNG output regardless of input format
        base_name = os.path.splitext(filename)[0]  # Remove original extension
        output_filename = f"encoded_{base_name}.png"  # Always use .png
        output_path = os.path.join(upload_folder, output_filename)
        cv2.imwrite(output_path, encoded_image, [cv2.IMWRITE_PNG_COMPRESSION, 0])  # Lossless PNG

        return render_template('multichannelimage/encode-multichannelimage-result.html', 
                             file=output_filename,
                             message=text,
                             encrypted_text=encrypted_text,
                             encryption_method=encryption_method,
                             aes_key=aes_key)
    
    return render_template('multichannelimage/encode-multichannelimage.html')

@multichannelimage_bp.route('/multichannelimage_decode', methods=['GET', 'POST'])
@login_required
def multichannelimage_decode():
    if request.method == 'POST':
        file = request.files.get('image')
        decrypt = request.form.get('decrypt', 'no')
        encryption_method = request.form.get('encryption_method', '')
        key = request.form.get('encryption_key', '')
        aes_key = request.form.get('aes_key', '')

        if not file or not allowed_file(file.filename):
            flash("Invalid file format. Use PNG or JPG.", "error")
            return redirect(url_for('multichannelimage.multichannelimage_decode'))

        filename = secure_filename(file.filename)
        upload_folder = current_app.config['UPLOAD_MULTICHANNELIMAGE_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        file_path = os.path.join(upload_folder, filename)
        file.save(file_path)

        image = cv2.imread(file_path)
        if image is None:
            flash("Failed to load image file.", "error")
            return redirect(url_for('multichannelimage.multichannelimage_decode'))

        try:
            extracted_text = decode_text_from_image(image)
        except ValueError as e:
            flash(str(e), "error")
            return redirect(url_for('multichannelimage.multichannelimage_decode'))

        decrypted_text = extracted_text
        if decrypt == 'yes' and encryption_method:
            try:
                if encryption_method == 'caesar':
                    decrypted_text = caesar_decrypt(extracted_text)
                elif encryption_method == 'vigenere':
                    if not key:
                        flash("Vigenère key is required!", "error")
                        return redirect(url_for('multichannelimage.multichannelimage_decode'))
                    decrypted_text = vigenere_decrypt(extracted_text, key)
                elif encryption_method == 'aes':
                    if not aes_key:
                        flash("AES key is required!", "error")
                        return redirect(url_for('multichannelimage.multichannelimage_decode'))
                    decrypted_text = aes_decrypt(extracted_text, aes_key)
        

            except Exception as e:
                flash(f"Decryption failed: {str(e)}", "error")
                return redirect(url_for('multichannelimage.multichannelimage_decode'))
        else:
            encryption_method = 'none'

        return render_template('multichannelimage/decode-multichannelimage-result.html', 
                             file=filename,
                             extracted_text=extracted_text,
                             decrypted_text=decrypted_text,
                             encryption_method=encryption_method)
    
    return render_template('multichannelimage/decode-multichannelimage.html')

def encode_text_in_image(image, text):
    """Encode text into image using multiple bits per channel"""
    length = len(text)
    binary = f'{length:032b}' + ''.join(format(ord(c), '08b') for c in text) + '1111111111111110'
    
    required_bits = len(binary)
    available_bits = image.size * BITS_PER_CHANNEL
    if required_bits > available_bits:
        raise ValueError("Image too small for message")

    encoded = image.copy()
    bit_index = 0
    
    for i in range(encoded.shape[0]):
        for j in range(encoded.shape[1]):
            for k in range(encoded.shape[2]):
                if bit_index >= len(binary):
                    return encoded
                
                pixel = encoded[i, j, k]
                pixel = pixel & 0xFC  # Clear the last 2 bits
                bits_to_encode = binary[bit_index:bit_index+2].ljust(2, '0')
                pixel |= int(bits_to_encode, 2)
                encoded[i, j, k] = pixel
                bit_index += 2
    
    return encoded

def decode_text_from_image(image):
    """Decode text from image using multiple bits per channel"""
    binary = ''
    
    for i in range(image.shape[0]):
        for j in range(image.shape[1]):
            for k in range(image.shape[2]):
                pixel = image[i, j, k]
                bits = format(pixel & 3, '02b')  # Extract the last 2 bits
                binary += bits
                
                if len(binary) >= 32:
                    length = int(binary[:32], 2)
                    expected_bits = 32 + length * 8 + 16  # Length + message + end marker
                    
                    if len(binary) >= expected_bits:
                        msg_binary = binary[32:32 + length * 8]
                        end_marker = binary[32 + length * 8:32 + length * 8 + 16]
                        
                        if end_marker != '1111111111111110':
                            raise ValueError("Invalid end marker")
                        
                        text = ''
                        for i in range(0, len(msg_binary), 8):
                            chunk = msg_binary[i:i+8]
                            if len(chunk) != 8:
                                raise ValueError("Incomplete character data in message")
                            text += chr(int(chunk, 2))
                        return text
    
    raise ValueError("No valid message found in image")