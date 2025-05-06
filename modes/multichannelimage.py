import os
import cv2
import numpy as np
from flask import Blueprint, current_app, render_template, request, flash, redirect, url_for, send_file
from flask_login import login_required
from werkzeug.utils import secure_filename
from .utils import caesar_encrypt, caesar_decrypt, vigenere_encrypt, vigenere_decrypt, aes_encrypt, aes_decrypt, columnar_encrypt, columnar_decrypt, ecc_generate_keys, ecc_encrypt, ecc_decrypt
import logging
from cryptography.hazmat.primitives import serialization
import base64

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

multichannelimage_bp = Blueprint('multichannelimage', __name__, template_folder='templates/multichannelimage')

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
BITS_PER_CHANNEL = 2  # Using 2 bits per channel for more capacity

def allowed_file(filename):
    """Check if the file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@multichannelimage_bp.route('/Uploads/<filename>')
@login_required
def uploaded_file(filename):
    """Serve uploaded files."""
    file_path = os.path.join(current_app.config['UPLOAD_MULTICHANNELIMAGE_FOLDER'], filename)
    if not os.path.exists(file_path):
        logger.error(f"File not found: {file_path}")
        flash("File not found!", "error")
        return redirect(url_for('multichannelimage.multichannelimage_encode'))
    return send_file(file_path, as_attachment=True, download_name=filename)

@multichannelimage_bp.route('/multichannelimage_encode', methods=['GET', 'POST'])
@login_required
def multichannelimage_encode():
    """Handle image encoding requests."""
    if request.method == 'POST':
        file = request.files.get('image')
        text = request.form.get('text', '').strip()
        encrypt = request.form.get('encrypt', 'no')
        encryption_method = request.form.get('encryption_method', '')
        key = request.form.get('encryption_key', 'SECRETKEY')

        logger.debug(f"Form data: text='{text}', encrypt='{encrypt}', encryption_method='{encryption_method}', encryption_key='{key}'")

        if not file or not allowed_file(file.filename):
            flash("Invalid file format. Use PNG or JPG.", "error")
            return redirect(url_for('multichannelimage.multichannelimage_encode'))

        if not text:
            flash("Message cannot be empty!", "error")
            return redirect(url_for('multichannelimage.multichannelimage_encode'))

        filename = secure_filename(file.filename)
        upload_folder = current_app.config['UPLOAD_MULTICHANNELIMAGE_FOLDER']
        logger.debug(f"Upload folder: {upload_folder}")
        os.makedirs(upload_folder, exist_ok=True)
        file_path = os.path.join(upload_folder, filename)
        file.save(file_path)

        image = cv2.imread(file_path)
        if image is None:
            logger.error(f"Failed to load image file: {file_path}")
            flash("Failed to load image file.", "error")
            return redirect(url_for('multichannelimage.multichannelimage_encode'))

        max_capacity = (image.size * BITS_PER_CHANNEL) // 8  # bytes
        if len(text) > max_capacity:
            logger.error(f"Message too long! Maximum capacity: {max_capacity} characters, provided: {len(text)}")
            flash(f"Message too long! Maximum capacity: {max_capacity} characters", "error")
            return redirect(url_for('multichannelimage.multichannelimage_encode'))

        encrypted_text = text
        aes_key = None
        vigenere_key = None
        columnar_key = None
        ecc_private_key = None

        if encrypt == 'yes' and encryption_method:
            try:
                if encryption_method == 'caesar':
                    encrypted_text = caesar_encrypt(text)
                    logger.debug(f"Encrypted message (Caesar): {encrypted_text[:50]}...")
                elif encryption_method == 'vigenere':
                    if not key:
                        flash("Vigenère key is required!", "error")
                        return redirect(url_for('multichannelimage.multichannelimage_encode'))
                    encrypted_text = vigenere_encrypt(text, key)
                    vigenere_key = key
                    logger.debug(f"Encrypted message (Vigenère): {encrypted_text[:50]}...")
                elif encryption_method == 'aes':
                    encrypted_text, aes_key = aes_encrypt(text)
                    logger.debug(f"Encrypted message (AES): {encrypted_text[:50]}...")
                elif encryption_method == 'columnar':
                    if not key:
                        flash("Columnar key is required!", "error")
                        return redirect(url_for('multichannelimage.multichannelimage_encode'))
                    encrypted_text = columnar_encrypt(text, key)
                    columnar_key = key
                    logger.debug(f"Encrypted message (Columnar): {encrypted_text[:50]}...")
                elif encryption_method == 'ecc':
                    logger.debug("Attempting ECC encryption")
                    try:
                        public_key, private_key = ecc_generate_keys()
                        logger.debug(f"ECC keys generated: public_key={public_key[:50]}..., private_key={private_key[:50]}...")
                        encrypted_text = ecc_encrypt(text, public_key)
                        if isinstance(encrypted_text, str) and "Encryption failed" in encrypted_text:
                            logger.error(f"ECC encryption failed: {encrypted_text}")
                            flash(encrypted_text, "error")
                            return redirect(url_for('multichannelimage.multichannelimage_encode'))
                        # Serialize ECC private key like audio.py
                        if isinstance(private_key, bytes):
                            ecc_private_key = base64.b64encode(private_key).decode('utf-8')
                        elif isinstance(private_key, str):
                            ecc_private_key = private_key
                        else:
                            ecc_private_key = private_key.private_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PrivateFormat.PKCS8,
                                encryption_algorithm=serialization.NoEncryption()
                            ).decode('utf-8')
                        logger.debug(f"ECC private key serialized: {ecc_private_key[:50]}...")
                        # Test decryption to verify key
                        test_decrypt = ecc_decrypt(encrypted_text, ecc_private_key)
                        logger.debug(f"Test decryption result: {test_decrypt}")
                        if isinstance(test_decrypt, str) and "Decryption failed" in test_decrypt:
                            logger.error(f"Test decryption failed: {test_decrypt}")
                            flash(f"ECC test decryption failed: {test_decrypt}", "error")
                            return redirect(url_for('multichannelimage.multichannelimage_encode'))
                        logger.debug(f"Encrypted message (ECC): {encrypted_text[:50]}...")
                    except Exception as e:
                        logger.error(f"ECC encryption error: {str(e)}")
                        flash(f"ECC encryption failed: {str(e)}", "error")
                        return redirect(url_for('multichannelimage.multichannelimage_encode'))
            except Exception as e:
                logger.error(f"Encryption failed: {str(e)}")
                flash(f"Encryption failed: {str(e)}", "error")
                return redirect(url_for('multichannelimage.multichannelimage_encode'))
        else:
            encryption_method = 'none'

        logger.debug(f"Encryption result: encrypted_text='{encrypted_text[:50]}...', aes_key={aes_key}, vigenere_key={vigenere_key}, columnar_key={columnar_key}, ecc_private_key={ecc_private_key[:50] if ecc_private_key else None}...")

        try:
            encoded_image = encode_text_in_image(image, encrypted_text)
            # Force PNG output regardless of input format
            base_name = os.path.splitext(filename)[0]  # Remove original extension
            output_filename = f"encoded_{base_name}.png"  # Always use .png
            output_path = os.path.join(upload_folder, output_filename)
            cv2.imwrite(output_path, encoded_image, [cv2.IMWRITE_PNG_COMPRESSION, 0])  # Lossless PNG
            logger.debug(f"Encoded image saved to: {output_path}")
        except ValueError as e:
            logger.error(f"Encoding failed: {str(e)}")
            flash(str(e), "error")
            return redirect(url_for('multichannelimage.multichannelimage_encode'))

        return render_template('multichannelimage/encode-multichannelimage-result.html', 
                              file=output_filename,
                              message=text,
                              encrypted_text=encrypted_text,
                              encryption_method=encryption_method,
                              aes_key=aes_key,
                              vigenere_key=vigenere_key if encryption_method == 'vigenere' else None,
                              columnar_key=columnar_key if encryption_method == 'columnar' else None,
                              ecc_private_key=ecc_private_key if encryption_method == 'ecc' else None)
    
    return render_template('multichannelimage/encode-multichannelimage.html')

@multichannelimage_bp.route('/multichannelimage_decode', methods=['GET', 'POST'])
@login_required
def multichannelimage_decode():
    """Handle image decoding requests."""
    if request.method == 'POST':
        file = request.files.get('image')
        decrypt = request.form.get('decrypt', 'no')
        encryption_method = request.form.get('encryption_method', '')
        vigenere_key = request.form.get('vigenere_key', '').strip()
        aes_key = request.form.get('aes_key', '').strip()
        columnar_key = request.form.get('columnar_key', '').strip()
        ecc_key = request.form.get('ecc_key', '').strip()

        logger.debug(f"Form data: decrypt='{decrypt}', encryption_method='{encryption_method}', vigenere_key='{vigenere_key}', aes_key='{aes_key}', columnar_key='{columnar_key}', ecc_key='{ecc_key[:50] if ecc_key else None}'")

        if not file or not allowed_file(file.filename):
            flash("Invalid file format. Use PNG or JPG.", "error")
            return redirect(url_for('multichannelimage.multichannelimage_decode'))

        filename = secure_filename(file.filename)
        upload_folder = current_app.config['UPLOAD_MULTICHANNELIMAGE_FOLDER']
        logger.debug(f"Upload folder: {upload_folder}")
        os.makedirs(upload_folder, exist_ok=True)
        file_path = os.path.join(upload_folder, filename)
        file.save(file_path)

        image = cv2.imread(file_path)
        if image is None:
            logger.error(f"Failed to load image file: {file_path}")
            flash("Failed to load image file.", "error")
            return redirect(url_for('multichannelimage.multichannelimage_decode'))

        try:
            extracted_text = decode_text_from_image(image)
            logger.debug(f"Extracted text: {extracted_text[:50]}...")
        except ValueError as e:
            logger.error(f"Decoding failed: {str(e)}")
            flash(str(e), "error")
            return redirect(url_for('multichannelimage.multichannelimage_decode'))

        decrypted_text = extracted_text
        if decrypt == 'yes' and encryption_method:
            try:
                if encryption_method == 'caesar':
                    decrypted_text = caesar_decrypt(extracted_text)
                    logger.debug(f"Decrypted text (Caesar): {decrypted_text}")
                elif encryption_method == 'vigenere':
                    if not vigenere_key:
                        flash("Vigenère key is required!", "error")
                        return redirect(url_for('multichannelimage.multichannelimage_decode'))
                    decrypted_text = vigenere_decrypt(extracted_text, vigenere_key)
                    logger.debug(f"Decrypted text (Vigenère): {decrypted_text}")
                elif encryption_method == 'aes':
                    if not aes_key:
                        flash("AES key is required!", "error")
                        return redirect(url_for('multichannelimage.multichannelimage_decode'))
                    decrypted_text = aes_decrypt(extracted_text, aes_key)
                    logger.debug(f"Decrypted text (AES): {decrypted_text}")
                    if isinstance(decrypted_text, str) and "Decryption failed" in decrypted_text:
                        flash(decrypted_text, "error")
                        return redirect(url_for('multichannelimage.multichannelimage_decode'))
                elif encryption_method == 'columnar':
                    if not columnar_key:
                        flash("Columnar key is required!", "error")
                        return redirect(url_for('multichannelimage.multichannelimage_decode'))
                    decrypted_text = columnar_decrypt(extracted_text, columnar_key)
                    logger.debug(f"Decrypted text (Columnar): {decrypted_text}")
                elif encryption_method == 'ecc':
                    if not ecc_key:
                        flash("ECC private key is required!", "error")
                        return redirect(url_for('multichannelimage.multichannelimage_decode'))
                    logger.debug(f"Attempting ECC decryption with key: {ecc_key[:50]}...")
                    try:
                        decrypted_text = ecc_decrypt(extracted_text, ecc_key)
                        if isinstance(decrypted_text, str) and "Decryption failed" in decrypted_text:
                            logger.error(f"ECC decryption failed: {decrypted_text}")
                            flash(decrypted_text, "error")
                            return redirect(url_for('multichannelimage.multichannelimage_decode'))
                        logger.debug(f"Decrypted text (ECC): {decrypted_text}")
                    except Exception as e:
                        logger.error(f"ECC decryption error: {str(e)}")
                        flash(f"ECC decryption failed: {str(e)}", "error")
                        return redirect(url_for('multichannelimage.multichannelimage_decode'))
            except Exception as e:
                logger.error(f"Decryption failed: {str(e)}")
                flash(f"Decryption failed: {str(e)}", "error")
                return redirect(url_for('multichannelimage.multichannelimage_decode'))
        else:
            encryption_method = 'none'

        return render_template('multichannelimage/decode-multichannelimage-result.html', 
                              file=filename,
                              extracted_text=extracted_text,
                              decrypted_text=decrypted_text,
                              encryption_method=encryption_method,
                              vigenere_key=vigenere_key if encryption_method == 'vigenere' else None,
                              aes_key=aes_key if encryption_method == 'aes' else None,
                              columnar_key=columnar_key if encryption_method == 'columnar' else None,
                              ecc_key=ecc_key if encryption_method == 'ecc' else None)
    
    return render_template('multichannelimage/decode-multichannelimage.html')

def encode_text_in_image(image, text):
    """Encode text into image using multiple bits per channel."""
    length = len(text)
    binary = f'{length:032b}' + ''.join(format(ord(c), '08b') for c in text) + '1111111111111110'
    
    required_bits = len(binary)
    available_bits = image.size * BITS_PER_CHANNEL
    if required_bits > available_bits:
        raise ValueError(f"Image too small for message. Required: {required_bits} bits, Available: {available_bits} bits")

    encoded = image.copy()
    bit_index = 0
    
    for i in range(encoded.shape[0]):
        for j in range(encoded.shape[1]):
            for k in range(encoded.shape[2]):
                if bit_index >= len(binary):
                    logger.debug(f"Encoded {bit_index} bits into image")
                    return encoded
                
                pixel = encoded[i, j, k]
                pixel = pixel & 0xFC  # Clear the last 2 bits
                bits_to_encode = binary[bit_index:bit_index+2].ljust(2, '0')
                pixel |= int(bits_to_encode, 2)
                encoded[i, j, k] = pixel
                bit_index += 2
    
    logger.debug(f"Encoded {bit_index} bits into image")
    return encoded

def decode_text_from_image(image):
    """Decode text from image using multiple bits per channel."""
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
                        logger.debug(f"Decoded text: {text[:50]}...")
                        return text
    
    raise ValueError("No valid message found in image")