import os
import wave
import logging
import base64
from flask import Blueprint, current_app, render_template, request, flash, redirect, url_for, send_file
from flask_login import login_required
from werkzeug.utils import secure_filename
from .utils import caesar_encrypt, caesar_decrypt, vigenere_encrypt, vigenere_decrypt, aes_encrypt, aes_decrypt, columnar_encrypt, columnar_decrypt, ecc_generate_keys, ecc_encrypt, ecc_decrypt

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

audio_bp = Blueprint("audio", __name__, template_folder="templates/audio")

ALLOWED_EXTENSIONS = {'wav'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@audio_bp.route('/Uploads/<filename>')
@login_required
def uploaded_file(filename):
    file_path = os.path.join(current_app.config['UPLOAD_AUDIO_FOLDER'], filename)
    return send_file(file_path, as_attachment=True, download_name=filename)

@audio_bp.route("/audio_encode", methods=['GET', 'POST'])
@login_required
def audio_encode():
    if request.method == 'POST':
        message = request.form.get('message', '').strip()
        encrypt = request.form.get('encrypt', 'no')
        encryption_method = request.form.get('encryption_method', '')
        key = request.form.get('encryption_key', '').strip()

        logger.debug(f"Form data: message='{message}', encrypt='{encrypt}', encryption_method='{encryption_method}', key='{key}'")

        if not message:
            flash("Message cannot be empty!", "error")
            return redirect(url_for('audio.audio_encode'))
        
        file = request.files.get('audio')
        if not file or file.filename == '' or not allowed_file(file.filename):
            flash("Only WAV files are supported.", "error")
            return redirect(url_for('audio.audio_encode'))
        
        filename = secure_filename(file.filename)
        upload_folder = current_app.config['UPLOAD_AUDIO_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        file_path = os.path.join(upload_folder, filename)
        file.save(file_path)

        encrypted_message = message
        aes_key = None
        vigenere_key = None
        columnar_key = None
        ecc_key = None

        if encrypt == 'yes' and encryption_method:
            try:
                if encryption_method == 'caesar':
                    encrypted_message = caesar_encrypt(message)
                elif encryption_method == 'vigenere':
                    if not key:
                        flash("Vigenère cipher key is required!", "error")
                        return redirect(url_for('audio.audio_encode'))
                    encrypted_message = vigenere_encrypt(message, key)
                    vigenere_key = key
                elif encryption_method == 'aes':
                    encrypted_message, aes_key = aes_encrypt(message)
                elif encryption_method == 'columnar':
                    if not key:
                        flash("Columnar cipher key is required!", "error")
                        return redirect(url_for('audio.audio_encode'))
                    encrypted_message = columnar_encrypt(message, key)
                    columnar_key = key
                elif encryption_method == 'ecc':
                    logger.debug("Attempting ECC encryption")
                    try:
                        public_key, private_key = ecc_generate_keys()
                        logger.debug(f"ECC keys generated: public_key={public_key}, private_key={private_key}")
                        encrypted_message = ecc_encrypt(message, public_key)
                        if isinstance(encrypted_message, str) and "Encryption failed" in encrypted_message:
                            logger.error(f"ECC encryption failed: {encrypted_message}")
                            flash(encrypted_message, "error")
                            return redirect(url_for('audio.audio_encode'))
                        if not private_key:
                            logger.error("ECC private key is empty or None")
                            flash("ECC private key generation failed", "error")
                            return redirect(url_for('audio.audio_encode'))
                        # Serialize private key to string (assuming PEM or raw bytes)
                        try:
                            if isinstance(private_key, bytes):
                                ecc_key = base64.b64encode(private_key).decode('utf-8')
                            elif isinstance(private_key, str):
                                ecc_key = private_key
                            else:
                                # Handle cryptography key object
                                from cryptography.hazmat.primitives import serialization
                                ecc_key = private_key.private_bytes(
                                    encoding=serialization.Encoding.PEM,
                                    format=serialization.PrivateFormat.PKCS8,
                                    encryption_algorithm=serialization.NoEncryption()
                                ).decode('utf-8')
                            logger.debug(f"ECC private key serialized: {ecc_key}")
                        except Exception as e:
                            logger.error(f"ECC key serialization failed: {str(e)}")
                            flash(f"ECC key serialization failed: {str(e)}", "error")
                            return redirect(url_for('audio.audio_encode'))
                    except Exception as e:
                        logger.error(f"ECC encryption error: {str(e)}")
                        flash(f"ECC encryption failed: {str(e)}", "error")
                        return redirect(url_for('audio.audio_encode'))
            except Exception as e:
                logger.error(f"Encryption error: {str(e)}")
                flash(f"Encryption failed: {str(e)}", "error")
                return redirect(url_for('audio.audio_encode'))
        else:
            encryption_method = 'none'

        logger.debug(f"Encryption result: encrypted_message='{encrypted_message}', ecc_key={ecc_key}, vigenere_key={vigenere_key}, columnar_key={columnar_key}, aes_key={aes_key}")

        try:
            with wave.open(file_path, "rb") as audio:
                params = audio.getparams()
                frames = bytearray(audio.readframes(audio.getnframes()))

            message_length = len(encrypted_message)
            length_binary = format(message_length, '032b')  # Store message length
            message_binary = length_binary + ''.join(format(ord(char), '08b') for char in encrypted_message)

            if len(message_binary) > len(frames):
                flash("Message too long for this audio file!", "error")
                return redirect(url_for('audio.audio_encode'))

            for i, bit in enumerate(message_binary):
                frames[i] = (frames[i] & 254) | int(bit)  # Modify LSB

            output_filename = f"encoded_{filename}"
            output_path = os.path.join(upload_folder, output_filename)
            
            with wave.open(output_path, "wb") as encoded_audio:
                encoded_audio.setparams(params)
                encoded_audio.writeframes(bytes(frames))

        except Exception as e:
            logger.error(f"Encoding error: {e}")
            flash(f"Error encoding message: {e}", "error")
            return redirect(url_for('audio.audio_encode'))

        logger.debug(f"Rendering template with: file={output_filename}, message={message}, encrypted_message={encrypted_message}, encryption_method={encryption_method}, aes_key={aes_key}, vigenere_key={vigenere_key}, columnar_key={columnar_key}, ecc_key={ecc_key}")

        return render_template("audio/encode-audio-result.html", 
                             file=output_filename, 
                             message=message, 
                             encrypted_message=encrypted_message, 
                             encryption_method=encryption_method, 
                             aes_key=aes_key, 
                             vigenere_key=vigenere_key, 
                             columnar_key=columnar_key, 
                             ecc_key=ecc_key)
    
    return render_template("audio/encode-audio.html")

@audio_bp.route("/audio_decode", methods=['GET', 'POST'])
@login_required
def audio_decode():
    if request.method == 'POST':
        file = request.files.get('audio')
        if not file or file.filename == '' or not allowed_file(file.filename):
            flash("Only WAV files are supported for decoding.", "error")
            return redirect(url_for('audio.audio_decode'))
        
        filename = secure_filename(file.filename)
        upload_folder = current_app.config['UPLOAD_AUDIO_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        file_path = os.path.join(upload_folder, filename)
        file.save(file_path)

        try:
            with wave.open(file_path, "rb") as audio:
                frames = bytearray(audio.readframes(audio.getnframes()))

            length_bits = ''.join(str(frames[i] & 1) for i in range(32))
            message_length = int(length_bits, 2)  # Read the actual number of characters
            extracted_bits = ''.join(str(frames[i] & 1) for i in range(32, 32 + (message_length * 8)))
            extracted_message = ''.join(chr(int(extracted_bits[i:i+8], 2)) for i in range(0, len(extracted_bits), 8)).rstrip('\x00')

            if not extracted_message:
                flash("No message found in the audio file!", "error")
                return redirect(url_for('audio.audio_decode'))

        except Exception as e:
            flash(f"Error decoding audio: {e}", "error")
            return redirect(url_for('audio.audio_decode'))

        decrypt = request.form.get('decrypt', 'no')
        encryption_method = request.form.get('encryption_method', '')
        vigenere_key = request.form.get('vigenere_key', '').strip()
        aes_key = request.form.get('aes_key', '').strip()
        columnar_key = request.form.get('columnar_key', '').strip()
        ecc_key = request.form.get('ecc_key', '').strip()
        decrypted_message = extracted_message

        if decrypt == 'yes' and encryption_method:
            try:
                if encryption_method == 'caesar':
                    decrypted_message = caesar_decrypt(extracted_message)
                elif encryption_method == 'vigenere':
                    if not vigenere_key:
                        flash("Vigenère key is required!", "error")
                        return redirect(url_for('audio.audio_decode'))
                    decrypted_message = vigenere_decrypt(extracted_message, vigenere_key)
                elif encryption_method == 'aes':
                    if not aes_key:
                        flash("AES key is required!", "error")
                        return redirect(url_for('audio.audio_decode'))
                    decrypted_message = aes_decrypt(extracted_message, aes_key)
                    if "Decryption failed" in decrypted_message:
                        flash(decrypted_message, "error")
                        return redirect(url_for('audio.audio_decode'))
                elif encryption_method == 'columnar':
                    if not columnar_key:
                        flash("Columnar cipher key is required!", "error")
                        return redirect(url_for('audio.audio_decode'))
                    decrypted_message = columnar_decrypt(extracted_message, columnar_key)
                elif encryption_method == 'ecc':
                    if not ecc_key:
                        flash("ECC private key is required!", "error")
                        return redirect(url_for('audio.audio_decode'))
                    decrypted_message = ecc_decrypt(extracted_message, ecc_key)
                    if "Decryption failed" in decrypted_message:
                        flash(decrypted_message, "error")
                        return redirect(url_for('audio.audio_decode'))
            except Exception as e:
                flash(f"Decryption failed: {str(e)}", "error")
                return redirect(url_for('audio.audio_decode'))
        else:
            encryption_method = 'none'

        return render_template("audio/decode-audio-result.html", 
                             file=filename, 
                             extracted_message=extracted_message, 
                             decrypted_message=decrypted_message, 
                             encryption_method=encryption_method)
    
    return render_template("audio/decode-audio.html")