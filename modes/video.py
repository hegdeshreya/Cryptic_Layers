import os
import cv2
import numpy as np
import subprocess
from flask import Blueprint, current_app, render_template, request, flash, redirect, url_for, send_file
from flask_login import login_required
from werkzeug.utils import secure_filename
from .utils import caesar_encrypt, caesar_decrypt, vigenere_encrypt, vigenere_decrypt, aes_encrypt, aes_decrypt, columnar_encrypt, columnar_decrypt, ecc_encrypt, ecc_decrypt, ecc_generate_keys
import pywt
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Blueprint for video routes
video_bp = Blueprint("video", __name__, template_folder="templates/video")

# Allowed video file extensions
ALLOWED_EXTENSIONS = {'mp4', 'avi'}

def allowed_file(filename):
    """Check if the file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@video_bp.route('/Uploads/<filename>')
@login_required
def uploaded_file(filename):
    """Serve uploaded files."""
    file_path = os.path.join(current_app.config['UPLOAD_VIDEO_FOLDER'], filename)
    if not os.path.exists(file_path):
        logger.error(f"File not found: {file_path}")
        flash("File not found!", "error")
        return redirect(url_for('video.video_encode'))
    return send_file(file_path, as_attachment=True, download_name=filename)

# Helper functions
def extract_audio(video_path, audio_path):
    """Extract audio from a video file using FFmpeg."""
    try:
        video_path = os.path.abspath(video_path)
        audio_path = os.path.abspath(audio_path)
        logger.debug(f"Video path: {video_path}")
        logger.debug(f"Audio path: {audio_path}")

        if not os.path.exists(video_path):
            logger.error(f"Video file does not exist: {video_path}")
            raise FileNotFoundError(f"Video file does not exist: {video_path}")

        os.makedirs(os.path.dirname(audio_path), exist_ok=True)

        command = [
            r"C:\ffmpeg\bin\ffmpeg.exe",
            "-i", video_path,
            "-q:a", "0",
            "-map", "0:a:0",
            audio_path,
            "-y"
        ]
        logger.debug(f"Running FFmpeg command: {' '.join(command)}")

        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        logger.debug(f"Audio extracted to: {audio_path}")
    except subprocess.CalledProcessError as e:
        logger.error(f"FFmpeg error: {e.stderr}")
        raise RuntimeError(f"FFmpeg failed: {e.stderr}")
    except FileNotFoundError as e:
        logger.error(f"File not found: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error extracting audio: {str(e)}")
        raise

def merge_audio(video_path, audio_path, output_path):
    """Merge audio back into a video file using FFmpeg."""
    try:
        video_path = os.path.abspath(video_path)
        audio_path = os.path.abspath(audio_path)
        output_path = os.path.abspath(output_path)
        logger.debug(f"Video path: {video_path}")
        logger.debug(f"Audio path: {audio_path}")
        logger.debug(f"Output path: {output_path}")

        command = [
            r"C:\ffmpeg\bin\ffmpeg.exe",
            "-i", video_path,
            "-i", audio_path,
            "-c:v", "copy",
            "-c:a", "aac",
            "-map", "0:v:0",
            "-map", "1:a:0",
            "-shortest",
            output_path,
            "-y"
        ]
        logger.debug(f"Running FFmpeg command: {' '.join(command)}")

        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        logger.debug(f"Audio merged into: {output_path}")
    except subprocess.CalledProcessError as e:
        logger.error(f"FFmpeg error: {e.stderr}")
        raise RuntimeError(f"FFmpeg failed: {e.stderr}")
    except Exception as e:
        logger.error(f"Unexpected error merging audio: {str(e)}")
        raise

def text_to_bits(text):
    """Convert text to a list of bits."""
    return [int(bit) for char in text for bit in bin(ord(char))[2:].zfill(8)]

def bits_to_text(bits):
    """Convert a list of bits back to text."""
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) == 8:
            chars.append(chr(int(''.join(map(str, byte)), 2)))
    return ''.join(chars)

def embed_dwt(frame, bits, bit_idx):
    """Embed bits into a frame using DWT."""
    gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY).astype(float)
    coeffs = pywt.dwt2(gray_frame, 'haar')
    LL, (LH, HL, HH) = coeffs
    flat_HH = HH.flatten()
    embed_capacity = len(flat_HH)
    for i in range(min(embed_capacity, len(bits) - bit_idx)):
        flat_HH[i] += (50 if bits[bit_idx + i] else -50)
    HH = flat_HH.reshape(HH.shape)
    modified_frame = pywt.idwt2((LL, (LH, HL, HH)), 'haar')
    return cv2.cvtColor(np.clip(modified_frame, 0, 255).astype(np.uint8), cv2.COLOR_GRAY2BGR), bit_idx + min(embed_capacity, len(bits) - bit_idx)

def extract_dwt(frame, num_bits, bit_idx):
    """Extract bits from a frame using DWT."""
    gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY).astype(float)
    _, (_, _, HH) = pywt.dwt2(gray_frame, 'haar')
    flat_HH = HH.flatten()
    embed_capacity = len(flat_HH)
    bits = []
    for i in range(min(num_bits - bit_idx, embed_capacity)):
        bits.append(1 if flat_HH[i] > 25 else 0)
    return bits, bit_idx + len(bits)

def encode_video(input_path, output_path, message):
    """Encode a message into a video file."""
    try:
        audio_path = os.path.join(current_app.config['UPLOAD_VIDEO_FOLDER'], "temp_audio.aac")
        extract_audio(input_path, audio_path)

        message_bits = text_to_bits(message)
        length_bits = [int(bit) for bit in bin(len(message_bits))[2:].zfill(32)]
        data_bits = length_bits + message_bits
        logger.debug(f"Encoding {len(data_bits)} bits (32 length + {len(message_bits)} message)")

        cap = cv2.VideoCapture(input_path)
        frame_width = int(cap.get(3))
        frame_height = int(cap.get(4))
        fps = int(cap.get(5))
        frame_count = int(cap.get(7))
        logger.debug(f"Video has {frame_count} frames, {frame_width}x{frame_height}, {fps} fps")
        fourcc = cv2.VideoWriter_fourcc(*'avc1')

        temp_video_path = os.path.join(current_app.config['UPLOAD_VIDEO_FOLDER'], "temp_video.mp4")
        out = cv2.VideoWriter(temp_video_path, fourcc, fps, (frame_width, frame_height))

        bit_idx = 0
        frame_idx = 0
        while cap.isOpened() and bit_idx < len(data_bits):
            ret, frame = cap.read()
            if not ret:
                logger.warning(f"Ran out of frames at frame {frame_idx} with {len(data_bits) - bit_idx} bits remaining")
                break
            frame, bit_idx = embed_dwt(frame, data_bits, bit_idx)
            out.write(frame)
            frame_idx += 1
        logger.debug(f"Embedded {bit_idx} bits in {frame_idx} frames")

        while cap.isOpened():
            ret, frame = cap.read()
            if not ret:
                break
            out.write(frame)
            frame_idx += 1
        logger.debug(f"Processed {frame_idx} total frames")

        cap.release()
        out.release()

        merge_audio(temp_video_path, audio_path, output_path)

        os.remove(temp_video_path)
        os.remove(audio_path)

        logger.debug(f"Video encoded and saved to: {output_path}")
    except Exception as e:
        logger.error(f"Error encoding video: {e}")
        raise

def decode_video(input_path):
    """Decode a message from a video file."""
    try:
        cap = cv2.VideoCapture(input_path)
        frame_count = int(cap.get(7))
        logger.debug(f"Decoding from video with {frame_count} frames")

        length_bits = []
        bit_idx = 0
        frame_idx = 0
        while cap.isOpened() and bit_idx < 32:
            ret, frame = cap.read()
            if not ret:
                logger.error(f"Ran out of frames at frame {frame_idx} while extracting length")
                raise RuntimeError("Insufficient frames to extract message length")
            bits, bit_idx = extract_dwt(frame, 32, bit_idx)
            length_bits.extend(bits)
            frame_idx += 1
        msg_len = int(''.join(map(str, length_bits)), 2)
        logger.debug(f"Extracted message length: {msg_len} bits")

        data_bits = []
        bit_idx = 0
        cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
        frame_idx = 0
        while cap.isOpened() and bit_idx < 32 + msg_len:
            ret, frame = cap.read()
            if not ret:
                logger.error(f"Ran out of frames at frame {frame_idx} while extracting {32 + msg_len - bit_idx} remaining bits")
                raise RuntimeError("Insufficient frames to extract message")
            bits, bit_idx = extract_dwt(frame, 32 + msg_len, bit_idx)
            data_bits.extend(bits)
            frame_idx += 1
        logger.debug(f"Extracted {len(data_bits)} bits in {frame_idx} frames")

        cap.release()
        extracted_message = bits_to_text(data_bits[32:32 + msg_len])
        logger.debug(f"Raw extracted message: {extracted_message}")
        return extracted_message
    except Exception as e:
        logger.error(f"Error decoding video: {e}")
        raise

@video_bp.route("/video_encode", methods=['GET', 'POST'])
@login_required
def video_encode():
    """Handle video encoding requests."""
    if request.method == 'POST':
        message = request.form.get('message', '').strip()
        encrypt = request.form.get('encrypt', 'no')
        encryption_method = request.form.get('encryption_method', '')
        encryption_key = request.form.get('encryption_key', '').strip()

        logger.debug(f"Form data: message='{message}', encrypt='{encrypt}', encryption_method='{encryption_method}', encryption_key='{encryption_key}'")

        if not message:
            flash("Message cannot be empty!", "error")
            return redirect(url_for('video.video_encode'))

        file = request.files.get('video')
        if not file or file.filename == '' or not allowed_file(file.filename):
            flash("Only MP4 and AVI files are supported.", "error")
            return redirect(url_for('video.video_encode'))

        filename = secure_filename(file.filename)
        upload_folder = current_app.config['UPLOAD_VIDEO_FOLDER']
        logger.debug(f"Upload folder: {upload_folder}")
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
                    logger.debug(f"Encrypted message (Caesar): {encrypted_message}")
                elif encryption_method == 'vigenere':
                    if not encryption_key:
                        flash("Vigenère cipher key is required!", "error")
                        return redirect(url_for('video.video_encode'))
                    encrypted_message = vigenere_encrypt(message, encryption_key)
                    vigenere_key = encryption_key
                    logger.debug(f"Encrypted message (Vigenère): {encrypted_message}")
                elif encryption_method == 'aes':
                    encrypted_message, aes_key = aes_encrypt(message)
                    logger.debug(f"Encrypted message (AES): {encrypted_message}")
                elif encryption_method == 'columnar':
                    if not encryption_key:
                        flash("Columnar cipher key is required!", "error")
                        return redirect(url_for('video.video_encode'))
                    encrypted_message = columnar_encrypt(message, encryption_key)
                    columnar_key = encryption_key
                    logger.debug(f"Encrypted message (Columnar): {encrypted_message}")
                elif encryption_method == 'ecc':
                    logger.debug("Attempting ECC encryption")
                    try:
                        public_key, private_key = ecc_generate_keys()
                        logger.debug(f"ECC keys generated: public_key={public_key[:50]}..., private_key={private_key[:50]}...")
                        encrypted_message = ecc_encrypt(message, public_key)
                        if isinstance(encrypted_message, str) and "Encryption failed" in encrypted_message:
                            logger.error(f"ECC encryption failed: {encrypted_message}")
                            flash(encrypted_message, "error")
                            return redirect(url_for('video.video_encode'))
                        ecc_key = private_key
                        logger.debug(f"ECC private key serialized: {ecc_key[:50]}...")
                        # Test decryption to verify key
                        test_decrypt = ecc_decrypt(encrypted_message, ecc_key)
                        logger.debug(f"Test decryption result: {test_decrypt}")
                        if isinstance(test_decrypt, str) and "Decryption failed" in test_decrypt:
                            logger.error(f"Test decryption failed: {test_decrypt}")
                            flash(f"ECC test decryption failed: {test_decrypt}", "error")
                            return redirect(url_for('video.video_encode'))
                        logger.debug(f"Encrypted message (ECC): {encrypted_message[:50]}...")
                    except Exception as e:
                        logger.error(f"ECC encryption error: {str(e)}")
                        flash(f"ECC encryption failed: {str(e)}", "error")
                        return redirect(url_for('video.video_encode'))
            except Exception as e:
                logger.error(f"Encryption failed: {str(e)}")
                flash(f"Encryption failed: {str(e)}", "error")
                return redirect(url_for('video.video_encode'))
        else:
            encryption_method = 'none'

        logger.debug(f"Encryption result: encrypted_message='{encrypted_message[:50]}...', aes_key={aes_key}, vigenere_key={vigenere_key}, columnar_key={columnar_key}, ecc_key={ecc_key[:50] if ecc_key else None}...")

        try:
            output_filename = f"encoded_{filename}"
            output_path = os.path.join(upload_folder, output_filename)
            encode_video(file_path, output_path, encrypted_message)
        except Exception as e:
            flash(f"Error encoding message: {e}", "error")
            return redirect(url_for('video.video_encode'))

        return render_template("video/encode-video-result.html", 
                              file=output_filename, 
                              message=message, 
                              encrypted_message=encrypted_message, 
                              encryption_method=encryption_method, 
                              aes_key=aes_key, 
                              vigenere_key=vigenere_key if encryption_method == 'vigenere' else None, 
                              columnar_key=columnar_key if encryption_method == 'columnar' else None,
                              ecc_key=ecc_key if encryption_method == 'ecc' else None)

    return render_template("video/encode-video.html")

@video_bp.route("/video_decode", methods=['GET', 'POST'])
@login_required
def video_decode():
    """Handle video decoding requests."""
    if request.method == 'POST':
        file = request.files.get('video')
        if not file or file.filename == '' or not allowed_file(file.filename):
            flash("Only MP4 and AVI files are supported for decoding.", "error")
            return redirect(url_for('video.video_decode'))

        filename = secure_filename(file.filename)
        upload_folder = current_app.config['UPLOAD_VIDEO_FOLDER']
        logger.debug(f"Upload folder: {upload_folder}")
        os.makedirs(upload_folder, exist_ok=True)
        file_path = os.path.join(upload_folder, filename)
        file.save(file_path)

        try:
            extracted_message = decode_video(file_path)
            if not extracted_message:
                flash("No message found in the video file!", "error")
                return redirect(url_for('video.video_decode'))
            logger.debug(f"Extracted message: {extracted_message[:50]}...")
        except Exception as e:
            flash(f"Error decoding video: {e}", "error")
            return redirect(url_for('video.video_decode'))

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
                    logger.debug(f"Decrypted message (Caesar): {decrypted_message}")
                elif encryption_method == 'vigenere':
                    if not vigenere_key:
                        flash("Vigenère key is required!", "error")
                        return redirect(url_for('video.video_decode'))
                    decrypted_message = vigenere_decrypt(extracted_message, vigenere_key)
                    logger.debug(f"Decrypted message (Vigenère): {decrypted_message}")
                elif encryption_method == 'aes':
                    if not aes_key:
                        flash("AES key is required!", "error")
                        return redirect(url_for('video.video_decode'))
                    decrypted_message = aes_decrypt(extracted_message, aes_key)
                    logger.debug(f"Decrypted message (AES): {decrypted_message}")
                    if isinstance(decrypted_message, str) and "Decryption failed" in decrypted_message:
                        flash(decrypted_message, "error")
                        return redirect(url_for('video.video_decode'))
                elif encryption_method == 'columnar':
                    if not columnar_key:
                        flash("Columnar key is required!", "error")
                        return redirect(url_for('video.video_decode'))
                    decrypted_message = columnar_decrypt(extracted_message, columnar_key)
                    logger.debug(f"Decrypted message (Columnar): {decrypted_message}")
                elif encryption_method == 'ecc':
                    if not ecc_key:
                        flash("ECC private key is required!", "error")
                        return redirect(url_for('video.video_decode'))
                    logger.debug(f"Received ECC private key: {ecc_key[:50]}...")
                    try:
                        decrypted_message = ecc_decrypt(extracted_message, ecc_key)
                        if isinstance(decrypted_message, str) and "Decryption failed" in decrypted_message:
                            logger.error(f"ECC decryption failed: {decrypted_message}")
                            flash(decrypted_message, "error")
                            return redirect(url_for('video.video_decode'))
                        logger.debug(f"Decrypted message (ECC): {decrypted_message}")
                    except Exception as e:
                        logger.error(f"ECC decryption error: {str(e)}")
                        flash(f"ECC decryption failed: {str(e)}", "error")
                        return redirect(url_for('video.video_decode'))
            except Exception as e:
                logger.error(f"Decryption failed: {str(e)}")
                flash(f"Decryption failed: {str(e)}", "error")
                return redirect(url_for('video.video_decode'))
        else:
            encryption_method = 'none'

        return render_template("video/decode-video-result.html", 
                              file=filename, 
                              extracted_message=extracted_message, 
                              decrypted_message=decrypted_message, 
                              encryption_method=encryption_method, 
                              vigenere_key=vigenere_key if encryption_method == 'vigenere' else None, 
                              aes_key=aes_key if encryption_method == 'aes' else None, 
                              columnar_key=columnar_key if encryption_method == 'columnar' else None, 
                              ecc_key=ecc_key if encryption_method == 'ecc' else None)

    return render_template("video/decode-video.html")