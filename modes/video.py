# modes/video.py
import cv2
import numpy as np
import os
from flask import Blueprint, render_template, request, flash, redirect, url_for, send_from_directory, current_app
from flask_login import login_required
import logging  # Added for debugging
from .utils import caesar_encrypt, caesar_decrypt, vigenere_encrypt, vigenere_decrypt, aes_encrypt, aes_decrypt
# Set up logging


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

video_bp = Blueprint('video', __name__, template_folder='../templates/video')

def text_to_bits(text):
    return [int(bit) for char in text for bit in bin(ord(char))[2:].zfill(8)]

def bits_to_text(bits):
    chars = [chr(int(''.join(map(str, bits[i:i+8])), 2)) for i in range(0, len(bits), 8) if len(bits[i:i+8]) == 8]
    return ''.join(chars)

def encode_video(input_path, output_path, message, encrypt=False, encryption_method=None, encryption_key=None):
    logger.debug(f"Starting encode_video with input: {input_path}, output: {output_path}, message length: {len(message)}")
    
    # Encrypt message if requested
    aes_key = None
    if encrypt:
        if encryption_method == "caesar":
            message = caesar_encrypt(message)
        elif encryption_method == "vigenere":
            if not encryption_key:
                raise ValueError("Vigenère encryption requires a key")
            message = vigenere_encrypt(message, encryption_key)
        elif encryption_method == "aes":
            encrypted_message, aes_key = aes_encrypt(message)
            message = encrypted_message
        else:
            raise ValueError("Unsupported encryption method")

    # Convert message to bits with 32-bit length prefix
    message_bits = text_to_bits(message)
    length_bits = [int(bit) for bit in bin(len(message_bits))[2:].zfill(32)]
    data_bits = length_bits + message_bits
    logger.debug(f"Total bits to embed: {len(data_bits)}")

    # Open video
    cap = cv2.VideoCapture(input_path)
    if not cap.isOpened():
        raise ValueError("Failed to open input video")

    frame_width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    frame_height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    fps = int(cap.get(cv2.CAP_PROP_FPS))
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))

    bits_per_frame = frame_width * frame_height * 3
    required_frames = (len(data_bits) + bits_per_frame - 1) // bits_per_frame
    if required_frames > total_frames:
        cap.release()
        raise ValueError(f"Video too short. Need {required_frames} frames, got {total_frames}")

    # Output video as MP4
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    out = cv2.VideoWriter(output_path, fourcc, fps, (frame_width, frame_height))
    if not out.isOpened():
        cap.release()
        raise ValueError("Failed to open output video writer. Check OpenCV codec support.")

    bit_idx = 0
    frames_processed = 0

    # Encode only required frames
    while cap.isOpened() and bit_idx < len(data_bits) and frames_processed < required_frames:
        ret, frame = cap.read()
        if not ret:
            break
        frames_processed += 1

        flat_frame = frame.reshape(-1, 3)
        pixels_to_modify = min(len(flat_frame), (len(data_bits) - bit_idx + 2) // 3)

        for i in range(pixels_to_modify):
            if bit_idx >= len(data_bits):
                break
            for channel in range(3):
                if bit_idx < len(data_bits):
                    flat_frame[i, channel] = (flat_frame[i, channel] & 0xFE) | data_bits[bit_idx]
                    bit_idx += 1

        frame = flat_frame.reshape(frame_height, frame_width, 3)
        out.write(frame)
        logger.debug(f"Frame {frames_processed}: Embedded {bit_idx} bits")

    # Copy remaining frames unchanged
    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break
        out.write(frame)

    cap.release()
    out.release()
    cv2.destroyAllWindows()
    logger.debug(f"Encoding complete. Output file: {output_path}, size: {os.path.getsize(output_path) if os.path.exists(output_path) else 'Not found'}")
    return aes_key if encryption_method == "aes" else None

def decode_video(input_path, decrypt=False, encryption_method=None, encryption_key=None):
    logger.debug(f"Starting decode_video with input: {input_path}")
    
    cap = cv2.VideoCapture(input_path)
    if not cap.isOpened():
        raise ValueError("Failed to open input video")

    # Extract 32-bit length prefix
    length_bits = []
    bit_count = 0
    while cap.isOpened() and bit_count < 32:
        ret, frame = cap.read()
        if not ret:
            break
        flat_frame = frame.reshape(-1, 3)
        for i in range(min(len(flat_frame), (32 - bit_count + 2) // 3)):
            for channel in range(3):
                if bit_count < 32:
                    length_bits.append(flat_frame[i, channel] & 1)
                    bit_count += 1

    if len(length_bits) < 32:
        cap.release()
        raise ValueError("Video too short for length prefix")

    msg_len = int(''.join(map(str, length_bits)), 2)
    logger.debug(f"Extracted message length: {msg_len}")
    if msg_len <= 0 or msg_len > 1_000_000:
        cap.release()
        raise ValueError(f"Invalid message length: {msg_len}")

    # Extract message bits
    data_bits = []
    bit_count = 0
    while cap.isOpened() and bit_count < msg_len * 8:
        ret, frame = cap.read()
        if not ret:
            break
        flat_frame = frame.reshape(-1, 3)
        for i in range(min(len(flat_frame), (msg_len * 8 - bit_count + 2) // 3)):
            for channel in range(3):
                if bit_count < msg_len * 8:
                    data_bits.append(flat_frame[i, channel] & 1)
                    bit_count += 1

    cap.release()
    cv2.destroyAllWindows()

    if len(data_bits) < msg_len * 8:
        raise ValueError(f"Not enough bits extracted: got {len(data_bits)}, expected {msg_len * 8}")

    extracted_message = bits_to_text(data_bits)
    decrypted_message = extracted_message
    if decrypt:
        if encryption_method == "caesar":
            decrypted_message = caesar_decrypt(extracted_message)
        elif encryption_method == "vigenere":
            if not encryption_key:
                raise ValueError("Vigenère decryption requires a key")
            decrypted_message = vigenere_decrypt(extracted_message, encryption_key)
        elif encryption_method == "aes":
            if not encryption_key:
                raise ValueError("AES decryption requires a key")
            decrypted_message = aes_decrypt(extracted_message, encryption_key)
        else:
            raise ValueError("Unsupported decryption method")

    logger.debug(f"Decoded: Extracted='{extracted_message}', Decrypted='{decrypted_message}'")
    return extracted_message, decrypted_message

@video_bp.route('/video_encode', methods=['GET', 'POST'])
@login_required
def video_encode():
    if request.method == 'POST':
        if 'video' not in request.files:
            flash('No video file provided', 'error')
            return redirect(request.url)
        video = request.files['video']
        message = request.form.get('message')
        encrypt = request.form.get('encrypt') == 'yes'
        method = request.form.get('encryption_method') if encrypt else None
        key = request.form.get('encryption_key') if encrypt and method in ['vigenere'] else None

        if video and message:
            input_path = os.path.join(current_app.config['UPLOAD_FOLDER'], 'input_video.mp4')
            output_path = os.path.join(current_app.config['UPLOAD_FOLDER'], 'encoded_video.mp4')
            video.save(input_path)
            try:
                aes_key = encode_video(input_path, output_path, message, encrypt, method, key)
                if not os.path.exists(output_path):
                    raise ValueError("Output file was not created")
                flash('Video encoded successfully!', 'success')
                return render_template('encode-video-result.html', aes_key=aes_key, file='encoded_video.mp4')
            except Exception as e:
                logger.error(f"Encoding error: {str(e)}")
                flash(f"Encoding failed: {str(e)}", 'error')
                return redirect(request.url)
        else:
            flash('Missing video or message', 'error')
    return render_template('encode-video.html')

@video_bp.route('/video_decode', methods=['GET', 'POST'])
@login_required
def video_decode():
    if request.method == 'POST':
        if 'video' not in request.files:
            flash('No video file provided', 'error')
            return redirect(request.url)
        video = request.files['video']
        decrypt = request.form.get('decrypt') == 'yes'
        method = request.form.get('encryption_method') if decrypt else None
        key = request.form.get('encryption_key') if decrypt and method == 'vigenere' else request.form.get('aes_key') if decrypt and method == 'aes' else None

        if video:
            input_path = os.path.join(current_app.config['UPLOAD_FOLDER'], 'encoded_video.mp4')
            video.save(input_path)
            try:
                extracted, decrypted = decode_video(input_path, decrypt, method, key)
                flash('Video decoded successfully!', 'success')
                return render_template('decode-video-result.html', 
                                     extracted_message=extracted, 
                                     decrypted_message=decrypted, 
                                     encryption_method=method)
            except Exception as e:
                logger.error(f"Decoding error: {str(e)}")
                flash(f"Decoding failed: {str(e)}", 'error')
                return redirect(request.url)
        else:
            flash('Missing video', 'error')
    return render_template('decode-video.html')

@video_bp.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename)
    else:
        flash('File not found', 'error')
        return redirect(url_for('video.video_encode'))