import cv2
import numpy as np
import os
from flask import Blueprint, render_template, request, flash, redirect, url_for, send_from_directory, current_app
from flask_login import login_required
import logging
import pywt
from .utils import caesar_encrypt, caesar_decrypt, vigenere_encrypt, vigenere_decrypt, aes_encrypt, aes_decrypt

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Blueprint for video routes
video_bp = Blueprint('video', __name__, template_folder='../templates/video')

# Utility functions for converting text to bits and vice versa
def text_to_bits(text):
    return [int(bit) for char in text for bit in bin(ord(char))[2:].zfill(8)]

def bits_to_text(bits):
    chars = [chr(int(''.join(map(str, bits[i:i+8])), 2)) for i in range(0, len(bits), 8) if len(bits[i:i+8]) == 8]
    return ''.join(chars)

# Embed bits into a frame using DWT
def embed_dwt(frame, bits, bit_idx):
    gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY).astype(float)
    coeffs = pywt.dwt2(gray_frame, 'haar')
    LL, (LH, HL, HH) = coeffs
    flat_HH = HH.flatten()
    embed_capacity = len(flat_HH)
    
    original_hh_sample = flat_HH[:10].tolist()  # Sample before embedding
    for i in range(min(embed_capacity, len(bits) - bit_idx)):
        flat_HH[i] += (10 if bits[bit_idx + i] else -10)  # Increased to ±10
    
    HH = flat_HH.reshape(HH.shape)
    modified_frame = pywt.idwt2((LL, (LH, HL, HH)), 'haar')
    logger.debug(f"Embedded {min(embed_capacity, len(bits) - bit_idx)} bits at idx {bit_idx}, HH sample before={original_hh_sample}, after={flat_HH[:10].tolist()}")
    return cv2.cvtColor(np.clip(modified_frame, 0, 255).astype(np.uint8), cv2.COLOR_GRAY2BGR), bit_idx + min(embed_capacity, len(bits) - bit_idx)

# Extract bits from a frame using DWT
def extract_dwt(frame, num_bits, bit_idx):
    gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY).astype(float)
    _, (_, _, HH) = pywt.dwt2(gray_frame, 'haar')
    flat_HH = HH.flatten()
    embed_capacity = len(flat_HH)
    bits = []
    
    logger.debug(f"Extracting bits from frame: flat_HH sample={flat_HH[:10].tolist()}")
    
    for i in range(min(num_bits - bit_idx, embed_capacity)):
        bits.append(1 if flat_HH[i] > 5 else 0)  # Threshold > 5 for +10
    
    logger.debug(f"Extracted {len(bits)} bits from frame (capacity={embed_capacity}), bits={bits[:32]}")
    return bits, bit_idx + len(bits)

# Encode a message into a video
def encode_video(input_path, output_path, message, encrypt=False, encryption_method=None, encryption_key=None, use_avi=False):
    logger.debug(f"Encoding: input={input_path}, output={output_path}, message='{message}', use_avi={use_avi}")
    
    aes_key = None
    if encrypt:
        if encryption_method == "caesar":
            message = caesar_encrypt(message)
        elif encryption_method == "vigenere":
            if not encryption_key:
                raise ValueError("Vigenère encryption requires a key")
            message = vigenere_encrypt(message, encryption_key)
        elif encryption_method == "aes":
            message, aes_key = aes_encrypt(message)
        else:
            raise ValueError("Unsupported encryption method")
    
    message_bits = text_to_bits(message)
    length_bits = [int(bit) for bit in bin(len(message_bits))[2:].zfill(32)]
    data_bits = length_bits + message_bits
    logger.debug(f"Total bits to embed: {len(data_bits)}, length_bits={length_bits}")
    
    cap = cv2.VideoCapture(input_path)
    if not cap.isOpened():
        raise ValueError("Failed to open input video")
    
    frame_width, frame_height = int(cap.get(3)), int(cap.get(4))
    fps, total_frames = int(cap.get(5)), int(cap.get(7))
    bits_per_frame = (frame_width // 2) * (frame_height // 2)
    required_frames = (len(data_bits) + bits_per_frame - 1) // bits_per_frame
    if required_frames > total_frames:
        cap.release()
        raise ValueError(f"Video too short: need {required_frames} frames, got {total_frames}")
    
    fourcc = cv2.VideoWriter_fourcc(*'XVID') if use_avi else cv2.VideoWriter_fourcc(*'mp4v')
    output_ext = '.avi' if use_avi else '.mp4'
    output_path = os.path.splitext(output_path)[0] + output_ext
    out = cv2.VideoWriter(output_path, fourcc, fps, (frame_width, frame_height))
    
    bit_idx = 0
    frame_count = 0
    while cap.isOpened() and bit_idx < len(data_bits):
        ret, frame = cap.read()
        if not ret:
            break
        frame, bit_idx = embed_dwt(frame, data_bits, bit_idx)
        out.write(frame)
        frame_count += 1
        logger.debug(f"Encoded frame {frame_count}, bit_idx={bit_idx}")
    
    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break
        out.write(frame)
    
    cap.release()
    out.release()
    logger.debug(f"Encoded video saved to {output_path}")
    return aes_key if encryption_method == "aes" else None

# Decode a message from a video
def decode_video(input_path, decrypt=False, encryption_method=None, encryption_key=None):
    logger.debug(f"Decoding: input={input_path}")
    
    cap = cv2.VideoCapture(input_path)
    if not cap.isOpened():
        raise ValueError("Failed to open input video")
    
    # Extract length prefix (32 bits)
    length_bits = []
    bit_idx = 0
    while cap.isOpened() and bit_idx < 32:
        ret, frame = cap.read()
        if not ret:
            break
        bits, bit_idx = extract_dwt(frame, 32, bit_idx)
        length_bits.extend(bits)
    
    if len(length_bits) < 32:
        cap.release()
        raise ValueError("Video too short for length prefix")
    
    msg_len = int(''.join(map(str, length_bits)), 2)
    logger.debug(f"Message length: {msg_len} bits")
    
    # Sanity check
    max_bits = int(cap.get(7)) * (int(cap.get(3)) // 2) * (int(cap.get(4)) // 2)
    if msg_len > max_bits or msg_len < 8:
        cap.release()
        raise ValueError(f"Invalid message length: {msg_len} bits (max={max_bits}, min=8)")
    
    # Reset and extract message bits
    cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
    data_bits = []
    bit_idx = 0
    while cap.isOpened() and bit_idx < 32 + msg_len:
        ret, frame = cap.read()
        if not ret:
            break
        bits, bit_idx = extract_dwt(frame, 32 + msg_len, bit_idx)
        data_bits.extend(bits)
    
    cap.release()
    if len(data_bits) < 32 + msg_len:
        logger.warning(f"Extracted only {len(data_bits)} of {32 + msg_len} bits")
    
    extracted_message = bits_to_text(data_bits[32:32 + msg_len])
    logger.debug(f"Extracted message: '{extracted_message}'")
    
    decrypted_message = extracted_message
    if decrypt:
        if encryption_method == "caesar":
            decrypted_message = caesar_decrypt(extracted_message)
        elif encryption_method == "vigenere":
            if not encryption_key:
                raise ValueError("Vigenère decryption requires a key")
            decrypted_message = vigenere_decrypt(extracted_message, encryption_key)
        elif encryption_method == "aes":
            decrypted_message = aes_decrypt(extracted_message, encryption_key)
    
    logger.debug(f"Decrypted message: '{decrypted_message}'")
    return extracted_message, decrypted_message

# Flask routes for video encoding and decoding
@video_bp.route('/video_encode', methods=['GET', 'POST'])
@login_required
def video_encode():
    if request.method == 'POST':
        if 'video' not in request.files or not request.form.get('message'):
            flash('Missing video or message', 'error')
            return redirect(url_for('video.video_encode'))
        video = request.files['video']
        message = request.form.get('message')
        encrypt = request.form.get('encrypt') == 'yes'
        method = request.form.get('encryption_method') if encrypt else None
        key = request.form.get('encryption_key') if encrypt and method in ['vigenere', 'aes'] else None
        use_avi = request.form.get('output_format', 'mp4') == 'avi'  # Add this to your form
        
        input_path = os.path.join(current_app.config['UPLOAD_FOLDER'], 'input_video.mp4')
        output_path = os.path.join(current_app.config['UPLOAD_FOLDER'], 'encoded_video')
        video.save(input_path)
        try:
            aes_key = encode_video(input_path, output_path, message, encrypt, method, key, use_avi)
            flash('Video encoded successfully!', 'success')
            return render_template('encode-video-result.html', aes_key=aes_key, file=f"encoded_video.{ 'avi' if use_avi else 'mp4' }")
        except Exception as e:
            logger.error(f"Encoding error: {str(e)}")
            flash(f"Encoding failed: {str(e)}", 'error')
    return render_template('encode-video.html')

@video_bp.route('/video_decode', methods=['GET', 'POST'])
@login_required
def video_decode():
    if request.method == 'POST':
        if 'video' not in request.files:
            flash('No video file provided', 'error')
            return redirect(url_for('video.video_decode'))
        video = request.files['video']
        decrypt = request.form.get('decrypt') == 'yes'
        method = request.form.get('encryption_method') if decrypt else None
        key = request.form.get('aes_key') if decrypt and method == 'aes' else request.form.get('encryption_key') if decrypt else None
        
        input_path = os.path.join(current_app.config['UPLOAD_FOLDER'], video.filename)
        video.save(input_path)
        try:
            extracted, decrypted = decode_video(input_path, decrypt, method, key)
            flash('Video decoded successfully!', 'success')
            return render_template('decode-video-result.html', extracted_message=extracted, decrypted_message=decrypted)
        except Exception as e:
            logger.error(f"Decoding error: {str(e)}")
            flash(f"Decoding failed: {str(e)}", 'error')
    return render_template('decode-video.html')

@video_bp.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename)
    flash('File not found', 'error')
    return redirect(url_for('video.video_encode'))