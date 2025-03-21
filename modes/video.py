import os
import cv2
import numpy as np
import subprocess
from flask import Blueprint, current_app, render_template, request, flash, redirect, url_for, send_file
from flask_login import login_required
from werkzeug.utils import secure_filename
from .utils import caesar_encrypt, caesar_decrypt, vigenere_encrypt, vigenere_decrypt, aes_encrypt, aes_decrypt, columnar_encrypt, columnar_decrypt
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

@video_bp.route('/uploads/<filename>')
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
        command = [r"C:\ffmpeg\bin\ffmpeg.exe", "-i", video_path, "-q:a", "0", "-map", "a", audio_path, "-y"]
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        logger.debug(f"Audio extracted to: {audio_path}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error extracting audio: {e}")
        raise

def merge_audio(video_path, audio_path, output_path):
    """Merge audio back into a video file using FFmpeg."""
    try:
        command = [r"C:\ffmpeg\bin\ffmpeg.exe", "-i", video_path, "-i", audio_path, "-c:v", "copy", "-c:a", "aac", "-strict", "experimental", output_path, "-y"]
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        logger.debug(f"Audio merged into: {output_path}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error merging audio: {e}")
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
        flat_HH[i] += (20 if bits[bit_idx + i] else -20)  # Modify HH coefficients
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
        bits.append(1 if flat_HH[i] > 10 else 0)  # Extract bits from HH coefficients
    return bits, bit_idx + len(bits)

def encode_video(input_path, output_path, message):
    """Encode a message into a video file."""
    try:
        # Extract audio from the input video
        audio_path = os.path.join(current_app.config['UPLOAD_VIDEO_FOLDER'], "temp_audio.aac")
        extract_audio(input_path, audio_path)

        # Convert the message to bits
        message_bits = text_to_bits(message)
        length_bits = [int(bit) for bit in bin(len(message_bits))[2:].zfill(32)]
        data_bits = length_bits + message_bits

        # Open the input video
        cap = cv2.VideoCapture(input_path)
        frame_width = int(cap.get(3))
        frame_height = int(cap.get(4))
        fps = int(cap.get(5))
        fourcc = cv2.VideoWriter_fourcc(*'avc1')  # Use H.264 codec

        # Create a temporary video file
        temp_video_path = os.path.join(current_app.config['UPLOAD_VIDEO_FOLDER'], "temp_video.mp4")
        out = cv2.VideoWriter(temp_video_path, fourcc, fps, (frame_width, frame_height))

        # Embed the message into the video frames
        bit_idx = 0
        while cap.isOpened() and bit_idx < len(data_bits):
            ret, frame = cap.read()
            if not ret:
                break
            frame, bit_idx = embed_dwt(frame, data_bits, bit_idx)
            out.write(frame)

        # Write the remaining frames (if any)
        while cap.isOpened():
            ret, frame = cap.read()
            if not ret:
                break
            out.write(frame)

        # Release resources
        cap.release()
        out.release()

        # Merge the extracted audio back into the video
        merge_audio(temp_video_path, audio_path, output_path)

        # Clean up temporary files
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
        length_bits = []
        bit_idx = 0
        while cap.isOpened() and bit_idx < 32:
            ret, frame = cap.read()
            if not ret:
                break
            bits, bit_idx = extract_dwt(frame, 32, bit_idx)
            length_bits.extend(bits)
        msg_len = int(''.join(map(str, length_bits)), 2)
        logger.debug(f"Extracted message length: {msg_len}")

        data_bits = []
        bit_idx = 0
        cap.set(cv2.CAP_PROP_POS_FRAMES, 0)  # Reset to start
        while cap.isOpened() and bit_idx < 32 + msg_len:
            ret, frame = cap.read()
            if not ret:
                break
            bits, bit_idx = extract_dwt(frame, 32 + msg_len, bit_idx)
            data_bits.extend(bits)

        cap.release()
        extracted_message = bits_to_text(data_bits[32:32 + msg_len])
        logger.debug(f"Extracted bits: {data_bits[32:32 + msg_len]}")
        logger.debug(f"Extracted message: {extracted_message}")
        return extracted_message
    except Exception as e:
        logger.error(f"Error decoding video: {e}")
        raise

@video_bp.route("/video_encode", methods=['GET', 'POST'])
@login_required
def video_encode():
    """Handle video encoding requests."""
    if request.method == 'POST':
        message = request.form.get('message', '')
        encrypt = request.form.get('encrypt', 'no')
        encryption_method = request.form.get('encryption_method', '')
        key = request.form.get('encryption_key', '').strip()

        if not message:
            flash("Message cannot be empty!", "error")
            return redirect(url_for('video.video_encode'))

        file = request.files.get('video')
        if not file or file.filename == '' or not allowed_file(file.filename):
            flash("Only MP4 and AVI files are supported.", "error")
            return redirect(url_for('video.video_encode'))

        filename = secure_filename(file.filename)
        upload_folder = current_app.config['UPLOAD_VIDEO_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        file_path = os.path.join(upload_folder, filename)
        file.save(file_path)

        encrypted_message = message
        aes_key = None
        if encrypt == 'yes' and encryption_method:
            if encryption_method == 'caesar':
                encrypted_message = caesar_encrypt(message)
            elif encryption_method == 'vigenere':
                if not key:
                    flash("Vigenère cipher key is required!", "error")
                    return redirect(url_for('video.video_encode'))
                encrypted_message = vigenere_encrypt(message, key)
            elif encryption_method == 'aes':
                encrypted_message, aes_key = aes_encrypt(message)
            elif encryption_method == 'columnar':
                if not key:
                    flash("Columnar cipher key is required!", "error")
                    return redirect(url_for('video.video_encode'))
                encrypted_message = columnar_encrypt(message, key)

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
                              aes_key=aes_key)

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
        os.makedirs(upload_folder, exist_ok=True)
        file_path = os.path.join(upload_folder, filename)
        file.save(file_path)

        try:
            extracted_message = decode_video(file_path)
            if not extracted_message:
                flash("No message found in the video file!", "error")
                return redirect(url_for('video.video_decode'))
        except Exception as e:
            flash(f"Error decoding video: {e}", "error")
            return redirect(url_for('video.video_decode'))

        decrypt = request.form.get('decrypt', 'no')
        encryption_method = request.form.get('encryption_method', '')
        key = request.form.get('encryption_key', '').strip()
        aes_key = request.form.get('aes_key', '').strip()
        decrypted_message = extracted_message

        if decrypt == 'yes' and encryption_method:
            try:
                if encryption_method == 'caesar':
                    decrypted_message = caesar_decrypt(extracted_message)
                elif encryption_method == 'vigenere':
                    if not key:
                        flash("Vigenère key is required!", "error")
                        return redirect(url_for('video.video_decode'))
                    decrypted_message = vigenere_decrypt(extracted_message, key)
                elif encryption_method == 'aes':
                    if not aes_key:
                        flash("AES key is required!", "error")
                        return redirect(url_for('video.video_decode'))
                    decrypted_message = aes_decrypt(extracted_message, aes_key)
                elif encryption_method == 'columnar':
                    if not key:
                        flash("Columnar cipher key is required!", "error")
                        return redirect(url_for('video.video_decode'))
                    decrypted_message = columnar_decrypt(extracted_message, key)
            except Exception as e:
                flash(f"Decryption failed: {str(e)}", "error")
                return redirect(url_for('video.video_decode'))
        else:
            encryption_method = 'none'

        return render_template("video/decode-video-result.html", 
                              file=filename, 
                              extracted_message=extracted_message, 
                              decrypted_message=decrypted_message, 
                              encryption_method=encryption_method)

    return render_template("video/decode-video.html")