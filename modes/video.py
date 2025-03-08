import cv2
import numpy as np
import os
import shutil
from subprocess import check_call, STDOUT
from flask import Blueprint, render_template, request, flash, redirect, url_for, send_from_directory, current_app
from flask_login import login_required
import logging
from stegano import lsb
from .utils import caesar_encrypt, caesar_decrypt, vigenere_encrypt, vigenere_decrypt, aes_encrypt, aes_decrypt

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

video_bp = Blueprint('video', __name__, template_folder='../templates/video')
FFMPEG_PATH = r"C:\ffmpeg-7.1-essentials_build\bin\ffmpeg.exe"

def frame_extraction(video_path, output_dir="./tmp"):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    logger.debug(f"Extracting frames from {video_path} to {output_dir}")
    cap = cv2.VideoCapture(video_path)
    count = 0
    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break
        cv2.imwrite(os.path.join(output_dir, f"{count}.png"), frame)
        count += 1
    cap.release()
    logger.debug(f"Extracted {count} frames")
    return count

def split_message(message, frame_count):
    chunk_size = max(1, (len(message) + frame_count - 1) // frame_count)
    chunks = [message[i:i + chunk_size] for i in range(0, len(message), chunk_size)]
    logger.debug(f"Split message into {len(chunks)} chunks for {frame_count} frames")
    return chunks

def encode_video(input_path, output_path, message, encrypt=False, encryption_method=None, encryption_key=None, output_format='avi'):
    logger.debug(f"Starting encode_video: input={input_path}, output={output_path}, message_len={len(message)}, format={output_format}")
    
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

    # Extract frames
    tmp_dir = "./tmp"
    frame_count = frame_extraction(input_path, tmp_dir)
    if frame_count == 0:
        raise ValueError("No frames extracted from video")

    # Split message into chunks
    message_chunks = split_message(message, frame_count)

    # Embed message into frames
    for i, chunk in enumerate(message_chunks):
        if i >= frame_count:
            break
        frame_path = os.path.join(tmp_dir, f"{i}.png")
        secret = lsb.hide(frame_path, chunk)
        secret.save(frame_path)
        logger.debug(f"Embedded '{chunk}' into {frame_path}")

    # Rebuild video
    output_cmd = [FFMPEG_PATH, "-i", f"{tmp_dir}/%d.png", "-c:v", "ffv1", "-y", output_path]
    logger.debug(f"Running FFmpeg: {' '.join(output_cmd)}")
    try:
        check_call(output_cmd, stdout=open(os.devnull, "w"), stderr=STDOUT)
    except Exception as e:
        raise ValueError(f"FFmpeg encoding failed: {str(e)}")
    finally:
        if os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir)
            logger.debug("Cleaned up tmp directory")

    return aes_key if encryption_method == "aes" else None

def decode_video(input_path, decrypt=False, encryption_method=None, encryption_key=None):
    logger.debug(f"Starting decode_video: input={input_path}")
    
    # Extract frames
    tmp_dir = "./tmp"
    frame_count = frame_extraction(input_path, tmp_dir)
    if frame_count == 0:
        raise ValueError("No frames extracted from video")

    # Decode message from frames
    message_chunks = []
    for i in range(frame_count):
        frame_path = os.path.join(tmp_dir, f"{i}.png")
        try:
            chunk = lsb.reveal(frame_path)
            if chunk is None:
                logger.debug(f"No more data in frame {i}, stopping")
                break
            message_chunks.append(chunk)
            logger.debug(f"Extracted '{chunk}' from {frame_path}")
        except Exception as e:
            logger.warning(f"Error decoding frame {i}: {str(e)}")
            break

    extracted_message = ''.join(message_chunks)
    logger.debug(f"Extracted message: '{extracted_message}'")

    decrypted_message = extracted_message
    if decrypt:
        if encryption_method == "caesar":
            decrypted_message = caesar_decrypt(extracted_message)
        elif encryption_method == "vigenere":
            decrypted_message = vigenere_decrypt(extracted_message, encryption_key)
        elif encryption_method == "aes":
            decrypted_message = aes_decrypt(extracted_message, encryption_key)

    logger.debug(f"Decrypted message: '{decrypted_message}'")

    # Clean up
    if os.path.exists(tmp_dir):
        shutil.rmtree(tmp_dir)
        logger.debug("Cleaned up tmp directory")

    return extracted_message, decrypted_message

@video_bp.route('/video_encode', methods=['GET', 'POST'])
@login_required
def video_encode():
    if request.method == 'POST':
        if 'video' not in request.files:
            flash('No video file provided', 'error')
            return redirect(url_for('video.video_encode'))
        video = request.files['video']
        message = request.form.get('message')
        encrypt = request.form.get('encrypt') == 'yes'
        method = request.form.get('encryption_method') if encrypt else None
        key = request.form.get('encryption_key') if encrypt and method in ['vigenere'] else None
        output_format = request.form.get('output_format', 'avi')

        if video and message:
            input_path = os.path.join(current_app.config['UPLOAD_FOLDER'], 'input_video.mp4')
            output_path = os.path.join(current_app.config['UPLOAD_FOLDER'], f'encoded_video.{output_format}')
            video.save(input_path)
            try:
                aes_key = encode_video(input_path, output_path, message, encrypt, method, key, output_format)
                flash('Video encoded successfully!', 'success')
                return render_template('encode-video-result.html', aes_key=aes_key, file=f'encoded_video.{output_format}')
            except Exception as e:
                logger.error(f"Encoding error: {str(e)}")
                flash(f"Encoding failed: {str(e)}", 'error')
                return redirect(url_for('video.video_encode'))
        else:
            flash('Missing video or message', 'error')
            return redirect(url_for('video.video_encode'))
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
            return redirect(url_for('video.video_decode'))
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