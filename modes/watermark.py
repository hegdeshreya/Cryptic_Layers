import os
import uuid
import logging
import time
from datetime import datetime, timedelta
from PIL import Image
import stepic
import qrcode
import cv2
import numpy as np
from flask import Blueprint, current_app, render_template, request, flash, redirect, url_for, send_file, session
from flask_login import login_required
from werkzeug.utils import secure_filename

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Define blueprint
watermark_bp = Blueprint("watermark", __name__, template_folder="templates/watermark")

# Allowed image extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def safe_remove(file_path, retries=3, delay=0.1):
    """Attempt to remove a file with retries to handle permission errors."""
    for attempt in range(retries):
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                logger.debug(f"Removed temporary file: {file_path}")
            return
        except PermissionError as e:
            logger.warning(f"PermissionError removing {file_path}: {str(e)}, attempt {attempt + 1}/{retries}")
            time.sleep(delay)
        except Exception as e:
            logger.error(f"Error removing {file_path}: {str(e)}")
            break
    logger.error(f"Failed to remove {file_path} after {retries} attempts")

@watermark_bp.route('/Uploads/watermark/<filename>')
@login_required
def uploaded_file(filename):
    file_path = os.path.join(current_app.config['UPLOAD_WATERMARK_FOLDER'], filename)
    logger.debug(f"Accessing file: {file_path}")
    if request.args.get('preview'):
        return send_file(file_path, mimetype='image/png')
    try:
        return send_file(file_path, as_attachment=True, download_name=filename)
    finally:
        if os.path.exists(file_path) and not filename.startswith("encoded_"):
            logger.debug(f"Removing temporary file: {file_path}")
            safe_remove(file_path)

@watermark_bp.route("/watermark_encode", methods=['GET', 'POST'])
@login_required
def watermark_encode():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        if not name:
            flash("Name cannot be empty!", "error")
            return redirect(url_for('watermark.watermark_encode'))

        file = request.files.get('image')
        if not file or file.filename == '':
            flash("No image selected!", "error")
            return redirect(url_for('watermark.watermark_encode'))

        filename = secure_filename(file.filename)
        if not allowed_file(filename):
            flash("Unsupported image format. Use PNG, JPG, or BMP.", "error")
            return redirect(url_for('watermark.watermark_encode'))

        upload_folder = current_app.config['UPLOAD_WATERMARK_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        unique_id = str(uuid.uuid4())
        file_path = os.path.join(upload_folder, f"{unique_id}_{filename}")
        file.save(file_path)
        logger.debug(f"Saved uploaded file: {file_path}")

        try:
            # Open and process the input image
            im = Image.open(file_path).convert('RGB')
            width, height = im.size

            # Ensure image is large enough
            if width < 150 or height < 150:
                flash("Image is too small. Minimum dimensions are 150x150 pixels.", "error")
                safe_remove(file_path)
                return redirect(url_for('watermark.watermark_encode'))

            # Hide name in image using steganography
            encoded_image = stepic.encode(im, name.encode())

            # QR code creation
            qr = qrcode.QRCode(version=1, box_size=10, border=4)
            decode_url = url_for('watermark.watermark_decode_result', unique_id=unique_id, _external=True)
            logger.debug(f"QR code URL: {decode_url}")
            qr.add_data(decode_url)
            qr.make(fit=True)
            qr_img = qr.make_image(fill_color="black", back_color="white")
            qr_size = 150
            qr_img = qr_img.resize((qr_size, qr_size), Image.Resampling.LANCZOS)

            # Calculate final image dimensions
            padding = 10
            new_height = height + qr_size + padding * 2
            final_image = Image.new('RGB', (width, new_height), (255, 255, 255))

            # Paste main image and QR code
            final_image.paste(encoded_image, (0, 0))
            qr_x = max(5, width - qr_size - 5)
            qr_y = height + padding
            final_image.paste(qr_img, (qr_x, qr_y))

            # Save encoded image
            encoded_filename = f"encoded_{unique_id}.png"
            encoded_path = os.path.join(upload_folder, encoded_filename)
            final_image.save(encoded_path, quality=95)
            logger.debug(f"Saved encoded image: {encoded_path}")

            # Store in session
            if 'image_storage' not in session:
                session['image_storage'] = {}
            session['image_storage'][unique_id] = {
                'path': encoded_path,
                'created_at': datetime.utcnow().isoformat()
            }
            session.modified = True
            logger.debug(f"Stored in session: {unique_id}")

            return render_template(
                "watermark/watermark_encode_result.html",
                encoded_file=encoded_filename,
                name=name,
                unique_id=unique_id
            )
        except Exception as e:
            logger.error(f"Error encoding image: {str(e)}")
            flash(f"Failed to process image: {str(e)}", "error")
            safe_remove(file_path)
            return redirect(url_for('watermark.watermark_encode'))
        finally:
            safe_remove(file_path)

    return render_template("watermark/watermark_encode.html")

@watermark_bp.route("/watermark_decode", methods=['GET', 'POST'])
@login_required
def watermark_decode():
    if request.method == 'POST':
        file = request.files.get('image')
        if not file or file.filename == '':
            flash("No image selected!", "error")
            return redirect(url_for('watermark.watermark_decode'))

        filename = secure_filename(file.filename)
        if not allowed_file(filename):
            flash("Unsupported image format. Use PNG, JPG, or BMP.", "error")
            return redirect(url_for('watermark.watermark_decode'))

        upload_folder = current_app.config['UPLOAD_WATERMARK_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        unique_id = str(uuid.uuid4())
        file_path = os.path.join(upload_folder, f"decode_{unique_id}_{filename}")
        file.save(file_path)
        logger.debug(f"Saved decode file: {file_path}")

        try:
            # Validate image dimensions
            img_pil = Image.open(file_path)
            width, height = img_pil.size
            if width < 100 or height < 100:
                flash("Image is too small. Minimum dimensions are 100x100 pixels.", "error")
                img_pil.close()
                safe_remove(file_path)
                return redirect(url_for('watermark.watermark_decode'))

            # Try QR code detection first (for mobile compatibility)
            img = cv2.imread(file_path)
            if img is None:
                flash("Failed to read image. Ensure it is a valid image file.", "error")
                img_pil.close()
                safe_remove(file_path)
                return redirect(url_for('watermark.watermark_decode'))

            detector = cv2.QRCodeDetector()
            data, bbox, _ = detector.detectAndDecode(img)
            if data and 'unique_id=' in data:
                unique_id = data.split('unique_id=')[-1]
                img_pil.close()
                return redirect(url_for('watermark.watermark_decode_result', unique_id=unique_id))

            # If no QR code, store image for direct decoding
            if 'image_storage' not in session:
                session['image_storage'] = {}
            session['image_storage'][unique_id] = {
                'path': file_path,
                'created_at': datetime.utcnow().isoformat()
            }
            session.modified = True
            img_pil.close()

            return redirect(url_for('watermark.watermark_decode_result', unique_id=unique_id))
        except Exception as e:
            logger.error(f"Error processing image: {str(e)}")
            flash(f"Error processing image: {str(e)}", "error")
            safe_remove(file_path)
            return redirect(url_for('watermark.watermark_decode'))

    return render_template("watermark/watermark_decode.html")

@watermark_bp.route("/watermark/decode_result/<unique_id>")
@login_required
def watermark_decode_result(unique_id):
    image_storage = session.get('image_storage', {})
    
    # Clean up expired entries (e.g., older than 1 hour)
    expiry_time = datetime.utcnow() - timedelta(hours=1)
    for uid, data in list(image_storage.items()):
        created_at = datetime.fromisoformat(data['created_at'])
        if created_at < expiry_time:
            safe_remove(data['path'])
            del image_storage[uid]
    session['image_storage'] = image_storage
    session.modified = True

    if unique_id not in image_storage:
        logger.warning(f"Image not found in session for unique_id: {unique_id}")
        flash("Image not found or expired.", "error")
        return redirect(url_for('watermark.watermark_decode'))

    encoded_filepath = image_storage[unique_id]['path']
    if not os.path.exists(encoded_filepath):
        logger.warning(f"Image file missing: {encoded_filepath}")
        flash("Image file not found on server.", "error")
        del image_storage[unique_id]
        session['image_storage'] = image_storage
        session.modified = True
        return redirect(url_for('watermark.watermark_decode'))

    try:
        image = Image.open(encoded_filepath)
        decoded_name = stepic.decode(image)
        image.close()
        logger.debug(f"Decoded name: {decoded_name}")
        if not decoded_name:
            flash("No hidden name found in the image.", "error")
            safe_remove(encoded_filepath)
            del image_storage[unique_id]
            session['image_storage'] = image_storage
            session.modified = True
            return redirect(url_for('watermark.watermark_decode'))
        return render_template("watermark/watermark_decode_result.html", decoded_name=decoded_name)
    except Exception as e:
        logger.error(f"Error decoding image: {str(e)}")
        flash(f"Error decoding image: {str(e)}", "error")
        safe_remove(encoded_filepath)
        del image_storage[unique_id]
        session['image_storage'] = image_storage
        session.modified = True
        return redirect(url_for('watermark.watermark_decode'))

@watermark_bp.route("/watermark/clear_storage")
@login_required
def clear_storage():
    image_storage = session.get('image_storage', {})
    for unique_id, data in image_storage.items():
        file_path = data['path']
        safe_remove(file_path)
    session['image_storage'] = {}
    session.modified = True
    flash("Stored images cleared.", "success")
    return redirect(url_for('watermark.watermark_encode'))