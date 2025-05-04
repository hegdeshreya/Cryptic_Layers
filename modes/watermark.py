import os
import uuid
from PIL import Image, ImageDraw, ImageFont
import stepic
import qrcode
import cv2
from flask import Blueprint, current_app, render_template, request, flash, redirect, url_for, send_file
from flask_login import login_required
from werkzeug.utils import secure_filename

# Define blueprint
watermark_bp = Blueprint("watermark", __name__, template_folder="templates/watermark")

# Allowed image extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp'}

# Store image paths with UUIDs
image_storage = {}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@watermark_bp.route('/Uploads/watermark/<filename>')
@login_required
def uploaded_file(filename):
    file_path = os.path.join(current_app.config['UPLOAD_WATERMARK_FOLDER'], filename)
    if request.args.get('preview'):
        return send_file(file_path, mimetype='image/png')
    try:
        return send_file(file_path, as_attachment=True, download_name=filename)
    finally:
        if os.path.exists(file_path) and not filename.startswith("encoded_"):
            os.remove(file_path)

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

        try:
            # Open and process the input image
            im = Image.open(file_path).convert('RGBA')
            width, height = im.size

            # Create watermark layer for the main image only
            watermark_layer = Image.new('RGBA', (width, height), (0, 0, 0, 0))
            draw = ImageDraw.Draw(watermark_layer)

            font_path = os.path.join(current_app.static_folder, "fonts", "arial.ttf")
            font = ImageFont.truetype(font_path, size=50)

            text_bbox = draw.textbbox((0, 0), name, font=font)
            text_width = text_bbox[2] - text_bbox[0]
            text_height = text_bbox[3] - text_bbox[1]
            text_x = (width - text_width) // 2
            text_y = (height - text_height) // 2

            shadow_color = (0, 0, 0, 128)
            main_color = (255, 255, 255, 255)
            for offset in range(1, 4):
                draw.text((text_x + offset, text_y + offset), name, font=font, fill=shadow_color)
            draw.text((text_x, text_y), name, font=font, fill=main_color)

            # Apply watermark to main image
            watermarked_image = Image.alpha_composite(im, watermark_layer)
            watermarked_rgb = watermarked_image.convert('RGB')
            encoded_image = stepic.encode(watermarked_rgb, name.encode())

            # QR code creation
            qr = qrcode.QRCode(version=1, box_size=6, border=2)
            decode_url = url_for('watermark.watermark_decode_result', unique_id=unique_id, _external=True)
            qr.add_data(decode_url)
            qr.make(fit=True)
            qr_img = qr.make_image(fill_color="black", back_color="white")
            qr_size = 150  # Smaller QR code size
            qr_img = qr_img.resize((qr_size, qr_size), Image.Resampling.LANCZOS)

            # Calculate final image dimensions
            padding = 20
            new_height = height + qr_size + padding * 2  # Adjusted for smaller QR code
            final_image = Image.new('RGB', (width, new_height), (255, 255, 255))

            # Paste main image and QR code
            final_image.paste(encoded_image, (0, 0))
            qr_x = max(10, width - qr_size - 10)  # Right-align QR code with 10px padding
            qr_y = height + padding  # Place QR code below image
            final_image.paste(qr_img, (qr_x, qr_y))

            encoded_filename = f"encoded_{unique_id}.png"
            encoded_path = os.path.join(upload_folder, encoded_filename)
            final_image.save(encoded_path)
            image_storage[unique_id] = encoded_path

            return render_template("watermark/watermark_encode_result.html",
                                   encoded_file=encoded_filename,
                                   name=name)
        except Exception as e:
            flash(f"Failed to process image: {str(e)}", "error")
            return redirect(url_for('watermark.watermark_encode'))
        finally:
            if os.path.exists(file_path):
                os.remove(file_path)

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

        try:
            # QR code detection with error handling
            img = cv2.imread(file_path)
            detector = cv2.QRCodeDetector()
            data, bbox, _ = detector.detectAndDecode(img)
            if not data:
                flash("No QR code found in the image!", "error")
                return redirect(url_for('watermark.watermark_decode'))

            if 'unique_id=' not in data:
                flash("Invalid QR code!", "error")
                return redirect(url_for('watermark.watermark_decode'))

            unique_id = data.split('unique_id=')[-1]
            if unique_id not in image_storage:
                flash("Image not found or expired.", "error")
                return redirect(url_for('watermark.watermark_decode'))

            return redirect(url_for('watermark.watermark_decode_result', unique_id=unique_id))
        except Exception as e:
            flash(f"Error processing image: {str(e)}", "error")
            return redirect(url_for('watermark.watermark_decode'))
        finally:
            if os.path.exists(file_path):
                os.remove(file_path)

    return render_template("watermark/watermark_decode.html")

@watermark_bp.route("/watermark/decode_result/<unique_id>")
@login_required
def watermark_decode_result(unique_id):
    if unique_id not in image_storage:
        flash("Image not found or expired.", "error")
        return redirect(url_for('watermark.watermark_decode'))

    encoded_filepath = image_storage.get(unique_id)
    try:
        image = Image.open(encoded_filepath)
        decoded_name = stepic.decode(image)
        if os.path.exists(encoded_filepath):
            os.remove(encoded_filepath)
        del image_storage[unique_id]

        return render_template("watermark/watermark_decode_result.html", decoded_name=decoded_name)
    except Exception as e:
        flash(f"Error decoding image: {str(e)}", "error")
        return redirect(url_for('watermark.watermark_decode'))