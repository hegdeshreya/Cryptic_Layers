import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from modes.text import text_bp
from modes.video import video_bp
from modes.audio import audio_bp
from modes.multichannelimage import multichannelimage_bp
from modes.watermark import watermark_bp
from urllib.parse import urlparse, urljoin

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'Shreya-1234567890')
app.config['SESSION_COOKIE_SECURE'] = False   # When True, cookies are only sent over HTTPS.
                                              #Set to False here for development (HTTP), but should be True in production
app.config['SESSION_COOKIE_HTTPONLY'] = True  #Prevents JavaScript from accessing the session cookie, improving security.
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  #mitigating CSRF attacks by restricting cross-site cookie sharing.

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False             #Disables a feature that tracks object modifications, reducing overhead

# Upload folder configuration
app.config['UPLOAD_FOLDER'] = "Uploads"
app.config['UPLOAD_TEXT_FOLDER'] = os.path.join(app.config['UPLOAD_FOLDER'], "text")
app.config['UPLOAD_AUDIO_FOLDER'] = os.path.join(app.config['UPLOAD_FOLDER'], "audio")
app.config['UPLOAD_MULTICHANNELIMAGE_FOLDER'] = os.path.join(app.config['UPLOAD_FOLDER'], "multichannelimage")
app.config['UPLOAD_VIDEO_FOLDER'] = os.path.join(app.config['UPLOAD_FOLDER'], "video")
app.config['UPLOAD_WATERMARK_FOLDER'] = os.path.join(app.config['UPLOAD_FOLDER'], "watermark")

# Ensure upload folders exist
for folder in [
    app.config['UPLOAD_FOLDER'],
    app.config['UPLOAD_TEXT_FOLDER'],
    app.config['UPLOAD_AUDIO_FOLDER'],
    app.config['UPLOAD_MULTICHANNELIMAGE_FOLDER'],
    app.config['UPLOAD_VIDEO_FOLDER'],
    app.config['UPLOAD_WATERMARK_FOLDER']
]:
    if not os.path.exists(folder):
        os.makedirs(folder)

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  #login route as the default redirect for unauthenticated users trying to access protected routes.

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return self.username

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    print(f"[DEBUG] Loading user with username: {user_id}")
    user = User.query.filter_by(username=user_id).first()
    print(f"[DEBUG] User found: {user.username if user else 'None'}")
    return user

# Create database tables
with app.app_context():
    db.create_all()

# Helper function to validate 'next' URL
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

# Debug session and authentication
@app.before_request
def log_request():
    print(f"[DEBUG] Request: {request.method} {request.path}, Authenticated: {current_user.is_authenticated}, Session: {session}")

@app.route('/', methods=['GET', 'POST'])
def index():
    print("[DEBUG] Index route accessed")
    if request.method == 'POST':
        if not current_user.is_authenticated:
            flash("Please log in to use encode or decode features.", "error")
            print("[DEBUG] Redirecting to login from index POST")
            return redirect(url_for('login'))
        method = request.form.get('method')
        action = request.form.get('action')
        if method and action:
            print(f"[DEBUG] Redirecting to {method}.{method}_{action}")
            return redirect(url_for(f'{method}.{method}_{action}'))
        else:
            flash("Invalid method or action", "error")
    return render_template("index.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    print(f"[DEBUG] Login route accessed, Next: {request.args.get('next')}")
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            print(f"[DEBUG] Logging in user: {user.username}")
            login_user(user)
            flash("Logged in successfully!", "success")
            next_page = request.args.get('next')
            if next_page and is_safe_url(next_page):
                print(f"[DEBUG] Redirecting to next: {next_page}")
                return redirect(next_page)
            print("[DEBUG] Redirecting to index")
            return redirect(url_for('index'))
        flash("Invalid username or password", "error")
        print("[DEBUG] Login failed")
    return render_template("login.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    print("[DEBUG] Register route accessed")
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash("Username already exists", "error")
            print("[DEBUG] Username exists")
        else:
            new_user = User(username=username)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful! Please log in.", "success")
            print("[DEBUG] User registered")
            return redirect(url_for('login'))
    return render_template("register.html")

@app.route('/logout')
@login_required
def logout():
    print("[DEBUG] Logout route accessed")
    logout_user()
    flash("Logged out successfully!", "success")
    return redirect(url_for('index'))

@app.route('/reset_session')
def reset_session():
    print("[DEBUG] Reset session route accessed")
    session.clear()
    logout_user()
    flash("Session reset, please log in again.", "info")
    return redirect(url_for('login'))

@app.route('/clear_session')
def clear_session():
    print("[DEBUG] Clear session route accessed")
    session.clear()
    flash("Session cleared", "info")
    return redirect(url_for('index'))

# Register blueprints
app.register_blueprint(text_bp, url_prefix="/text")
app.register_blueprint(video_bp, url_prefix="/video")
app.register_blueprint(audio_bp, url_prefix="/audio")
app.register_blueprint(multichannelimage_bp, url_prefix="/multichannelimage")
app.register_blueprint(watermark_bp, url_prefix="/watermark")
print("[DEBUG] Blueprints registered: text, video, audio, multichannelimage, watermark")

if __name__ == "__main__":
    app.run(debug=True)