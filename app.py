from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from modes.text import text_bp
from modes.video import video_bp
from modes.audio import audio_bp
from modes.multichannelimage import multichannelimage_bp
import os

app = Flask(__name__)
app.secret_key = "your-secret-key"  # Consider moving this to an environment variable for security

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Upload folder configuration
app.config['UPLOAD_FOLDER'] = "uploads"
app.config['UPLOAD_TEXT_FOLDER'] = os.path.join(app.config['UPLOAD_FOLDER'], "text")
app.config['UPLOAD_AUDIO_FOLDER'] = os.path.join(app.config['UPLOAD_FOLDER'], "audio")
app.config['UPLOAD_MULTICHANNELIMAGE_FOLDER'] = os.path.join(app.config['UPLOAD_FOLDER'], "multichannelimage")

# Ensure upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

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
        return str(self.id)  # Flask-Login expects a string

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    print(f"Loading user with ID: {user_id}")  # Debug
    try:
        return User.query.get(int(user_id))
    except ValueError:
        print(f"Invalid user_id: {user_id}")
        return None

# Create database tables
with app.app_context():
    db.create_all()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if not current_user.is_authenticated:
            flash("Please log in to use encode or decode features.", "error")
            return redirect(url_for('login'))
        method = request.form.get('method')
        action = request.form.get('action')
        if method and action:
            return redirect(url_for(f'{method}.{method}_{action}'))
        else:
            flash("Invalid method or action", "error")
    return render_template("index.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            print(f"Logging in user with ID: {user.id}")  # Debug
            login_user(user)
            flash("Logged in successfully!", "success")
            return redirect(url_for('index'))
        flash("Invalid username or password", "error")
    return render_template("login.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash("Username already exists", "error")
        else:
            new_user = User(username=username)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for('login'))
    return render_template("register.html")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "success")
    return redirect(url_for('index'))

# Optional: Add a route to clear session for debugging
@app.route('/clear_session')
def clear_session():
    session.clear()
    flash("Session cleared", "info")
    return redirect(url_for('index'))

# Register blueprints
app.register_blueprint(text_bp, url_prefix="/text")
app.register_blueprint(video_bp, url_prefix="/video")
app.register_blueprint(audio_bp, url_prefix="/audio")
app.register_blueprint(multichannelimage_bp, url_prefix="/multichannelimage")

if __name__ == "__main__":
    app.run(debug=True)