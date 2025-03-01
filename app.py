from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from modes.text import text_bp  # Import the text blueprint

app = Flask(__name__)
app.secret_key = "your-secret-key"
app.config['UPLOAD_TEXT_FOLDER'] = "uploads"

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Simple in-memory user store (replace with database later)
users = {}

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(username):
    if username in users:
        return User(username)
    return None

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if not current_user.is_authenticated:
            flash("Please log in to use encode or decode features.", "error")
            return redirect(url_for('login'))
        method = request.form.get('method')
        action = request.form.get('action')
        return redirect(url_for(f'{method}.{method}_{action}'))  # Updated to use blueprint routes
    return render_template("index.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in users and users[username] == password:
            user = User(username)
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
        if username in users:
            flash("Username already exists", "error")
        else:
            users[username] = password
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for('login'))
    return render_template("register.html")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "success")
    return redirect(url_for('index'))

# Register the text blueprint
app.register_blueprint(text_bp, url_prefix="/text")

if __name__ == "__main__":
    app.run(debug=True)