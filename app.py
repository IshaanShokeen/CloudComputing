from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os

# ------------------ App Setup ------------------
app = Flask(__name__)
app.secret_key = "your_secret_key"

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)

# ------------------ Models ------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(300), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('files', lazy=True))

with app.app_context():
    db.create_all()

# ------------------ Routes ------------------
@app.route('/')
def home():
    return redirect(url_for('login')) if 'user_id' not in session else redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ''
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        else:
            message = 'Invalid email or password'
    return render_template('login.html', message=message)

@app.route('/signup', methods=['GET', 'POST'])
def signup_page():
    message = ''
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(email=email).first():
            message = 'User already exists'
        else:
            hashed_pw = generate_password_hash(password)
            new_user = User(name=name, email=email, password=hashed_pw)
            db.session.add(new_user)
            db.session.commit()
            flash('Signup successful! Please login.', 'success')
            return redirect(url_for('login'))
    return render_template('signup.html', message=message)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    user_files = File.query.filter_by(user_id=user.id).all()

    # Calculate total size in MB
    total_size_mb = 0
    for f in user_files:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], f.filename)
        if os.path.exists(filepath):
            total_size_mb += os.path.getsize(filepath) / (1024*1024)

    return render_template('index.html', files=user_files, total_size_mb=round(total_size_mb, 2), user=user, os=os)

@app.route('/upload_file', methods=['POST'])
def upload_file():  
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if 'file' not in request.files:
        flash("No file part", "danger")
        return redirect(url_for('dashboard'))

    file = request.files['file']
    if file.filename == '':
        flash("No selected file", "danger")
        return redirect(url_for('dashboard'))

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    # Add file to database
    new_file = File(filename=filename, user_id=session['user_id'])
    db.session.add(new_file)
    db.session.commit()

    flash(f"File '{filename}' uploaded successfully!", "success")
    return redirect(url_for('dashboard'))

@app.route('/download/<filename>')
def download_file(filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    file_record = File.query.filter_by(filename=filename, user_id=session['user_id']).first()
    if not file_record:
        flash("Unauthorized or file missing", "danger")
        return redirect(url_for('dashboard'))

    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/delete_file/<filename>', methods=['POST'])
def delete_file(filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    file_record = File.query.filter_by(filename=filename, user_id=session['user_id']).first()
    if file_record:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(filepath):
            os.remove(filepath)
        db.session.delete(file_record)
        db.session.commit()
        flash(f"File '{filename}' deleted!", "success")
    else:
        flash("File not found or unauthorized!", "danger")

    return redirect(url_for('dashboard'))

# ------------------ Run App ------------------
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
