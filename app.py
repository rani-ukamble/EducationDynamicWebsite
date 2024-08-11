import os
from flask import Flask, render_template, request, redirect, session, url_for, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'secret_key'

UPLOAD_FOLDER = os.path.join('static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    profile_photo = db.Column(db.String(100), nullable=True)

    def __init__(self, name, email, password, profile_photo=None):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        self.profile_photo = profile_photo

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))
    
    
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    display_name = db.Column(db.String(200), nullable=False)

class YouTubeLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(200), nullable=False)
    display_name = db.Column(db.String(200), nullable=False)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        photo = request.files['photo']
        
        if photo:
            filename = secure_filename(photo.filename)
            photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            filename = None
        
        new_user = User(name=name, email=email, password=password, profile_photo=filename)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['name'] = user.name
            session['email'] = user.email
            session['profile_photo'] = user.profile_photo
            return redirect('/dashboard')
        else:
            error = 'Invalid email or password'
            return render_template('login.html', error=error)
 
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        files = File.query.all()
        youtube_links = YouTubeLink.query.all()
        return render_template('dashboard.html', user=user, files=files, youtube_links=youtube_links)
    return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('name', None)
    session.pop('email', None)
    session.pop('profile_photo', None)
    return redirect('/login')

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == '123':  # Replace with your actual admin password
            files = request.files.getlist('file')
            names = request.form.getlist('display_name')
            yt_urls = request.form.getlist('yt_url')
            yt_names = request.form.getlist('yt_display_name')

            if len(files) == len(names):  # Ensure each file has a corresponding display name
                for i, file in enumerate(files):
                    if file and names[i]:
                        filename = file.filename
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        new_file = File(filename=filename, display_name=names[i])
                        db.session.add(new_file)
                db.session.commit()

            if len(yt_urls) == len(yt_names):  # Ensure each YouTube link has a corresponding display name
                for i, url in enumerate(yt_urls):
                    if url and yt_names[i]:
                        new_link = YouTubeLink(url=url, display_name=yt_names[i])
                        db.session.add(new_link)
                db.session.commit()
                
            return redirect('/admin')
        return 'Invalid password', 403
    
    files = File.query.all()
    youtube_links = YouTubeLink.query.all()
    return render_template('admin.html', files=files, youtube_links=youtube_links)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/download/<int:file_id>')
def download(file_id):
    file = File.query.get_or_404(file_id)
    return send_from_directory(app.config['UPLOAD_FOLDER'], file.filename, as_attachment=True)

@app.route('/delete/<int:file_id>')
def delete(file_id):
    file = File.query.get_or_404(file_id)
    filename = file.filename
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    db.session.delete(file)
    db.session.commit()
    return redirect('/admin')

@app.route('/delete_link/<int:link_id>')
def delete_link(link_id):
    link = YouTubeLink.query.get_or_404(link_id)
    db.session.delete(link)
    db.session.commit()
    return redirect('/admin')

if __name__ == '__main__':
    app.run(debug=True)
