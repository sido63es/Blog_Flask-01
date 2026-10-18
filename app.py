import os
import hmac
import secrets
import smtplib
from datetime import datetime
from email.message import EmailMessage
from functools import wraps

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.datastructures import FileStorage
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['SMTP_HOST'] = os.environ.get('SMTP_HOST', '')
app.config['SMTP_PORT'] = int(os.environ.get('SMTP_PORT', '587'))
app.config['SMTP_USE_SSL'] = os.environ.get('SMTP_USE_SSL', '').lower() in {'1', 'true', 'yes'}
app.config['SMTP_USERNAME'] = os.environ.get('SMTP_USERNAME', '')
app.config['SMTP_PASSWORD'] = os.environ.get('SMTP_PASSWORD', '')
app.config['MAIL_FROM'] = os.environ.get('MAIL_FROM', '')
app.config['COMMENT_NOTIFICATION_EMAIL'] = os.environ.get('COMMENT_NOTIFICATION_EMAIL', '')
app.config['MAX_CONTENT_LENGTH'] = 26 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = os.path.join(app.static_folder, 'uploads')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

ALLOWED_IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.webp'}
MAX_IMAGE_SIZE = 5 * 1024 * 1024
MAX_IMAGES_PER_UPLOAD = 5


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    author = db.Column(db.String(50), nullable=False, default="Anónimo")
    comments = db.relationship('Comment', backref='post', cascade='all, delete-orphan')
    images = db.relationship(
        'PostImage',
        backref='post',
        cascade='all, delete-orphan',
        order_by='PostImage.id',
    )


class PostImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(80), nullable=False, unique=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='guest')
    comments = db.relationship('Comment', backref='user', cascade='all, delete-orphan')


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


def send_comment_notification(post: Post, comment: Comment) -> None:
    config = app.config
    required = ('SMTP_HOST', 'MAIL_FROM', 'COMMENT_NOTIFICATION_EMAIL')
    missing = [key for key in required if not config[key]]
    if missing:
        raise RuntimeError(f"Falta configurar: {', '.join(missing)}")
    if bool(config['SMTP_USERNAME']) != bool(config['SMTP_PASSWORD']):
        raise RuntimeError('SMTP_USERNAME y SMTP_PASSWORD deben configurarse juntos.')

    message = EmailMessage()
    message['Subject'] = 'Nuevo comentario en tu blog'
    message['From'] = config['MAIL_FROM']
    message['To'] = config['COMMENT_NOTIFICATION_EMAIL']
    message.set_content(
        f"Se ha publicado un nuevo comentario.\n\n"
        f"Artículo: {post.title}\n"
        f"Autor: {comment.user.username}\n"
        f"Fecha: {comment.date_posted.strftime('%d/%m/%Y a las %H:%M')}\n\n"
        f"{comment.content}\n"
    )

    smtp_class = smtplib.SMTP_SSL if config['SMTP_USE_SSL'] else smtplib.SMTP
    with smtp_class(config['SMTP_HOST'], config['SMTP_PORT'], timeout=10) as smtp:
        if not config['SMTP_USE_SSL']:
            smtp.starttls()
        if config['SMTP_USERNAME']:
            smtp.login(config['SMTP_USERNAME'], config['SMTP_PASSWORD'])
        smtp.send_message(message)


def validate_image_uploads(files: list[FileStorage]) -> tuple[list[tuple[FileStorage, str]], str | None]:
    uploads = [file for file in files if file and file.filename]
    if len(uploads) > MAX_IMAGES_PER_UPLOAD:
        return [], f'Puedes subir como máximo {MAX_IMAGES_PER_UPLOAD} imágenes a la vez.'

    valid_uploads = []
    signatures = {
        '.jpg': lambda data: data.startswith(b'\xff\xd8\xff'),
        '.jpeg': lambda data: data.startswith(b'\xff\xd8\xff'),
        '.png': lambda data: data.startswith(b'\x89PNG\r\n\x1a\n'),
        '.gif': lambda data: data.startswith((b'GIF87a', b'GIF89a')),
        '.webp': lambda data: data[:4] == b'RIFF' and data[8:12] == b'WEBP',
    }
    for file in uploads:
        filename = file.filename
        if not filename:
            continue
        extension = os.path.splitext(filename)[1].lower()
        if extension not in ALLOWED_IMAGE_EXTENSIONS:
            return [], 'Formato no permitido. Usa imágenes JPG, PNG, GIF o WebP.'
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)
        if size > MAX_IMAGE_SIZE:
            return [], 'Cada imagen debe ocupar como máximo 5 MB.'
        if size == 0 or not signatures[extension](file.read(12)):
            return [], 'Uno de los archivos no es una imagen válida del formato indicado.'
        file.seek(0)
        valid_uploads.append((file, extension))
    return valid_uploads, None


def store_uploaded_images(
    uploads: list[tuple[FileStorage, str]],
) -> list[PostImage]:
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    image_records = []
    saved_paths = []
    try:
        for file, extension in uploads:
            filename = f'{secrets.token_hex(16)}{extension}'
            path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            saved_paths.append(path)
            file.save(path)
            image_records.append(PostImage(filename=filename))
    except OSError:
        for path in saved_paths:
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
            except OSError:
                app.logger.exception('No se pudo limpiar una imagen parcialmente guardada.')
        raise
    return image_records


def remove_image_files(images: list[PostImage]) -> bool:
    failed = False
    for image in images:
        path = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        except OSError:
            failed = True
            app.logger.exception('No se pudo borrar el archivo de imagen %s.', image.filename)
    return failed


with app.app_context():
    db.create_all()


def get_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return session['_csrf_token']


@app.before_request
def load_user_and_check_csrf():
    user_id = session.get('user_id')
    g.current_user = db.session.get(User, user_id) if user_id else None
    if request.method == 'POST':
        expected = session.get('_csrf_token', '')
        supplied = request.form.get('_csrf_token', '')
        if not expected or not hmac.compare_digest(expected, supplied):
            abort(400)


@app.context_processor
def inject_template_helpers():
    return {'csrf_token': get_csrf_token, 'current_user': g.current_user}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.current_user is None:
            flash('Inicia sesión para realizar esa acción.', 'error')
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.current_user is None:
            flash('Inicia sesión con una cuenta administradora.', 'error')
            return redirect(url_for('login'))
        if g.current_user.role != 'admin':
            abort(403)
        return view(*args, **kwargs)
    return wrapped


@app.route('/')
def home():
    posts = Post.query.order_by(Post.date_posted.desc()).all()
    return render_template('index.html', posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if g.current_user is not None:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if len(username) < 3 or len(username) > 40:
            flash('El nombre de usuario debe tener entre 3 y 40 caracteres.', 'error')
        elif len(password) < 8:
            flash('La contraseña debe tener al menos 8 caracteres.', 'error')
        elif User.query.filter_by(username=username).first():
            flash('Ese nombre de usuario ya está registrado.', 'error')
        else:
            first_user = User.query.count() == 0
            user = User(
                username=username,
                password_hash=generate_password_hash(password),
                role='admin' if first_user else 'guest',
            )
            db.session.add(user)
            db.session.commit()
            session.clear()
            session['user_id'] = user.id
            flash(
                'Tu cuenta de administrador está lista.' if first_user
                else 'Registro completado. Ya puedes comentar.',
                'success',
            )
            return redirect(url_for('home'))
    return render_template('auth.html', mode='register')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.current_user is not None:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user is None or not check_password_hash(user.password_hash, password):
            flash('Usuario o contraseña incorrectos.', 'error')
        else:
            session.clear()
            session['user_id'] = user.id
            return redirect(url_for('home'))
    return render_template('auth.html', mode='login')


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    session.clear()
    flash('Has cerrado sesión.', 'success')
    return redirect(url_for('home'))


@app.route('/post/new', methods=['POST'])
@admin_required
def create_post():
    title = request.form.get('title', '').strip()
    content = request.form.get('content', '').strip()
    if not title or not content:
        flash('El título y el contenido son obligatorios.', 'error')
        return redirect(url_for('home'))

    uploads, error = validate_image_uploads(request.files.getlist('images'))
    if error:
        flash(error, 'error')
        return redirect(url_for('home'))

    try:
        image_records = store_uploaded_images(uploads)
    except OSError:
        app.logger.exception('No se pudieron guardar las imágenes del artículo.')
        flash('No se pudieron guardar las imágenes. Inténtalo de nuevo.', 'error')
        return redirect(url_for('home'))

    post = Post(
        title=title,
        content=content,
        author=g.current_user.username,
        images=image_records,
    )
    db.session.add(post)
    try:
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        remove_image_files(image_records)
        raise
    flash('Artículo publicado.', 'success')
    return redirect(url_for('home'))


@app.route('/post/<int:post_id>')
def post_detail(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('post.html', post=post)


@app.route('/post/<int:post_id>/comment', methods=['POST'])
@login_required
def add_comment(post_id):
    post = Post.query.get_or_404(post_id)
    if g.current_user.role != 'guest':
        abort(403)
    content = request.form.get('content', '').strip()
    if not content:
        flash('El comentario no puede estar vacío.', 'error')
    else:
        comment = Comment(content=content, post=post, user=g.current_user)
        db.session.add(comment)
        db.session.commit()
        try:
            send_comment_notification(post, comment)
        except (OSError, RuntimeError, smtplib.SMTPException, ValueError):
            app.logger.exception('No se pudo enviar el aviso de nuevo comentario.')
            flash(
                'Comentario publicado, pero no se pudo enviar el correo de aviso.',
                'warning',
            )
        else:
            flash('Comentario publicado y aviso enviado por correo.', 'success')
    return redirect(url_for('post_detail', post_id=post.id))


@app.route('/post/<int:post_id>/delete', methods=['POST'])
@admin_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    images = list(post.images)
    db.session.delete(post)
    db.session.commit()
    if remove_image_files(images):
        flash('Artículo borrado, pero no se pudieron eliminar todas sus imágenes.', 'warning')
    return redirect(url_for('home'))


@app.route('/post/<int:post_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        if not title or not content:
            flash('El título y el contenido son obligatorios.', 'error')
            return render_template('edit.html', post=post)

        uploads, error = validate_image_uploads(request.files.getlist('images'))
        if error:
            flash(error, 'error')
            return render_template('edit.html', post=post)

        try:
            image_records = store_uploaded_images(uploads)
        except OSError:
            app.logger.exception('No se pudieron guardar las imágenes del artículo.')
            flash('No se pudieron guardar las imágenes. Inténtalo de nuevo.', 'error')
            return render_template('edit.html', post=post)

        delete_ids = request.form.getlist('delete_images')
        try:
            delete_ids = [int(image_id) for image_id in delete_ids]
        except ValueError:
            remove_image_files(image_records)
            abort(400)
        images_to_delete = [
            image for image in post.images
            if image.id in delete_ids
        ]
        post.title = title
        post.content = content
        post.images.extend(image_records)
        for image in images_to_delete:
            post.images.remove(image)
        try:
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()
            remove_image_files(image_records)
            raise
        if remove_image_files(images_to_delete):
            flash('Artículo actualizado, pero no se pudieron eliminar algunas imágenes.', 'warning')
        return redirect(url_for('post_detail', post_id=post.id))
    return render_template('edit.html', post=post)


@app.route('/users')
@admin_required
def manage_users():
    users = User.query.order_by(User.username).all()
    return render_template('users.html', users=users)


@app.route('/users/<int:user_id>/role', methods=['POST'])
@admin_required
def change_user_role(user_id):
    user = User.query.get_or_404(user_id)
    role = request.form.get('role')
    if role not in ('admin', 'guest'):
        abort(400)
    if user.id == g.current_user.id and role != 'admin':
        flash('No puedes quitarte tu propio rol de administrador.', 'error')
    elif user.role == 'admin' and role == 'guest' and User.query.filter_by(role='admin').count() <= 1:
        flash('Debe quedar al menos un administrador.', 'error')
    else:
        user.role = role
        db.session.commit()
        flash('Rol actualizado.', 'success')
    return redirect(url_for('manage_users'))


@app.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == g.current_user.id:
        flash('No puedes eliminar tu propia cuenta mientras tienes sesión iniciada.', 'error')
    elif user.role == 'admin' and User.query.filter_by(role='admin').count() <= 1:
        flash('Debe quedar al menos un administrador.', 'error')
    else:
        db.session.delete(user)
        db.session.commit()
        flash('Usuario eliminado.', 'success')
    return redirect(url_for('manage_users'))


if __name__ == '__main__':
    app.run(debug=True)
