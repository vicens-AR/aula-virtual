from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import random
import string
from datetime import datetime
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Configuración de la carpeta uploads
upload_folder = os.path.join(os.path.dirname(__file__), 'uploads')
if not os.path.exists(upload_folder):
    os.makedirs(upload_folder)

app.config['UPLOAD_FOLDER'] = upload_folder
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB de límite para archivos

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'pdf', 'doc', 'docx', 'jpg', 'png'}

app.config['SECRET_KEY'] = 'PNeZyC5a0GLUHljp0yvd'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://ucbx3vky0u2qn65r:PNeZyC5a0GLUHljp0yvd@b7yw5lq39svusrddrdv0-mysql.services.clever-cloud.com:3306/b7yw5lq39svusrddrdv0'  # Credenciales de Clever Cloud
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Modelo de Usuario
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), nullable=False)

class Clase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre_clase = db.Column(db.String(100), nullable=False)
    codigo_clase = db.Column(db.String(10), unique=True, nullable=False)
    profesor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tareas = db.Column(db.Text, nullable=True)  # Para almacenar tareas
    notificaciones = db.Column(db.Text, nullable=True)  # Para almacenar notificaciones

    profesor = db.relationship('User', backref='clases', lazy=True)

class AlumnoClase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    alumno_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    clase_id = db.Column(db.Integer, db.ForeignKey('clase.id'), nullable=False)

    alumno = db.relationship('User', backref='clases_alumno', lazy=True)
    clase = db.relationship('Clase', backref='alumnos', lazy=True)

class EntregaTarea(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    alumno_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    clase_id = db.Column(db.Integer, db.ForeignKey('clase.id'), nullable=False)
    archivo = db.Column(db.String(200), nullable=False)  # Ruta del archivo entregado
    nota = db.Column(db.Integer, nullable=True)  # Nota de la evaluación
    comentarios = db.Column(db.Text, nullable=True)  # Comentarios del profesor

    alumno = db.relationship('User', backref='entregas', lazy=True)
    clase = db.relationship('Clase', backref='entregas', lazy=True)

class TareaEntregada(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    alumno_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    clase_id = db.Column(db.Integer, db.ForeignKey('clase.id'), nullable=False)
    archivo = db.Column(db.String(200), nullable=False)  # Guardar el nombre del archivo

    alumno = db.relationship('User', backref='tareas_entregadas', lazy=True)
    clase = db.relationship('Clase', backref='tareas_entregadas', lazy=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Ruta para sign up
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')

        # Verificar si el usuario ya existe
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('El nombre de usuario ya está registrado. Elige otro.', 'danger')
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, password=hashed_password, role=role)
            db.session.add(new_user)
            db.session.commit()
            flash('¡Registro exitoso! Ya puedes iniciar sesión.', 'success')
            return redirect(url_for('login'))

    return render_template('signup.html')

# Ruta para login
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            if user.role == 'profesor':
                return redirect(url_for('dashboard_profesor'))
            else:
                return redirect(url_for('dashboard_alumno'))
        else:
            flash('Login fallido. Verifica tus credenciales.', 'danger')
    return render_template('login.html')

@app.route('/clase/<int:clase_id>/entregar_tarea', methods=['POST'])
@login_required
def entregar_tarea(clase_id):
    if current_user.role != 'alumno':
        return redirect(url_for('login'))
    
    clase = Clase.query.get_or_404(clase_id)
    
    if 'archivo' not in request.files:
        flash('No se seleccionó ningún archivo', 'danger')
        return redirect(request.url)
    
    archivo = request.files['archivo']
    
    if archivo and allowed_file(archivo.filename):
        filename = secure_filename(archivo.filename)
        archivo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        # Guardar la tarea en la tabla EntregaTarea
        nueva_tarea = EntregaTarea(alumno_id=current_user.id, clase_id=clase.id, archivo=filename)
        db.session.add(nueva_tarea)
        db.session.commit()
        
        flash('Tarea entregada exitosamente.', 'success')
        return redirect(url_for('dashboard_alumno'))
    else:
        flash('El archivo no tiene una extensión permitida', 'danger')
        return redirect(request.url)

@app.route('/profesor/clase/<int:clase_id>/ver_entregas')
@login_required
def ver_entregas(clase_id):
    if current_user.role != 'profesor':
        return redirect(url_for('login'))
    
    clase = Clase.query.get_or_404(clase_id)
    # Consulta las entregas desde la tabla correcta
    entregas = EntregaTarea.query.filter_by(clase_id=clase.id).all()
    
    return render_template('ver_entregas.html', entregas=entregas)

@app.route('/profesor/clase/<int:clase_id>/entregas', methods=['GET', 'POST'])
@login_required
def ver_entregas_clase(clase_id):
    if current_user.role != 'profesor':
        return redirect(url_for('login'))
    
    clase = Clase.query.get_or_404(clase_id)
    entregas = EntregaTarea.query.filter_by(clase_id=clase.id).all()

    if request.method == 'POST':
        entrega_id = request.form.get('entrega_id')
        nota = request.form.get('nota')
        comentarios = request.form.get('comentarios')

        entrega = EntregaTarea.query.get(entrega_id)
        entrega.nota = nota
        entrega.comentarios = comentarios
        db.session.commit()

        flash('Evaluación registrada correctamente.', 'success')
        return redirect(url_for('ver_entregas', clase_id=clase.id))

    return render_template('ver_entregas.html', clase=clase, entregas=entregas)

@app.route('/alumno/tareas_evaluadas')
@login_required
def tareas_evaluadas():
    if current_user.role != 'alumno':
        return redirect(url_for('login'))

    entregas = EntregaTarea.query.filter_by(alumno_id=current_user.id).all()
    return render_template('tareas_evaluadas.html', entregas=entregas)

# Rutas de Dashboard
@app.route('/profesor')
@login_required
def dashboard_profesor():
    if current_user.role != 'profesor':
        return redirect(url_for('login'))
    
    clases = Clase.query.filter_by(profesor_id=current_user.id).all()
    return render_template('profesores.html', clases=clases)

@app.route('/alumno')
@login_required
def dashboard_alumno():
    if current_user.role != 'alumno':
        return redirect(url_for('login'))

    clases_alumno = AlumnoClase.query.filter_by(alumno_id=current_user.id).all()
    clases = [clase.clase for clase in clases_alumno]  # Obtener las clases a las que está unido el alumno
    return render_template('alumnos.html', clases=clases)

@app.route('/clase/<int:clase_id>', methods=['GET', 'POST'])
@login_required
def clase(clase_id):
    clase = Clase.query.get_or_404(clase_id)

    if request.method == 'POST':
        tareas = request.form.get('tareas')
        notificaciones = request.form.get('notificaciones')

        clase.tareas = tareas
        clase.notificaciones = notificaciones
        db.session.commit()

        flash('Clase actualizada exitosamente.', 'success')
        return redirect(url_for('clase', clase_id=clase.id))

    return render_template('clase.html', clase=clase)

# Ruta para logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Función para generar código de clase
def generar_codigo_clase():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

# Ruta para que el profesor cree una clase
@app.route('/profesor/crear_clase', methods=['GET', 'POST'])
@login_required
def crear_clase():
    if current_user.role != 'profesor':
        return redirect(url_for('login'))

    if request.method == 'POST':
        nombre_clase = request.form.get('nombre_clase')
        codigo_clase = generar_codigo_clase()

        nueva_clase = Clase(nombre_clase=nombre_clase, codigo_clase=codigo_clase, profesor_id=current_user.id)
        db.session.add(nueva_clase)
        db.session.commit()

        flash(f'Clase creada exitosamente con el código: {codigo_clase}', 'success')
        return redirect(url_for('dashboard_profesor'))

    return render_template('crear_clase.html')

# Ruta para que los alumnos se unan a una clase
@app.route('/alumno/unirse_clase', methods=['GET', 'POST'])
@login_required
def unirse_clase():
    if current_user.role != 'alumno':
        return redirect(url_for('login'))

    if request.method == 'POST':
        codigo_clase = request.form.get('codigo_clase')
        clase = Clase.query.filter_by(codigo_clase=codigo_clase).first()

        if clase:
            # Verificar si ya está unido
            alumno_clase_existente = AlumnoClase.query.filter_by(alumno_id=current_user.id, clase_id=clase.id).first()
            if alumno_clase_existente:
                flash('Ya estás unido a esta clase.', 'warning')
            else:
                nueva_asignacion = AlumnoClase(alumno_id=current_user.id, clase_id=clase.id)
                db.session.add(nueva_asignacion)
                db.session.commit()
                flash(f'Te has unido a la clase: {clase.nombre_clase}', 'success')
        else:
            flash('Código de clase inválido.', 'danger')

    return render_template('unirse_clase.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Crea las tablas si no existen
    app.run(debug=True, port=3500)

