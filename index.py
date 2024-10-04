from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'PNeZyC5a0GLUHljp0yvd'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://ucbx3vky0u2qn65r:PNeZyC5a0GLUHljp0yvd@b7yw5lq39svusrddrdv0-mysql.services.clever-cloud.com:3306/b7yw5lq39svusrddrdv0'  # Sustituye con las credenciales de Clever Cloud
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

# Rutas de Dashboard
@app.route('/profesor')
@login_required
def dashboard_profesor():
    if current_user.role != 'profesor':
        return redirect(url_for('login'))
    return render_template('profesores.html')

@app.route('/alumno')
@login_required
def dashboard_alumno():
    if current_user.role != 'alumno':
        return redirect(url_for('login'))
    return render_template('alumnos.html')

# Ruta para logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Crea las tablas si no existen
    app.run(debug=True, port=3500)
