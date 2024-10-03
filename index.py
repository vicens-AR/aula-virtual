from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'tu_secreto_aqui'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://usuario:contraseña@host:puerto/nombre_bd'  # Sustituye con las credenciales de Clever Cloud
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

# Ruta para login
@app.route('/login', methods=['GET', 'POST'])
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
@app.route('/dashboard/profesor')
@login_required
def dashboard_profesor():
    if current_user.role != 'profesor':
        return redirect(url_for('login'))
    return render_template('dashboard_profesor.html')

@app.route('/dashboard/alumno')
@login_required
def dashboard_alumno():
    if current_user.role != 'alumno':
        return redirect(url_for('login'))
    return render_template('dashboard_alumno.html')

# Ruta para logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=3500)
