from flask import Flask, render_template, redirect, url_for, session, flash
from flask_bootstrap import Bootstrap
from flask_login.config import LOGIN_MESSAGE_CATEGORY
from flask_wtf import FlaskForm
from flask_wtf.recaptcha import validators
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import EqualTo, InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_manager, login_user, login_required, logout_user, current_user
from datetime import timedelta
import os

SECRET_KEY = os.environ.get('PY_SECRET_KEY')
DATABASE_URL = os.environ.get('DATABASE_URL')

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL

bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.refresh_view = 'relogin'
login_manager.needs_refresh_message = 'Session timed out, please login again!!'
login_manager.needs_refresh_message_category = 'info'

@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(days=1)
    session.modified = True

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80), EqualTo('confirm', message='Password must match')])
    confirm = PasswordField('Repeat Password')

class UpdateProfileForm(FlaskForm):
    email = StringField('email', validators=[Email(message='Invalid email'), Length(max=50)])
    password = PasswordField('password', validators=[Length(min=8, max=80), EqualTo('confirm', message='Password must match')])
    confirm = PasswordField('Repeat Password')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))
        flash('Invaild username or password', 'danger')
        return redirect(url_for('login'))
    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('New user created! You can login now', 'info')
        return redirect(url_for('login'))
    return render_template('signup.html',form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You were logged out', 'info')
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = UpdateProfileForm()
    if form.validate_on_submit():
        print ("Profile start")
        print (form)
        print (current_user.id)
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        #print (form.email.data)
        email=form.email.data
        update2user = User.query.filter(User.id==current_user.id).first()
        update2user.email = email
        update2user.password = hashed_password
        db.session.commit()
        logout_user()
        flash('User Info updated! Please login again', 'info')
        return redirect(url_for('login'))
    return render_template('profile.html',form=form,current_user=current_user)

@app.route('/deleteuser', methods=['GET', 'POST'])
@login_required
def deleteuser():
    id = current_user.id
    logout_user()
    User.query.filter(User.id==id).delete()
    db.session.commit()
    flash('User deleted!', 'warning')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)