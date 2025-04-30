''' Most of this content is inspired by https://www.youtube.com/watch?v=71EU8gnZqZQ'''

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError

from datetime import datetime

from flask_bcrypt import Bcrypt

# Adding Necessities
app = Flask(__name__)
app.secret_key = 'your_secret_key'

#connecting to database.db
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)

# encrypting passwords
bycrypt = Bcrypt(app)

# Login Managment

Login_manager = LoginManager()
Login_manager.init_app(app)
Login_manager.login_view = 'Login'

@Login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(
    validators=[InputRequired(), Length(min=4, max =30)], 
    render_kw={'placeholder': 'Username'})

    password = PasswordField(
    validators=[InputRequired(), Length(min=4, max =30)], 
    render_kw={'placeholder': 'Password'})
    
    submit = SubmitField('Register')


    def validate_username(self, username):
        existing_username = Users.query.filter_by(username=username.data).first()
        if existing_username:
            raise ValidationError("Username already taken, please choose a different one.")

    
class LoginForm(FlaskForm):
    username = StringField(
    validators=[InputRequired(), Length(min=4, max =30)], 
    render_kw={'placeholder': 'Username'})

    password = PasswordField(
    validators=[InputRequired(), Length(min=4, max =30)], 
    render_kw={'placeholder': 'Password'})
    
    submit = SubmitField('Login')


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first() # check if the username matches one in databae
        if user:
            if bycrypt.check_password_hash(user.password, form.password.data): # check if password matches the one in database
                login_user(user)
                return redirect(url_for('dashboard')) # redirect to dashboard if login
    return render_template('login.html', form=form) # creates form variable in html

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required # login required for dashboard
def dashboard():
    return render_template('dashboard.html', username=current_user.username)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_pass = bycrypt.generate_password_hash(form.password.data)
        new_user = Users(username=form.username.data, password=hashed_pass)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

# Run HTML
if __name__ == '__main__':
    app.run(debug=True)