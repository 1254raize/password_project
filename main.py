from flask import Flask, render_template, redirect, url_for, flash, session
from flask_bootstrap import Bootstrap
from sqlalchemy.orm import relationship
from forms import SignupForm, LoginForm, NewPasswordForm
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, UserMixin, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT = bytes(os.environ['SALT'], 'utf-8')

SECRET_KEY = os.environ['SECRET_KEY']

app = Flask(__name__)
app.secret_key = SECRET_KEY
Bootstrap(app)

db = SQLAlchemy(app)

try:
    URI = os.environ['DATABASE_URL']

    if URI.startswith("postgres://"):
        URI = URI.replace("postgres://", "postgresql://", 1)

        app.config["SQLALCHEMY_DATABASE_URI"] = URI
except KeyError:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"

# LOGIN CONFIG
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(), nullable=False)
    website_passwords = relationship("UserPasswords", back_populates="user")


class UserPasswords(db.Model):
    __tablename__ = "passwords"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    user = relationship("User", back_populates="website_passwords")
    website_name = db.Column(db.String(250), nullable=False)
    website_user = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False)
    website_password = db.Column(db.String(), nullable=False)


db.create_all()


def check_master_password(user_pass, user):
    if check_password_hash(password=user_pass, pwhash=user.password):
        return True
    else:
        return False


@app.route('/')
def home():
    return render_template('index.html', user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        user = User.query.filter_by(email=login_form.email.data).first()

        if user:
            user_pass = login_form.password.data
            if check_master_password(user_pass, user):
                login_user(user)
                session[current_user.email] = login_form.password.data
                flash('Logged In!!')
                return redirect(url_for('user_passwords'))
            else:
                flash('Wrong Password!!!')
                return redirect(url_for('login'))

        else:
            flash("Wrong Email!!!")
            return redirect(url_for("login"))
    return render_template('login.html', form=login_form, user=current_user)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    signup_form = SignupForm()
    if signup_form.validate_on_submit():
        if User.query.filter_by(email=signup_form.email.data).first():
            flash('Email already in use')
            return redirect(url_for('signup'))

        else:
            new_user = User(
                user_name=signup_form.name.data,
                email=signup_form.email.data,
                password=generate_password_hash(signup_form.password.data,
                                                method='pbkdf2:sha256',
                                                salt_length=16)
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('user_passwords'))

    return render_template('signup.html', form=signup_form, user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    flash('Logged out!!!')
    return redirect(url_for('home', user=current_user))


@app.route('/passwords', methods=['GET', 'POST'])
@login_required
def user_passwords():
    fernet = create_fernet(session[current_user.email])

    passwords_from_db = current_user.website_passwords
    passwords = []
    for password in passwords_from_db:
        passwords.append({
            'website_name': password.website_name,
            'website_user': password.website_user,
            'email': password.email,
            'website_password': (fernet.decrypt(password.website_password)).decode('utf8')
        })

    new_password_form = NewPasswordForm()

    if new_password_form.validate_on_submit():
        user_pass = new_password_form.master_password.data
        if check_master_password(user_pass, current_user):
            master_password = new_password_form.master_password.data

            fernet = create_fernet(master_password)

            website_password = new_password_form.website_password.data
            website_password_b = str.encode(website_password)

            token_b = fernet.encrypt(website_password_b)
            # token = token_b.decode('utf-8')

            new_password = UserPasswords(
                user=current_user,
                website_name=new_password_form.website_name.data,
                website_user=new_password_form.website_user.data,
                email=new_password_form.email.data,
                website_password=token_b,
            )

            db.session.add(new_password)
            db.session.commit()

            return redirect(url_for('user_passwords'))

        else:
            flash('Wrong Master Password')
            return redirect(url_for('passwords'))

    return render_template('userPasswords.html', user=current_user, form=new_password_form, passwords=passwords)


def create_fernet(master_password):
    master_password_b = str.encode(master_password)
    salt = SALT
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password_b))
    f = Fernet(key)
    return f


if __name__ == '__main__':
    app.run(debug=True)
