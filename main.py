from flask import Flask, render_template, redirect, url_for, flash, session, abort, request, make_response, jsonify
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
from datetime import timedelta
from functools import wraps

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


@app.before_request
def before_request_func():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=5)
    session.modified = True


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

            user = User.query.filter_by(email=signup_form.email.data).first()
            login_user(user)
            session[current_user.email] = signup_form.password.data
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
    passwords = create_decoded_password()

    new_password_form = NewPasswordForm()

    if new_password_form.validate_on_submit():
        user_pass = new_password_form.master_password.data
        if check_master_password(user_pass, current_user):

            token = create_token(new_password_form)

            new_password = UserPasswords(
                user=current_user,
                website_name=new_password_form.website_name.data,
                website_user=new_password_form.website_user.data,
                email=new_password_form.email.data,
                website_password=token,
            )

            db.session.add(new_password)
            db.session.commit()

            return redirect(url_for('user_passwords'))

        else:
            flash('Wrong Master Password')
            return redirect(url_for('user_passwords'))

    return render_template('userPasswords.html', user=current_user, form=new_password_form, passwords=passwords)


def create_decoded_password():
    fernet = create_fernet(session[current_user.email])
    passwords_from_db = current_user.website_passwords
    passwords = []
    for password in passwords_from_db:
        password_b = fernet.decrypt(bytes(password.website_password, 'utf-8'))
        passwords.append({
            'id': password.id,
            'website_name': password.website_name,
            'website_user': password.website_user,
            'email': password.email,
            'website_password': password_b.decode('utf8')
        })
    return passwords


def create_token(form):
    try:
        master_password = form.master_password.data
    except AttributeError:
        master_password = form['master_password']

    fernet = create_fernet(master_password)

    try:
        website_password = form.website_password.data
    except AttributeError:
        website_password = form['website_password']

    website_password_b = str.encode(website_password)

    token_b = fernet.encrypt(website_password_b)
    token = token_b.decode('utf-8')

    return token


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


@app.route('/delete-pass/<pass_id>', methods=['GET', 'POST'])
@login_required
def delete_password(pass_id):
    # print(current_user.website_passwords)
    # print(current_user.email)
    UserPasswords.query.filter_by(id=pass_id).delete()
    db.session.commit()

    return redirect(url_for('user_passwords'))


@app.route('/edit-pass/<pass_id>', methods=['GET', 'POST'])
@login_required
def edit_password(pass_id):
    if request.method == 'POST':
        form_data = request.form
        user_pass = form_data['master_password']

        if check_master_password(user_pass, current_user):
            password_to_edit = create_token(form_data)
            UserPasswords.query.filter_by(id=pass_id).update(dict(email=form_data['email'],
                                                                  website_name=form_data['website_name'],
                                                                  website_user=form_data['website_user'],
                                                                  website_password=password_to_edit))
            db.session.commit()
        return redirect(url_for('user_passwords'))


@app.route('/api-login', methods=['POST'])
def api_login():
    auth = request.form
    print(auth)
    if not auth or not auth.get('email') or not auth.get('password'):
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic-realm = "Login Required !!'}
        )
    else:
        user = User.query.filter_by(email=auth.get('email')).first()
        if check_master_password(user_pass=auth.get('password'), user=user):
            print(user.website_passwords)
            login_user(user)
            session[current_user.email] = auth.get('password')
            passwords = create_decoded_password()
            print(passwords)

            return make_response(
                jsonify(passwords),
                200
            )
        else:
            return make_response(
                'Wrong Master Password',
                401,
                {'WWW-Authenticate': 'Basic-realm = "Wrong Master Password !!"'}
            )


if __name__ == '__main__':
    app.run(debug=True)
