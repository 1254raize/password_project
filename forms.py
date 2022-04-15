from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import DataRequired, Length, Email, EqualTo, AnyOf


class SignupForm(FlaskForm):
    name = StringField(label='Name', validators=[DataRequired()])
    email = EmailField(label='Email',
                       validators=[DataRequired(), Email()])
    password = PasswordField(label='Password', validators=[DataRequired(), Length(min=12)])
    password_confirm = PasswordField(label='Confirm password',
                                     validators=[DataRequired(), EqualTo('password', message='Passwords do not match')])
    submit = SubmitField(label='Submit')


class LoginForm(FlaskForm):
    email = EmailField(label='Email', validators=[DataRequired(), Email()])
    password = PasswordField(label="Password", validators=[DataRequired(), Length(min=12)])
    submit = SubmitField(label="Log in")


class NewPasswordForm(FlaskForm):
    website_name = StringField(label='Website Name', validators=[DataRequired()])
    website_user = StringField(label='User Name', validators=[DataRequired()])
    email = EmailField(label='Email', validators=[DataRequired(), Email()])
    website_password = PasswordField(label='Password', validators=[DataRequired()])
    master_password = PasswordField(label='Master Password', validators=[DataRequired()])
    submit = SubmitField(label='Submit')
