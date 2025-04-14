from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Length
from app.models import User

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    type = SelectField('Account Type', choices=[('patient', 'Patient'), ('doctor', 'Doctor')], validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Request Password Reset')

# class RegistrationForm(FlaskForm):
#     username = StringField('Username', validators=[
#         DataRequired(), 
#         Length(min=3, max=64, message='Username must be between 3 and 64 characters')
#     ])
#     email = StringField('Email', validators=[DataRequired(), Email()])
#     password = PasswordField('Password', validators=[
#         DataRequired(), 
#         Length(min=8, message='Password must be at least 8 characters long'),
#         Length(min=8, message='Password must be at least 8 characters long')
#     ])
#     confirm_password = PasswordField(
#         'Confirm Password', 
#         validators=[
#             DataRequired(), 
#             EqualTo('password', message='Passwords must match')
#         ]
#     )
#     user_type = RadioField('User Type', 
#         choices=[('patient', 'Patient'), ('doctor', 'Doctor')], 
#         validators=[DataRequired()],
#         default='patient'
#     )
#     license_number = StringField('License Number', validators=[
#         Optional(), 
#         Length(min=5, max=64, message='License number must be between 5 and 64 characters')
#     ])
#     submit = SubmitField('Register')

#     def validate_username(self, username):
#         user = User.query.filter_by(username=username.data).first()
#         if user:
#             raise ValidationError('Username is already taken. Please choose a different one.')

#     def validate_email(self, email):
#         user = User.query.filter_by(email=email.data).first()
#         if user:
#             raise ValidationError('Email is already registered. Please use a different email.')

#     def validate_license_number(self, license_number):
#         # Only validate license number if user type is doctor
#         if self.user_type.data == 'doctor':
#             if not license_number.data:
#                 raise ValidationError('License number is required for doctors.')
            
#             # Check if license number is unique for doctors
#             existing_doctor = User.query.filter_by(
#                 license_number=license_number.data, 
#                 type='doctor'
#             ).first()
#             if existing_doctor:
#                 raise ValidationError('This license number is already registered.')
