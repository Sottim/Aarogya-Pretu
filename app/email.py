from flask_mail import Mail, Message
from flask import current_app, url_for
from itsdangerous import URLSafeTimedSerializer
from flask import render_template
from app.utils.crypto import CryptoManager
from app import Mail
from threading import Thread

mail = Mail()

def init_app(app):
    mail.init_app(app)

def generate_verification_token(email):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-verification')

def verify_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt='email-verification',
            max_age=expiration
        )
        return email
    except:
        return None

def send_verification_email(user):
    token = generate_verification_token(user.email)
    verify_url = f"{current_app.config['FRONTEND_URL']}/verify-email/{token}"
    
    msg = Message(
        'Verify Your Email',
        sender=current_app.config['MAIL_DEFAULT_SENDER'],
        recipients=[user.email]
    )
    msg.body = f'''
    Dear {user.username},
    
    Thank you for registering with Aarogya Pretu. Please click the link below to verify your email address:
    
    {verify_url}
    
    If you did not register for an account, please ignore this email.
    
    Best regards,
    Aarogya Pretu Team
    '''
    mail.send(msg)

def send_password_reset_email(user):
    token = user.get_reset_password_token()
    msg = Message('Password Reset Request',
                  sender=current_app.config['MAIL_DEFAULT_SENDER'],
                  recipients=[user.email])
    
    # Get the frontend URL from config
    frontend_url = current_app.config['FRONTEND_URL']
    
    # Construct the reset URL
    reset_url = f"{frontend_url}/reset_password/{token}"
    
    msg.body = render_template('email/reset_password.txt',
                              user=user,
                              reset_url=reset_url)
    msg.html = render_template('email/reset_password.html',
                              user=user,
                              reset_url=reset_url)
    mail.send(msg)