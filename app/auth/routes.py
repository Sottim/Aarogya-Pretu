from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from app.utils.crypto import CryptoManager
from app import db
from app.models import User
from app.auth.forms import LoginForm, RegistrationForm, ResetPasswordRequestForm, ResetPasswordForm
from app.email import send_verification_email, generate_verification_token, verify_token, send_password_reset_email
from urllib.parse import urlparse as url_parse
import logging
from datetime import datetime, timedelta
from flask import current_app


# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

bp = Blueprint('auth', __name__)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            if not user.is_verified:
                flash('Please verify your email address before logging in.', 'warning')
                return redirect(url_for('auth.login'))
            
            login_user(user, remember=form.remember_me.data)
            next_page = request.args.get('next')
            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('main.index')
            return redirect(next_page)
        flash('Invalid email or password', 'danger')
    
    return render_template('auth/login.html', title='Login', form=form)

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            # Generate cryptographic keys
            logger.debug("Generating cryptographic keys...")
            crypto_manager = CryptoManager()
            private_key, public_key = crypto_manager.generate_key_pair()
            
            # Ensure keys are in correct string format
            if isinstance(private_key, bytes):
                private_key = private_key.decode('utf-8')
            if isinstance(public_key, bytes):
                public_key = public_key.decode('utf-8')
                
            # Create user with verification fields
            user = User(
                username=form.username.data,
                email=form.email.data,
                type=form.type.data,
                private_key=private_key,
                public_key=public_key,
                is_verified=False
            )
            user.set_password(form.password.data)
            
            # Generate verification token
            user.verification_token = generate_verification_token(user.email)
            user.verification_token_expires = datetime.utcnow() + timedelta(hours=1)
            
            db.session.add(user)
            db.session.commit()
            
            # Send verification email
            send_verification_email(user)
            
            flash('A verification email has been sent to your email address. Please check your inbox and verify your email to complete registration.', 'info')
            return redirect(url_for('auth.login'))
            
        except Exception as e:
            logger.error(f"Error during registration: {str(e)}")
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')
            return redirect(url_for('auth.register'))
    
    return render_template('auth/register.html', title='Register', form=form)

@bp.route('/verify-email/<token>')
def verify_email(token):
    email = verify_token(token)
    if not email:
        flash('The verification link is invalid or has expired.', 'danger')
        return redirect(url_for('auth.login'))
    
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('No user found with this email address.', 'danger')
        return redirect(url_for('auth.login'))
    
    if user.is_verified:
        flash('Your email is already verified.', 'info')
        return redirect(url_for('auth.login'))
    
    user.is_verified = True
    user.verification_token = None
    user.verification_token_expires = None
    db.session.commit()
    
    flash('Your email has been verified. You can now log in.', 'success')
    return redirect(url_for('auth.login'))

@bp.route('/resend-verification-email', methods=['POST'])
@login_required
def resend_verification_email():
    if current_user.is_verified:
        flash('Your email is already verified.', 'info')
        return redirect(url_for('main.index'))
    
    if current_user.verification_token_expires and current_user.verification_token_expires > datetime.utcnow():
        flash('A verification email has already been sent. Please check your inbox.', 'info')
        return redirect(url_for('auth.login'))
    
    current_user.verification_token = generate_verification_token(current_user.email)
    current_user.verification_token_expires = datetime.utcnow() + timedelta(hours=1)
    db.session.commit()
    
    send_verification_email(current_user)
    
    flash('A new verification email has been sent to your email address.', 'info')
    return redirect(url_for('auth.login'))

@bp.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash('Check your email for the instructions to reset your password')
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password_request.html',
                          title='Reset Password', form=form)

@bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('main.index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', form=form)

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))