from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user
from app.auth import bp
from app.auth.forms import LoginForm, RegistrationForm
from app.models import User
from app import db
from app.utils.crypto import CryptoManager
import logging

logger = logging.getLogger(__name__)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                if user.is_doctor:
                    next_page = url_for('doctor.dashboard')
                else:
                    next_page = url_for('main.index')
            return redirect(next_page)
        else:
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
                
            logger.debug(f"Generated private key format: {private_key[:64]}...")
            logger.debug(f"Generated public key format: {public_key[:64]}...")
            
            # Create new user with keys
            new_user = User(
                username=form.username.data,
                email=form.email.data, 
                type=form.user_type.data,
                public_key=public_key,
                private_key=private_key,
                license_number=form.license_number.data if form.user_type.data == 'doctor' else None
            )
            
            # Set password hash
            new_user.set_password(form.password.data)
            
            # Save user to database
            db.session.add(new_user)
            db.session.commit()
            logger.debug("User registered successfully")
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('auth.login'))
            
        except Exception as e:
            logger.error(f"Error during registration: {str(e)}")
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')
    
    return render_template('auth/register.html', title='Register', form=form)

@bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.index'))
