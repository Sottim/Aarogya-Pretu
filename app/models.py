from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime
import json
from flask import current_app

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    # Increase length to accommodate longer hashes like scrypt
    password_hash = db.Column(db.String(256))
    public_key = db.Column(db.Text)
    private_key = db.Column(db.Text)  # Encrypted with user's password
    type = db.Column(db.String(20), nullable=False)  # 'patient' or 'doctor'
    health_records = db.relationship('HealthRecord', backref='patient', lazy=True)
    
    # For doctors only
    license_number = db.Column(db.String(64), unique=True, nullable=True)

    # For email verification
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(128), unique=True)
    verification_token_expires = db.Column(db.DateTime)

    def is_verification_token_valid(self):
        if not self.verification_token:
            return False
        if not self.verification_token_expires:
            return False
        return self.verification_token_expires > datetime.utcnow()
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_reset_password_token(self, expires_in=3600):
        s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id}, salt='password-reset')

    @staticmethod
    def verify_reset_password_token(token):
        s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token, salt='password-reset', max_age=3600)
            return User.query.get(data['user_id'])
        except:
            return None

    @property
    def is_doctor(self):
        return self.type == 'doctor'

    @property
    def is_patient(self):
        return self.type == 'patient'

class HealthRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_data = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    signature = db.Column(db.Text, nullable=False)
    
    def set_encrypted_data(self, data_dict):
        """Convert dictionary to JSON string for storage"""
        if isinstance(data_dict, str):
            self.encrypted_data = data_dict
        else:
            self.encrypted_data = json.dumps(data_dict)
    
    def get_encrypted_data(self):
        """Convert stored JSON string back to dictionary"""
        try:
            if isinstance(self.encrypted_data, dict):
                return self.encrypted_data
            return json.loads(self.encrypted_data)
        except json.JSONDecodeError:
            return self.encrypted_data

class AccessRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    encrypted_key = db.Column(db.Text)  # Encrypted session key for approved requests
    
    doctor = db.relationship('User', foreign_keys=[doctor_id], backref='doctor_requests')
    patient = db.relationship('User', foreign_keys=[patient_id], backref='patient_requests')

# Define type for encrypted data (use LargeBinary for raw bytes)
EncryptedType = db.LargeBinary

class PastIllness(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True, nullable=False)
    # Encrypted Fields (using patient's public key)
    illness_name_encrypted = db.Column(EncryptedType, nullable=False)
    diagnosis_date_encrypted = db.Column(EncryptedType, nullable=True) # Store encrypted date representation
    details_encrypted = db.Column(EncryptedType, nullable=True) # Notes, treatment, etc.
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship
    patient = db.relationship('User', backref=db.backref('past_illnesses', lazy='dynamic'))

    def __repr__(self):
        return f'<PastIllness {self.id} for User {self.user_id}>'

class Surgery(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True, nullable=False)
    # Encrypted Fields
    surgery_name_encrypted = db.Column(EncryptedType, nullable=False)
    surgery_date_encrypted = db.Column(EncryptedType, nullable=True)
    details_encrypted = db.Column(EncryptedType, nullable=True) # Surgeon, hospital, notes
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    patient = db.relationship('User', backref=db.backref('surgeries', lazy='dynamic'))

    def __repr__(self):
        return f'<Surgery {self.id} for User {self.user_id}>'

class Allergy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True, nullable=False)
    # Encrypted Fields
    allergen_encrypted = db.Column(EncryptedType, nullable=False)
    severity_encrypted = db.Column(EncryptedType, nullable=True) # e.g., 'Mild', 'Severe'
    reaction_details_encrypted = db.Column(EncryptedType, nullable=True) # Description of reaction
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    patient = db.relationship('User', backref=db.backref('allergies', lazy='dynamic'))

    def __repr__(self):
        return f'<Allergy {self.id} for User {self.user_id}>'

class Medication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True, nullable=False)
    # Encrypted Fields
    medication_name_encrypted = db.Column(EncryptedType, nullable=False)
    dosage_encrypted = db.Column(EncryptedType, nullable=True)
    frequency_encrypted = db.Column(EncryptedType, nullable=True)
    start_date_encrypted = db.Column(EncryptedType, nullable=True)
    end_date_encrypted = db.Column(EncryptedType, nullable=True) # Null if ongoing
    reason_encrypted = db.Column(EncryptedType, nullable=True) # Condition being treated
    # Plaintext Fields
    is_current = db.Column(db.Boolean, default=True, index=True) # Easier to filter current meds
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    patient = db.relationship('User', backref=db.backref('medications', lazy='dynamic'))

    def __repr__(self):
        return f'<Medication {self.id} for User {self.user_id}>'

class Immunization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True, nullable=False)
    # Encrypted Fields
    vaccine_name_encrypted = db.Column(EncryptedType, nullable=False)
    date_received_encrypted = db.Column(EncryptedType, nullable=True)
    details_encrypted = db.Column(EncryptedType, nullable=True) # Dose number, manufacturer, location
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    patient = db.relationship('User', backref=db.backref('immunizations', lazy='dynamic'))

    def __repr__(self):
        return f'<Immunization {self.id} for User {self.user_id}>'

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))
