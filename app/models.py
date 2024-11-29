from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    public_key = db.Column(db.Text)
    private_key = db.Column(db.Text)  # Encrypted with user's password
    type = db.Column(db.String(20), nullable=False)  # 'patient' or 'doctor'
    health_records = db.relationship('HealthRecord', backref='patient', lazy=True)
    
    # For doctors only
    license_number = db.Column(db.String(64), unique=True, nullable=True)
    verified = db.Column(db.Boolean, default=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

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

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))
