from flask import render_template, flash, redirect, url_for, request
from flask_login import login_required, current_user
from app.doctor import bp
from app.models import User, AccessRequest, HealthRecord, PastIllness, Surgery, Allergy, Medication
from app import db
from app.utils.crypto import CryptoManager
import logging
import json

logger = logging.getLogger(__name__)

@bp.route('/dashboard')
@login_required
def dashboard():
    if not current_user.is_doctor:
        flash('This page is only for doctors', 'warning')
        return redirect(url_for('main.index'))
    
    # Get the search query
    search_query = request.args.get('query', '').strip()
    
    # Search for patients
    patients = []
    if search_query:
        id_filter = User.id == int(search_query) if search_query.isdigit() else False
        patients = User.query.filter(
            User.type == 'patient'
        ).filter(
            db.or_(
                id_filter,
                User.username.ilike(f'%{search_query}%'),
                User.email.ilike(f'%{search_query}%')
            )
        ).all()
    
    # Get access request status for found patients
    access_requests = {}
    if patients:
        requests = AccessRequest.query.filter_by(
            doctor_id=current_user.id
        ).filter(
            AccessRequest.patient_id.in_([p.id for p in patients])
        ).all()
        
        access_requests = {
            req.patient_id: req.status 
            for req in requests
        }
    
    return render_template(
        'doctor/dashboard.html',
        title='Doctor Dashboard',
        patients=patients,
        access_requests=access_requests,
        search_query=search_query
    )

@bp.route('/request_access/<int:patient_id>', methods=['POST'])
@login_required
def request_access(patient_id):
    if not current_user.is_doctor:
        flash('This page is only for doctors', 'warning')
        return redirect(url_for('main.index'))
    
    # Check if patient exists
    patient = User.query.get_or_404(patient_id)
    if not patient.is_patient:
        flash('Invalid patient ID', 'danger')
        return redirect(url_for('doctor.dashboard'))
    
    # Check if request already exists
    existing_request = AccessRequest.query.filter_by(
        doctor_id=current_user.id,
        patient_id=patient_id
    ).first()
    
    if existing_request:
        flash(f'Access request already exists with status: {existing_request.status}', 'info')
    else:
        # Create new access request
        access_request = AccessRequest(
            doctor_id=current_user.id,
            patient_id=patient_id,
            status='pending'
        )
        db.session.add(access_request)
        try:
            db.session.commit()
            flash('Access request sent successfully', 'success')
        except Exception as e:
            logger.error(f"Error creating access request: {str(e)}")
            db.session.rollback()
            flash('Error sending access request', 'danger')
    
    return redirect(url_for('doctor.dashboard', query=request.args.get('query', '')))

@bp.route('/view_records/<int:patient_id>')
@login_required
def view_records(patient_id):
    if not current_user.is_doctor:
        flash('This page is only for doctors', 'warning')
        return redirect(url_for('main.index'))
    
    # Check if doctor has approved access
    access = AccessRequest.query.filter_by(
        doctor_id=current_user.id,
        patient_id=patient_id,
        status='approved'
    ).first()
    
    if not access:
        flash('You do not have access to view these records', 'danger')
        return redirect(url_for('doctor.dashboard'))
    
    # Get patient and their records
    patient = User.query.get_or_404(patient_id)
    records = HealthRecord.query.filter_by(patient_id=patient_id).all()
    decrypted_records = []
    
    if records:
        crypto_manager = CryptoManager()
        for record in records:
            try:
                encrypted_data = record.get_encrypted_data()
                decrypted_data = crypto_manager.decrypt_data(
                    encrypted_data,
                    patient.private_key
                )
                decrypted_records.append({
                    'id': record.id,
                    'data': decrypted_data,
                    'timestamp': record.timestamp
                })
            except Exception as e:
                logger.error(f"Error decrypting record {record.id}: {str(e)}")
                flash(f'Error decrypting record: {str(e)}', 'danger')
    
    return render_template(
        'doctor/view_records.html',
        title=f'Health Records - {patient.username}',
        patient=patient,
        records=decrypted_records
    )

@bp.route('/view_medical_history/<int:patient_id>')
@login_required
def view_medical_history(patient_id):
    if not current_user.is_doctor:
        flash('This page is only for doctors', 'warning')
        return redirect(url_for('main.index'))
    
    # Check if doctor has approved access
    access = AccessRequest.query.filter_by(
        doctor_id=current_user.id,
        patient_id=patient_id,
        status='approved'
    ).first()
    
    if not access:
        flash('You do not have access to view this patient\'s medical history', 'danger')
        return redirect(url_for('doctor.dashboard'))
    
    # Get patient and their medical history
    patient = User.query.get_or_404(patient_id)
    
    # Get all medical history records
    illnesses = PastIllness.query.filter_by(user_id=patient_id).all()
    surgeries = Surgery.query.filter_by(user_id=patient_id).all()
    allergies = Allergy.query.filter_by(user_id=patient_id).all()
    medications = Medication.query.filter_by(user_id=patient_id).all()
    
    try:
        # Decrypt all records
        decrypted_illnesses = []
        for illness in illnesses:
            illness_name = CryptoManager.decrypt_data(
                json.loads(illness.illness_name_encrypted.decode('utf-8')),
                patient.private_key
            )
            diagnosis_date = CryptoManager.decrypt_data(
                json.loads(illness.diagnosis_date_encrypted.decode('utf-8')),
                patient.private_key
            )
            details = CryptoManager.decrypt_data(
                json.loads(illness.details_encrypted.decode('utf-8')),
                patient.private_key
            )
            
            decrypted_illnesses.append({
                'id': illness.id,
                'illness_name': illness_name,
                'diagnosis_date': diagnosis_date,
                'details': details
            })

        decrypted_surgeries = []
        for surgery in surgeries:
            surgery_name = CryptoManager.decrypt_data(
                json.loads(surgery.surgery_name_encrypted.decode('utf-8')),
                patient.private_key
            )
            surgery_date = CryptoManager.decrypt_data(
                json.loads(surgery.surgery_date_encrypted.decode('utf-8')),
                patient.private_key
            )
            details = CryptoManager.decrypt_data(
                json.loads(surgery.details_encrypted.decode('utf-8')),
                patient.private_key
            )
            
            decrypted_surgeries.append({
                'id': surgery.id,
                'surgery_name': surgery_name,
                'surgery_date': surgery_date,
                'details': details
            })

        decrypted_allergies = []
        for allergy in allergies:
            allergen = CryptoManager.decrypt_data(
                json.loads(allergy.allergen_encrypted.decode('utf-8')),
                patient.private_key
            )
            severity = CryptoManager.decrypt_data(
                json.loads(allergy.severity_encrypted.decode('utf-8')),
                patient.private_key
            )
            reaction_details = CryptoManager.decrypt_data(
                json.loads(allergy.reaction_details_encrypted.decode('utf-8')),
                patient.private_key
            )
            
            decrypted_allergies.append({
                'id': allergy.id,
                'allergen': allergen,
                'severity': severity,
                'reaction_details': reaction_details
            })

        decrypted_medications = []
        for medication in medications:
            medication_name = CryptoManager.decrypt_data(
                json.loads(medication.medication_name_encrypted.decode('utf-8')),
                patient.private_key
            )
            dosage = CryptoManager.decrypt_data(
                json.loads(medication.dosage_encrypted.decode('utf-8')),
                patient.private_key
            )
            frequency = CryptoManager.decrypt_data(
                json.loads(medication.frequency_encrypted.decode('utf-8')),
                patient.private_key
            )
            start_date = CryptoManager.decrypt_data(
                json.loads(medication.start_date_encrypted.decode('utf-8')),
                patient.private_key
            )
            end_date = CryptoManager.decrypt_data(
                json.loads(medication.end_date_encrypted.decode('utf-8')),
                patient.private_key
            )
            reason = CryptoManager.decrypt_data(
                json.loads(medication.reason_encrypted.decode('utf-8')),
                patient.private_key
            )
            
            decrypted_medications.append({
                'id': medication.id,
                'medication_name': medication_name,
                'dosage': dosage,
                'frequency': frequency,
                'start_date': start_date,
                'end_date': end_date,
                'reason': reason,
                'is_current': medication.is_current
            })

        return render_template(
            'doctor/view_medical_history.html',
            title=f'Medical History - {patient.username}',
            patient=patient,
            illnesses=decrypted_illnesses,
            surgeries=decrypted_surgeries,
            allergies=decrypted_allergies,
            medications=decrypted_medications
        )

    except Exception as e:
        logger.error(f"Error decrypting medical history: {str(e)}")
        flash('Error accessing medical history', 'danger')
        return redirect(url_for('doctor.dashboard'))
