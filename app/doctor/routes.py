from flask import render_template, flash, redirect, url_for, request
from flask_login import login_required, current_user
from app.doctor import bp
from app.models import User, AccessRequest, HealthRecord
from app import db
from app.utils.crypto import CryptoManager
import logging

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
