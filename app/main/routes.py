from flask import render_template, jsonify, flash, redirect, url_for, request
from flask_login import login_required, current_user
from app.main import bp
from app.models import User, HealthRecord, AccessRequest
from app import db
from app.utils.crypto import CryptoManager
import traceback
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@bp.route('/')
def index():
    return render_template('main/index.html', title='Home')

@bp.route('/health_data', methods=['GET', 'POST'])
@login_required
def health_data():
    if current_user.is_doctor:
        flash('This page is only for patients', 'warning')
        return redirect(url_for('doctor.dashboard'))
    
    if request.method == 'POST':
        form_type = request.form.get('form_type')
        if form_type == 'add':
            try:
                # Log form data for debugging
                logger.debug(f"Form data received: height={request.form.get('height')}, "
                           f"weight={request.form.get('weight')}, "
                           f"blood_type={request.form.get('blood_type')}")
                
                # Collect form data
                health_data = {
                    'height': float(request.form.get('height')),
                    'weight': float(request.form.get('weight')),
                    'blood_type': request.form.get('blood_type')
                }
                
                logger.debug("Health data formatted successfully")
                
                # Create a new health record
                crypto_manager = CryptoManager()
                
                try:
                    # Encrypt and sign the health data
                    logger.debug("Encrypting health data...")
                    encrypted_data = crypto_manager.encrypt_data(health_data, current_user.public_key)
                    logger.debug("Health data encrypted successfully")
                    
                    logger.debug("Signing health data...")
                    signature = crypto_manager.sign_data(health_data, current_user.private_key)
                    logger.debug("Health data signed successfully")
                    
                    # Create and save the record
                    logger.debug("Creating health record...")
                    record = HealthRecord(patient_id=current_user.id)
                    record.set_encrypted_data(encrypted_data)
                    record.signature = signature
                    
                    db.session.add(record)
                    db.session.commit()
                    logger.debug("Health record saved successfully")
                    
                    flash('Health record added successfully!', 'success')
                except Exception as e:
                    logger.error(f"Error during record creation: {str(e)}")
                    logger.error(traceback.format_exc())
                    db.session.rollback()
                    flash(f'Error saving health record: {str(e)}', 'danger')
                    
            except ValueError as e:
                logger.error(f"ValueError during health data processing: {str(e)}")
                flash(f'Invalid data provided: {str(e)}', 'danger')
            except Exception as e:
                logger.error(f"Unexpected error in health data route: {str(e)}")
                logger.error(traceback.format_exc())
                flash(f'An error occurred: {str(e)}', 'danger')
        else:
            flash('Invalid form type', 'danger')
        
        return redirect(url_for('main.health_data'))
    
    # Get and decrypt records
    records = HealthRecord.query.filter_by(patient_id=current_user.id).all()
    decrypted_records = []
    
    if records:
        crypto_manager = CryptoManager()
        for record in records:
            try:
                encrypted_data = record.get_encrypted_data()
                decrypted_data = crypto_manager.decrypt_data(
                    encrypted_data,
                    current_user.private_key
                )
                decrypted_records.append({
                    'id': record.id,
                    'data': decrypted_data,
                    'timestamp': record.timestamp
                })
            except Exception as e:
                logger.error(f"Error decrypting record {record.id}: {str(e)}")
                flash(f'Error decrypting record: {str(e)}', 'danger')
    
    return render_template('main/health_data.html', title='Health Data', records=decrypted_records)

@bp.route('/access_requests')
@login_required
def access_requests():
    if current_user.is_doctor:
        flash('This page is only for patients', 'warning')
        return redirect(url_for('doctor.dashboard'))
    
    pending_requests = AccessRequest.query.filter_by(
        patient_id=current_user.id,
        status='pending'
    ).all()
    
    approved_requests = AccessRequest.query.filter_by(
        patient_id=current_user.id,
        status='approved'
    ).all()
    
    return render_template('main/access_requests.html',
                         title='Access Requests',
                         pending_requests=pending_requests,
                         approved_requests=approved_requests)

@bp.route('/handle_access_request/<int:request_id>', methods=['POST'])
@login_required
def handle_access_request(request_id):
    if current_user.is_doctor:
        flash('This page is only for patients', 'warning')
        return redirect(url_for('doctor.dashboard'))
    
    # Get the access request
    access_request = AccessRequest.query.get_or_404(request_id)
    
    # Verify the request belongs to the current user
    if access_request.patient_id != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('main.access_requests'))
    
    action = request.form.get('action')
    
    try:
        if action == 'approve':
            access_request.status = 'approved'
            flash('Access request approved', 'success')
        elif action == 'deny':
            access_request.status = 'denied'
            flash('Access request denied', 'success')
        elif action == 'revoke':
            access_request.status = 'revoked'
            flash('Access has been revoked', 'success')
        else:
            flash('Invalid action', 'danger')
            return redirect(url_for('main.access_requests'))
        
        db.session.commit()
    except Exception as e:
        logger.error(f"Error handling access request: {str(e)}")
        db.session.rollback()
        flash('Error processing request', 'danger')
    
    return redirect(url_for('main.access_requests'))
