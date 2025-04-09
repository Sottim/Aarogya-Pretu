from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app import db
from app.models import PastIllness, Surgery # Add other models later
from app.medical_history import bp
from app.medical_history.forms import PastIllnessForm, SurgeryForm # Add other forms later
from app.utils.crypto import CryptoManager
import logging
import json
from datetime import datetime

logger = logging.getLogger(__name__)

@bp.route('/manage', methods=['GET', 'POST']) # Combined route for now
@login_required
def manage_medical_history():
    # For now, just handle Past Illnesses
    illness_form = PastIllnessForm()
    surgery_form = SurgeryForm()
    
    if illness_form.validate_on_submit():
        try:
            # Encrypt each field using the CryptoManager
            encrypted_illness_name = json.dumps(
                CryptoManager.encrypt_data(
                    illness_form.illness_name.data, 
                    current_user.public_key
                )
            ).encode('utf-8')
            
            encrypted_diagnosis_date = json.dumps(
                CryptoManager.encrypt_data(
                    str(illness_form.diagnosis_date.data), 
                    current_user.public_key
                )
            ).encode('utf-8')
            
            encrypted_details = json.dumps(
                CryptoManager.encrypt_data(
                    illness_form.treatment_details.data, 
                    current_user.public_key
                )
            ).encode('utf-8')

            # Create new PastIllness record with encrypted data
            illness = PastIllness(
                user_id=current_user.id,
                illness_name_encrypted=encrypted_illness_name,
                diagnosis_date_encrypted=encrypted_diagnosis_date,
                details_encrypted=encrypted_details
            )
            
            db.session.add(illness)
            db.session.commit()
            flash('Past illness record added successfully', 'success')
            return redirect(url_for('medical_history.manage_medical_history'))
            
        except Exception as e:
            logger.error(f"Error encrypting past illness data: {str(e)}")
            flash('Error saving past illness record', 'danger')
            return redirect(url_for('medical_history.manage_medical_history'))

    if surgery_form.validate_on_submit():
        try:
            # Encrypt each field using the CryptoManager
            encrypted_surgery_name = json.dumps(
                CryptoManager.encrypt_data(
                    surgery_form.surgery_name.data, 
                    current_user.public_key
                )
            ).encode('utf-8')
            
            encrypted_surgery_date = json.dumps(
                CryptoManager.encrypt_data(
                    str(surgery_form.surgery_date.data), 
                    current_user.public_key
                )
            ).encode('utf-8')
            
            # Combine surgeon, hospital, and details into a single details field
            details_dict = {
                'surgeon': surgery_form.surgeon.data,
                'hospital': surgery_form.hospital.data,
                'details': surgery_form.details.data
            }
            
            encrypted_details = json.dumps(
                CryptoManager.encrypt_data(
                    json.dumps(details_dict), 
                    current_user.public_key
                )
            ).encode('utf-8')

            # Create new Surgery record with encrypted data
            surgery = Surgery(
                user_id=current_user.id,
                surgery_name_encrypted=encrypted_surgery_name,
                surgery_date_encrypted=encrypted_surgery_date,
                details_encrypted=encrypted_details
            )
            
            db.session.add(surgery)
            db.session.commit()
            flash('Surgery record added successfully', 'success')
            return redirect(url_for('medical_history.manage_medical_history'))
            
        except Exception as e:
            logger.error(f"Error encrypting surgery data: {str(e)}")
            flash('Error saving surgery record', 'danger')
            return redirect(url_for('medical_history.manage_medical_history'))

    # Get and decrypt past illnesses for display
    illnesses_query = PastIllness.query.filter_by(user_id=current_user.id).all()
    decrypted_illnesses = []
    
    for illness in illnesses_query:
        try:
            illness_name = CryptoManager.decrypt_data(
                json.loads(illness.illness_name_encrypted.decode('utf-8')),
                current_user.private_key
            )
            diagnosis_date = CryptoManager.decrypt_data(
                json.loads(illness.diagnosis_date_encrypted.decode('utf-8')),
                current_user.private_key
            )
            details = CryptoManager.decrypt_data(
                json.loads(illness.details_encrypted.decode('utf-8')),
                current_user.private_key
            )
            
            decrypted_illnesses.append({
                'id': illness.id,
                'illness_name': illness_name,
                'diagnosis_date': diagnosis_date,
                'treatment_details': details
            })
        except Exception as e:
            logger.error(f"Error decrypting past illness {illness.id}: {str(e)}")
            flash(f'Error decrypting past illness record', 'danger')

    # Get and decrypt surgeries for display
    surgeries_query = Surgery.query.filter_by(user_id=current_user.id).all()
    decrypted_surgeries = []
    
    for surgery in surgeries_query:
        try:
            surgery_name = CryptoManager.decrypt_data(
                json.loads(surgery.surgery_name_encrypted.decode('utf-8')),
                current_user.private_key
            )
            surgery_date = CryptoManager.decrypt_data(
                json.loads(surgery.surgery_date_encrypted.decode('utf-8')),
                current_user.private_key
            )
            
            # Decrypt the details field and extract surgeon, hospital, and details
            details = CryptoManager.decrypt_data(
                json.loads(surgery.details_encrypted.decode('utf-8')),
                current_user.private_key
            )
            details_dict = json.loads(details)
            
            decrypted_surgeries.append({
                'id': surgery.id,
                'surgery_name': surgery_name,
                'surgery_date': surgery_date,
                'surgeon': details_dict.get('surgeon', ''),
                'hospital': details_dict.get('hospital', ''),
                'details': details_dict.get('details', '')
            })
        except Exception as e:
            logger.error(f"Error decrypting surgery {surgery.id}: {str(e)}")
            flash(f'Error decrypting surgery record', 'danger')

    return render_template('medical_history/manage.html', 
                           title='Manage Medical History', 
                           illness_form=illness_form,
                           surgery_form=surgery_form,
                           illnesses=decrypted_illnesses,
                           surgeries=decrypted_surgeries)

@bp.route('/delete/illness/<int:illness_id>', methods=['POST'])
@login_required
def delete_illness(illness_id):
    illness = PastIllness.query.get_or_404(illness_id)
    if illness.user_id != current_user.id:
        flash('You can only delete your own illness records', 'danger')
        return redirect(url_for('medical_history.manage_medical_history'))
    
    try:
        db.session.delete(illness)
        db.session.commit()
        flash('Illness record deleted successfully', 'success')
    except Exception as e:
        logger.error(f"Error deleting illness {illness_id}: {str(e)}")
        flash('Error deleting illness record', 'danger')
    
    return redirect(url_for('medical_history.manage_medical_history'))

@bp.route('/delete/surgery/<int:surgery_id>', methods=['POST'])
@login_required
def delete_surgery(surgery_id):
    surgery = Surgery.query.get_or_404(surgery_id)
    if surgery.user_id != current_user.id:
        flash('You can only delete your own surgery records', 'danger')
        return redirect(url_for('medical_history.manage_medical_history'))
    
    try:
        db.session.delete(surgery)
        db.session.commit()
        flash('Surgery record deleted successfully', 'success')
    except Exception as e:
        logger.error(f"Error deleting surgery {surgery_id}: {str(e)}")
        flash('Error deleting surgery record', 'danger')
    
    return redirect(url_for('medical_history.manage_medical_history'))

@bp.route('/edit/illness/<int:illness_id>', methods=['GET', 'POST'])
@login_required
def edit_illness(illness_id):
    illness = PastIllness.query.get_or_404(illness_id)
    if illness.user_id != current_user.id:
        flash('You can only edit your own illness records', 'danger')
        return redirect(url_for('medical_history.manage_medical_history'))
    
    form = PastIllnessForm()
    
    if form.validate_on_submit():
        try:
            # Encrypt each field using the CryptoManager
            encrypted_illness_name = json.dumps(
                CryptoManager.encrypt_data(
                    form.illness_name.data, 
                    current_user.public_key
                )
            ).encode('utf-8')
            
            encrypted_diagnosis_date = json.dumps(
                CryptoManager.encrypt_data(
                    str(form.diagnosis_date.data), 
                    current_user.public_key
                )
            ).encode('utf-8')
            
            encrypted_details = json.dumps(
                CryptoManager.encrypt_data(
                    form.treatment_details.data, 
                    current_user.public_key
                )
            ).encode('utf-8')

            illness.illness_name_encrypted = encrypted_illness_name
            illness.diagnosis_date_encrypted = encrypted_diagnosis_date
            illness.details_encrypted = encrypted_details
            
            db.session.commit()
            flash('Illness record updated successfully', 'success')
            return redirect(url_for('medical_history.manage_medical_history'))
            
        except Exception as e:
            logger.error(f"Error updating illness {illness_id}: {str(e)}")
            flash('Error updating illness record', 'danger')
            return redirect(url_for('medical_history.manage_medical_history'))
    
    # Populate form with current data
    if request.method == 'GET':
        try:
            illness_name = CryptoManager.decrypt_data(
                json.loads(illness.illness_name_encrypted.decode('utf-8')),
                current_user.private_key
            )
            diagnosis_date = CryptoManager.decrypt_data(
                json.loads(illness.diagnosis_date_encrypted.decode('utf-8')),
                current_user.private_key
            )
            details = CryptoManager.decrypt_data(
                json.loads(illness.details_encrypted.decode('utf-8')),
                current_user.private_key
            )
            
            form.illness_name.data = illness_name
            form.diagnosis_date.data = datetime.strptime(diagnosis_date, '%Y-%m-%d').date()
            form.treatment_details.data = details
        except Exception as e:
            logger.error(f"Error decrypting illness {illness_id} for edit: {str(e)}")
            flash('Error loading illness record for editing', 'danger')
            return redirect(url_for('medical_history.manage_medical_history'))
    
    return render_template('medical_history/edit.html', 
                           title='Edit Past Illness', 
                           form=form,
                           illness=illness)

@bp.route('/edit/surgery/<int:surgery_id>', methods=['GET', 'POST'])
@login_required
def edit_surgery(surgery_id):
    surgery = Surgery.query.get_or_404(surgery_id)
    if surgery.user_id != current_user.id:
        flash('You can only edit your own surgery records', 'danger')
        return redirect(url_for('medical_history.manage_medical_history'))
    
    form = SurgeryForm()
    
    if form.validate_on_submit():
        try:
            # Encrypt each field using the CryptoManager
            encrypted_surgery_name = json.dumps(
                CryptoManager.encrypt_data(
                    form.surgery_name.data, 
                    current_user.public_key
                )
            ).encode('utf-8')
            
            encrypted_surgery_date = json.dumps(
                CryptoManager.encrypt_data(
                    str(form.surgery_date.data), 
                    current_user.public_key
                )
            ).encode('utf-8')
            
            # Combine surgeon, hospital, and details into a single details field
            details_dict = {
                'surgeon': form.surgeon.data,
                'hospital': form.hospital.data,
                'details': form.details.data
            }
            
            encrypted_details = json.dumps(
                CryptoManager.encrypt_data(
                    json.dumps(details_dict), 
                    current_user.public_key
                )
            ).encode('utf-8')

            # Update the surgery record
            surgery.surgery_name_encrypted = encrypted_surgery_name
            surgery.surgery_date_encrypted = encrypted_surgery_date
            surgery.details_encrypted = encrypted_details
            
            db.session.commit()
            flash('Surgery record updated successfully', 'success')
            return redirect(url_for('medical_history.manage_medical_history'))
            
        except Exception as e:
            logger.error(f"Error updating surgery {surgery_id}: {str(e)}")
            flash('Error updating surgery record', 'danger')
            return redirect(url_for('medical_history.manage_medical_history'))
    
    # Populate form with current data
    if request.method == 'GET':
        try:
            surgery_name = CryptoManager.decrypt_data(
                json.loads(surgery.surgery_name_encrypted.decode('utf-8')),
                current_user.private_key
            )
            surgery_date = CryptoManager.decrypt_data(
                json.loads(surgery.surgery_date_encrypted.decode('utf-8')),
                current_user.private_key
            )
            
            # Decrypt the details field and extract surgeon, hospital, and details
            details = CryptoManager.decrypt_data(
                json.loads(surgery.details_encrypted.decode('utf-8')),
                current_user.private_key
            )
            details_dict = json.loads(details)
            
            form.surgery_name.data = surgery_name
            form.surgery_date.data = datetime.strptime(surgery_date, '%Y-%m-%d').date()
            form.surgeon.data = details_dict.get('surgeon', '')
            form.hospital.data = details_dict.get('hospital', '')
            form.details.data = details_dict.get('details', '')
        except Exception as e:
            logger.error(f"Error decrypting surgery {surgery_id} for edit: {str(e)}")
            flash('Error loading surgery record for editing', 'danger')
            return redirect(url_for('medical_history.manage_medical_history'))
    
    return render_template('medical_history/edit.html', 
                           title='Edit Surgery', 
                           form=form,
                           surgery=surgery)
