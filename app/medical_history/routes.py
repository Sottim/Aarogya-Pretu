from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app import db
from app.models import PastIllness, Surgery, Allergy, Medication # Add other models later
from app.medical_history import bp
from app.medical_history.forms import PastIllnessForm, SurgeryForm, AllergyForm, MedicationForm # Add other forms later
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
    allergy_form = AllergyForm()
    medication_form = MedicationForm()
    
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

    if allergy_form.validate_on_submit():
        try:
            # Encrypt each field using the CryptoManager
            encrypted_allergen = json.dumps(
                CryptoManager.encrypt_data(
                    allergy_form.allergen.data, 
                    current_user.public_key
                )
            ).encode('utf-8')
            
            encrypted_severity = json.dumps(
                CryptoManager.encrypt_data(
                    allergy_form.severity.data, 
                    current_user.public_key
                )
            ).encode('utf-8')
            
            encrypted_reaction_details = json.dumps(
                CryptoManager.encrypt_data(
                    allergy_form.reaction_details.data, 
                    current_user.public_key
                )
            ).encode('utf-8')

            # Create new Allergy record with encrypted data
            allergy = Allergy(
                user_id=current_user.id,
                allergen_encrypted=encrypted_allergen,
                severity_encrypted=encrypted_severity,
                reaction_details_encrypted=encrypted_reaction_details
            )
            
            db.session.add(allergy)
            db.session.commit()
            flash('Allergy record added successfully', 'success')
            return redirect(url_for('medical_history.manage_medical_history'))
            
        except Exception as e:
            logger.error(f"Error encrypting allergy data: {str(e)}")
            flash('Error saving allergy record', 'danger')
            return redirect(url_for('medical_history.manage_medical_history'))

    if medication_form.validate_on_submit():
        try:
            # Encrypt each field using the CryptoManager
            encrypted_medication_name = json.dumps(
                CryptoManager.encrypt_data(
                    medication_form.medication_name.data, 
                    current_user.public_key
                )
            ).encode('utf-8')
            
            encrypted_dosage = json.dumps(
                CryptoManager.encrypt_data(
                    medication_form.dosage.data, 
                    current_user.public_key
                )
            ).encode('utf-8')
            
            encrypted_frequency = json.dumps(
                CryptoManager.encrypt_data(
                    medication_form.frequency.data, 
                    current_user.public_key
                )
            ).encode('utf-8')
            
            encrypted_start_date = json.dumps(
                CryptoManager.encrypt_data(
                    str(medication_form.start_date.data), 
                    current_user.public_key
                )
            ).encode('utf-8')
            
            encrypted_end_date = json.dumps(
                CryptoManager.encrypt_data(
                    str(medication_form.end_date.data) if medication_form.end_date.data else '', 
                    current_user.public_key
                )
            ).encode('utf-8')
            
            encrypted_reason = json.dumps(
                CryptoManager.encrypt_data(
                    medication_form.reason.data, 
                    current_user.public_key
                )
            ).encode('utf-8')

            # Create new Medication record with encrypted data
            medication = Medication(
                user_id=current_user.id,
                medication_name_encrypted=encrypted_medication_name,
                dosage_encrypted=encrypted_dosage,
                frequency_encrypted=encrypted_frequency,
                start_date_encrypted=encrypted_start_date,
                end_date_encrypted=encrypted_end_date,
                reason_encrypted=encrypted_reason,
                is_current=medication_form.is_current.data
            )
            
            db.session.add(medication)
            db.session.commit()
            flash('Medication record added successfully', 'success')
            return redirect(url_for('medical_history.manage_medical_history'))
            
        except Exception as e:
            logger.error(f"Error encrypting medication data: {str(e)}")
            flash('Error saving medication record', 'danger')
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

    # Get and decrypt allergies for display
    allergies_query = Allergy.query.filter_by(user_id=current_user.id).all()
    decrypted_allergies = []
    
    for allergy in allergies_query:
        try:
            allergen = CryptoManager.decrypt_data(
                json.loads(allergy.allergen_encrypted.decode('utf-8')),
                current_user.private_key
            )
            severity = CryptoManager.decrypt_data(
                json.loads(allergy.severity_encrypted.decode('utf-8')),
                current_user.private_key
            )
            reaction_details = CryptoManager.decrypt_data(
                json.loads(allergy.reaction_details_encrypted.decode('utf-8')),
                current_user.private_key
            )
            
            decrypted_allergies.append({
                'id': allergy.id,
                'allergen': allergen,
                'severity': severity,
                'reaction_details': reaction_details
            })
        except Exception as e:
            logger.error(f"Error decrypting allergy {allergy.id}: {str(e)}")
            flash(f'Error decrypting allergy record', 'danger')

    # Get and decrypt medications for display
    medications_query = Medication.query.filter_by(user_id=current_user.id).all()
    decrypted_medications = []
    
    for medication in medications_query:
        try:
            medication_name = CryptoManager.decrypt_data(
                json.loads(medication.medication_name_encrypted.decode('utf-8')),
                current_user.private_key
            )
            dosage = CryptoManager.decrypt_data(
                json.loads(medication.dosage_encrypted.decode('utf-8')),
                current_user.private_key
            )
            frequency = CryptoManager.decrypt_data(
                json.loads(medication.frequency_encrypted.decode('utf-8')),
                current_user.private_key
            )
            start_date = CryptoManager.decrypt_data(
                json.loads(medication.start_date_encrypted.decode('utf-8')),
                current_user.private_key
            )
            end_date = CryptoManager.decrypt_data(
                json.loads(medication.end_date_encrypted.decode('utf-8')),
                current_user.private_key
            )
            reason = CryptoManager.decrypt_data(
                json.loads(medication.reason_encrypted.decode('utf-8')),
                current_user.private_key
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
        except Exception as e:
            logger.error(f"Error decrypting medication {medication.id}: {str(e)}")
            flash(f'Error decrypting medication record', 'danger')

    return render_template('medical_history/manage.html', 
                           title='Manage Medical History', 
                           illness_form=illness_form,
                           surgery_form=surgery_form,
                           allergy_form=allergy_form,
                           medication_form=medication_form,
                           illnesses=decrypted_illnesses,
                           surgeries=decrypted_surgeries,
                           allergies=decrypted_allergies,
                           medications=decrypted_medications)

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

@bp.route('/delete/allergy/<int:allergy_id>', methods=['POST'])
@login_required
def delete_allergy(allergy_id):
    allergy = Allergy.query.get_or_404(allergy_id)
    if allergy.user_id != current_user.id:
        flash('You can only delete your own allergy records', 'danger')
        return redirect(url_for('medical_history.manage_medical_history'))
    
    try:
        db.session.delete(allergy)
        db.session.commit()
        flash('Allergy record deleted successfully', 'success')
    except Exception as e:
        logger.error(f"Error deleting allergy {allergy_id}: {str(e)}")
        flash('Error deleting allergy record', 'danger')
    
    return redirect(url_for('medical_history.manage_medical_history'))

@bp.route('/delete/medication/<int:medication_id>', methods=['POST'])
@login_required
def delete_medication(medication_id):
    medication = Medication.query.get_or_404(medication_id)
    if medication.user_id != current_user.id:
        flash('You can only delete your own medication records', 'danger')
        return redirect(url_for('medical_history.manage_medical_history'))
    
    try:
        db.session.delete(medication)
        db.session.commit()
        flash('Medication record deleted successfully', 'success')
    except Exception as e:
        logger.error(f"Error deleting medication {medication_id}: {str(e)}")
        flash('Error deleting medication record', 'danger')
    
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

@bp.route('/edit/allergy/<int:allergy_id>', methods=['GET', 'POST'])
@login_required
def edit_allergy(allergy_id):
    allergy = Allergy.query.get_or_404(allergy_id)
    if allergy.user_id != current_user.id:
        flash('You can only edit your own allergy records', 'danger')
        return redirect(url_for('medical_history.manage_medical_history'))
    
    form = AllergyForm()
    
    if form.validate_on_submit():
        try:
            # Encrypt each field using the CryptoManager
            encrypted_allergen = json.dumps(
                CryptoManager.encrypt_data(
                    form.allergen.data, 
                    current_user.public_key
                )
            ).encode('utf-8')
            
            encrypted_severity = json.dumps(
                CryptoManager.encrypt_data(
                    form.severity.data, 
                    current_user.public_key
                )
            ).encode('utf-8')
            
            encrypted_reaction_details = json.dumps(
                CryptoManager.encrypt_data(
                    form.reaction_details.data, 
                    current_user.public_key
                )
            ).encode('utf-8')

            # Update the allergy record
            allergy.allergen_encrypted = encrypted_allergen
            allergy.severity_encrypted = encrypted_severity
            allergy.reaction_details_encrypted = encrypted_reaction_details
            
            db.session.commit()
            flash('Allergy record updated successfully', 'success')
            return redirect(url_for('medical_history.manage_medical_history'))
            
        except Exception as e:
            logger.error(f"Error updating allergy {allergy_id}: {str(e)}")
            flash('Error updating allergy record', 'danger')
            return redirect(url_for('medical_history.manage_medical_history'))
    
    # Populate form with current data
    if request.method == 'GET':
        try:
            allergen = CryptoManager.decrypt_data(
                json.loads(allergy.allergen_encrypted.decode('utf-8')),
                current_user.private_key
            )
            severity = CryptoManager.decrypt_data(
                json.loads(allergy.severity_encrypted.decode('utf-8')),
                current_user.private_key
            )
            reaction_details = CryptoManager.decrypt_data(
                json.loads(allergy.reaction_details_encrypted.decode('utf-8')),
                current_user.private_key
            )
            
            form.allergen.data = allergen
            form.severity.data = severity
            form.reaction_details.data = reaction_details
        except Exception as e:
            logger.error(f"Error decrypting allergy {allergy_id} for edit: {str(e)}")
            flash('Error loading allergy record for editing', 'danger')
            return redirect(url_for('medical_history.manage_medical_history'))
    
    return render_template('medical_history/edit.html', 
                           title='Edit Allergy', 
                           form=form,
                           allergy=allergy)

@bp.route('/edit/medication/<int:medication_id>', methods=['GET', 'POST'])
@login_required
def edit_medication(medication_id):
    medication = Medication.query.get_or_404(medication_id)
    if medication.user_id != current_user.id:
        flash('You can only edit your own medication records', 'danger')
        return redirect(url_for('medical_history.manage_medical_history'))
    
    form = MedicationForm()
    
    if form.validate_on_submit():
        try:
            # Encrypt each field using the CryptoManager
            encrypted_medication_name = json.dumps(
                CryptoManager.encrypt_data(
                    form.medication_name.data, 
                    current_user.public_key
                )
            ).encode('utf-8')
            
            encrypted_dosage = json.dumps(
                CryptoManager.encrypt_data(
                    form.dosage.data, 
                    current_user.public_key
                )
            ).encode('utf-8')
            
            encrypted_frequency = json.dumps(
                CryptoManager.encrypt_data(
                    form.frequency.data, 
                    current_user.public_key
                )
            ).encode('utf-8')
            
            encrypted_start_date = json.dumps(
                CryptoManager.encrypt_data(
                    str(form.start_date.data), 
                    current_user.public_key
                )
            ).encode('utf-8')
            
            encrypted_end_date = json.dumps(
                CryptoManager.encrypt_data(
                    str(form.end_date.data) if form.end_date.data else '', 
                    current_user.public_key
                )
            ).encode('utf-8')
            
            encrypted_reason = json.dumps(
                CryptoManager.encrypt_data(
                    form.reason.data, 
                    current_user.public_key
                )
            ).encode('utf-8')

            # Update the medication record
            medication.medication_name_encrypted = encrypted_medication_name
            medication.dosage_encrypted = encrypted_dosage
            medication.frequency_encrypted = encrypted_frequency
            medication.start_date_encrypted = encrypted_start_date
            medication.end_date_encrypted = encrypted_end_date
            medication.reason_encrypted = encrypted_reason
            medication.is_current = form.is_current.data
            
            db.session.commit()
            flash('Medication record updated successfully', 'success')
            return redirect(url_for('medical_history.manage_medical_history'))
            
        except Exception as e:
            logger.error(f"Error updating medication {medication_id}: {str(e)}")
            flash('Error updating medication record', 'danger')
            return redirect(url_for('medical_history.manage_medical_history'))
    
    # Populate form with current data
    if request.method == 'GET':
        try:
            medication_name = CryptoManager.decrypt_data(
                json.loads(medication.medication_name_encrypted.decode('utf-8')),
                current_user.private_key
            )
            dosage = CryptoManager.decrypt_data(
                json.loads(medication.dosage_encrypted.decode('utf-8')),
                current_user.private_key
            )
            frequency = CryptoManager.decrypt_data(
                json.loads(medication.frequency_encrypted.decode('utf-8')),
                current_user.private_key
            )
            start_date = CryptoManager.decrypt_data(
                json.loads(medication.start_date_encrypted.decode('utf-8')),
                current_user.private_key
            )
            end_date = CryptoManager.decrypt_data(
                json.loads(medication.end_date_encrypted.decode('utf-8')),
                current_user.private_key
            )
            reason = CryptoManager.decrypt_data(
                json.loads(medication.reason_encrypted.decode('utf-8')),
                current_user.private_key
            )
            
            form.medication_name.data = medication_name
            form.dosage.data = dosage
            form.frequency.data = frequency
            form.start_date.data = datetime.strptime(start_date, '%Y-%m-%d').date() if start_date else None
            form.end_date.data = datetime.strptime(end_date, '%Y-%m-%d').date() if end_date else None
            form.reason.data = reason
            form.is_current.data = medication.is_current
        except Exception as e:
            logger.error(f"Error decrypting medication {medication_id} for edit: {str(e)}")
            flash('Error loading medication record for editing', 'danger')
            return redirect(url_for('medical_history.manage_medical_history'))
    
    return render_template('medical_history/edit.html', 
                           title='Edit Medication', 
                           form=form,
                           medication=medication)
