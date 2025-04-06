from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app import db
from app.models import PastIllness # Add other models later
from app.medical_history import bp
from app.medical_history.forms import PastIllnessForm # Add other forms later
# Import encryption/decryption utilities (we'll create these)
# from app.utils import encrypt_data, decrypt_data 

@bp.route('/manage', methods=['GET', 'POST']) # Combined route for now
@login_required
def manage_medical_history():
    # For now, just handle Past Illnesses
    illness_form = PastIllnessForm()
    
    if illness_form.validate_on_submit():
        # TODO: Implement encryption
        # For now, store raw data directly into encrypted fields as placeholders
        # actual_encrypted_illness_name = encrypt_data(illness_form.illness_name.data, current_user.public_key)
        # actual_encrypted_diagnosis_date = encrypt_data(str(illness_form.diagnosis_date.data), current_user.public_key) # Dates need conversion
        # actual_encrypted_details = encrypt_data(illness_form.treatment_details.data, current_user.public_key)

        new_illness = PastIllness(
            user_id=current_user.id,
            # Use the correct model field names
            illness_name_encrypted=illness_form.illness_name.data.encode(), # Store raw data for now (encode to bytes)
            diagnosis_date_encrypted=str(illness_form.diagnosis_date.data).encode(), # Store raw data for now (encode to bytes)
            details_encrypted=illness_form.treatment_details.data.encode() # Map form field to model field (encode to bytes)
        )
        db.session.add(new_illness)
        db.session.commit()
        flash('Past illness added successfully.', 'success')
        return redirect(url_for('medical_history.manage_medical_history'))
        
    # TODO: Query and decrypt existing data to display
    # illnesses = PastIllness.query.filter_by(user_id=current_user.id).all()
    # decrypted_illnesses = []
    # for illness in illnesses:
    #     decrypted_illnesses.append({
    #         'illness_name': decrypt_data(illness.illness_name, current_user.private_key), # Need private key access
    #         'diagnosis_date': illness.diagnosis_date,
    #         'treatment_details': decrypt_data(illness.treatment_details, current_user.private_key)
    #     })

    # Placeholder for displaying data
    illnesses = PastIllness.query.filter_by(user_id=current_user.id).all()

    return render_template('medical_history/manage.html', 
                           title='Manage Medical History', 
                           illness_form=illness_form,
                           illnesses=illnesses) # Pass decrypted data later
