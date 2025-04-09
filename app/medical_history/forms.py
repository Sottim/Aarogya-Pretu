from flask_wtf import FlaskForm
from wtforms import StringField, DateField, TextAreaField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Optional

class PastIllnessForm(FlaskForm):
    illness_name = StringField('Illness Name', validators=[DataRequired(), Length(max=100)])
    diagnosis_date = DateField('Date of Diagnosis', format='%Y-%m-%d', validators=[Optional()])
    treatment_details = TextAreaField('Treatment Details / Notes', validators=[Length(max=500)])
    submit = SubmitField('Add Illness')

class SurgeryForm(FlaskForm):
    surgery_name = StringField('Surgery Name', validators=[DataRequired()])
    surgery_date = DateField('Date of Surgery', validators=[DataRequired()])
    surgeon = StringField('Surgeon Name', validators=[DataRequired()])
    hospital = StringField('Hospital', validators=[DataRequired()])
    details = TextAreaField('Additional Details')
    submit = SubmitField('Save Surgery')

class AllergyForm(FlaskForm):
    allergen = StringField('Allergen', validators=[DataRequired()])
    severity = StringField('Severity', validators=[DataRequired()])
    reaction_details = TextAreaField('Reaction Details')
    submit = SubmitField('Save Allergy')

class MedicationForm(FlaskForm):
    medication_name = StringField('Medication Name', validators=[DataRequired()])
    dosage = StringField('Dosage', validators=[DataRequired()])
    frequency = StringField('Frequency', validators=[DataRequired()])
    start_date = DateField('Start Date', validators=[DataRequired()])
    end_date = DateField('End Date', validators=[Optional()])
    reason = TextAreaField('Reason for Medication', validators=[Length(max=500)])
    is_current = BooleanField('Is Current Medication', default=True)
    submit = SubmitField('Save Medication')

# Add other forms here later
