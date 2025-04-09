from flask_wtf import FlaskForm
from wtforms import StringField, DateField, TextAreaField, SubmitField
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

# Add other forms here later (AllergyForm, etc.)
