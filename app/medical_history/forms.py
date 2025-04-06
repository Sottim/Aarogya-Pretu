from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, DateField, SubmitField
from wtforms.validators import DataRequired, Length, Optional

class PastIllnessForm(FlaskForm):
    illness_name = StringField('Illness Name', validators=[DataRequired(), Length(max=100)])
    diagnosis_date = DateField('Date of Diagnosis', format='%Y-%m-%d', validators=[Optional()])
    treatment_details = TextAreaField('Treatment Details / Notes', validators=[Length(max=500)])
    submit = SubmitField('Add Illness')

# Add other forms here later (SurgeryForm, AllergyForm, etc.)
