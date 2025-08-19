from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, TextAreaField, SelectField, 
    DateField, BooleanField, FieldList, FormField, HiddenField,
    EmailField, TelField, SubmitField
)
from wtforms.validators import (
    DataRequired, Length, Email, Optional, ValidationError,
    EqualTo, Regexp
)
from datetime import datetime, date
import json

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=255)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class MinistryRegistrationForm(FlaskForm):
    name = StringField('Ministry Name', validators=[DataRequired(), Length(min=3, max=255)])
    admin_username = StringField('Admin Username', validators=[
        DataRequired(), 
        Length(min=3, max=255),
        Regexp(r'^[a-zA-Z0-9_]+$', message="Username can only contain letters, numbers, and underscores")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(), 
        Length(min=8, message="Password must be at least 8 characters long")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    contact_phone = TelField('Contact Phone', validators=[Optional()])
    contact_email = EmailField('Contact Email', validators=[Optional(), Email()])
    address = TextAreaField('Address', validators=[Optional()])
    submit = SubmitField('Register Ministry')

class HospitalForm(FlaskForm):
    name = StringField('Hospital Name', validators=[DataRequired(), Length(min=3, max=255)])
    code = StringField('Hospital Code', validators=[
        Optional(), 
        Length(max=100),
        Regexp(r'^[A-Z0-9_-]*$', message="Code can only contain uppercase letters, numbers, hyphens, and underscores")
    ])
    address = TextAreaField('Address', validators=[Optional()])
    city = StringField('City', validators=[Optional(), Length(max=100)])
    province = StringField('Province', validators=[Optional(), Length(max=100)])
    postal_code = StringField('Postal Code', validators=[Optional(), Length(max=20)])
    contact_phone = TelField('Contact Phone', validators=[Optional()])
    contact_email = EmailField('Contact Email', validators=[Optional(), Email()])
    emergency_contact = TelField('Emergency Contact', validators=[Optional()])
    submit = SubmitField('Save Hospital')

    def validate_code(self, field):
        if field.data:
            # Import here to avoid circular imports
            from models import Hospital
            existing = Hospital.query.filter_by(code=field.data).first()
            if existing and (not hasattr(self, 'hospital_id') or existing.id != getattr(self, 'hospital_id', None)):
                raise ValidationError('Hospital code already exists')

class HospitalAdminForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(), 
        Length(min=3, max=255),
        Regexp(r'^[a-zA-Z0-9_]+$', message="Username can only contain letters, numbers, and underscores")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(), 
        Length(min=8, message="Password must be at least 8 characters long")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    full_name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=255)])
    email = EmailField('Email', validators=[Optional(), Email()])
    is_active = BooleanField('Active', default=True)
    submit = SubmitField('Save Admin')

    def __init__(self, hospital_id=None, admin_id=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.hospital_id = hospital_id
        self.admin_id = admin_id

    def validate_username(self, field):
        from models import HospitalAdmin
        existing = HospitalAdmin.query.filter_by(
            hospital_id=self.hospital_id, 
            username=field.data
        ).first()
        if existing and existing.id != self.admin_id:
            raise ValidationError('Username already exists in this hospital')

class PatientForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=255)])
    date_of_birth = DateField('Date of Birth', validators=[Optional()])
    gender = SelectField('Gender', choices=[
        ('', 'Select Gender'),
        ('male', 'Male'),
        ('female', 'Female'),
        ('other', 'Other'),
        ('prefer_not_to_say', 'Prefer not to say')
    ], validators=[Optional()])
    
    # Address fields
    address_line1 = StringField('Address Line 1', validators=[Optional(), Length(max=255)])
    address_line2 = StringField('Address Line 2', validators=[Optional(), Length(max=255)])
    city = StringField('City', validators=[Optional(), Length(max=100)])
    province = StringField('Province', validators=[Optional(), Length(max=100)])
    postal_code = StringField('Postal Code', validators=[Optional(), Length(max=20)])
    country = StringField('Country', validators=[Optional(), Length(max=100)], default='Sri Lanka')
    
    # Contact info
    phone_primary = TelField('Primary Phone', validators=[Optional()])
    phone_secondary = TelField('Secondary Phone', validators=[Optional()])
    email = EmailField('Email', validators=[Optional(), Email()])
    
    # Medical info
    blood_type = SelectField('Blood Type', choices=[
        ('', 'Select Blood Type'),
        ('A+', 'A+'), ('A-', 'A-'),
        ('B+', 'B+'), ('B-', 'B-'),
        ('AB+', 'AB+'), ('AB-', 'AB-'),
        ('O+', 'O+'), ('O-', 'O-')
    ], validators=[Optional()])
    
    guardian_number = StringField('Guardian/Emergency Contact', validators=[Optional(), Length(max=100)])
    
    submit = SubmitField('Save Patient')

    def validate_date_of_birth(self, field):
        if field.data and field.data > date.today():
            raise ValidationError('Date of birth cannot be in the future')

class PatientIdentifierForm(FlaskForm):
    id_type = SelectField('ID Type', choices=[
        ('', 'Select ID Type'),
        ('nic', 'National Identity Card'),
        ('passport', 'Passport'),
        ('driving_license', 'Driving License'),
        ('birth_certificate', 'Birth Certificate'),
        ('other', 'Other')
    ], validators=[DataRequired()])
    id_value = StringField('ID Number', validators=[DataRequired(), Length(min=1, max=255)])
    issued_country = StringField('Issued Country', validators=[Optional(), Length(max=100)], default='Sri Lanka')
    submit = SubmitField('Add Identifier')

class DoctorForm(FlaskForm):
    license_no = StringField('License Number', validators=[DataRequired(), Length(min=3, max=255)])
    password = PasswordField('Password', validators=[
        DataRequired(), 
        Length(min=8, message="Password must be at least 8 characters long")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    full_name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=255)])
    nic = StringField('NIC Number', validators=[Optional(), Length(max=255)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    
    # Contact info
    phone_primary = TelField('Primary Phone', validators=[Optional()])
    phone_secondary = TelField('Secondary Phone', validators=[Optional()])
    
    # Specialties
    specialty_1 = StringField('Primary Specialty', validators=[Optional(), Length(max=100)])
    specialty_2 = StringField('Secondary Specialty', validators=[Optional(), Length(max=100)])
    specialty_3 = StringField('Additional Specialty', validators=[Optional(), Length(max=100)])
    
    is_active = BooleanField('Active', default=True)
    submit = SubmitField('Save Doctor')

    def __init__(self, doctor_id=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.doctor_id = doctor_id

    def validate_license_no(self, field):
        from models import Doctor
        existing = Doctor.query.filter_by(license_no=field.data).first()
        if existing and existing.id != self.doctor_id:
            raise ValidationError('License number already exists')

    def validate_email(self, field):
        from models import Doctor
        existing = Doctor.query.filter_by(email=field.data).first()
        if existing and existing.id != self.doctor_id:
            raise ValidationError('Email already registered')

class MedicalEncounterForm(FlaskForm):
    receipt_number = StringField('Receipt Number', validators=[Optional(), Length(max=255)])
    patient_id = HiddenField('Patient ID', validators=[DataRequired()])
    
    diagnosis_text = TextAreaField('Diagnosis', validators=[DataRequired()], 
                                 render_kw={"rows": 4, "placeholder": "Enter detailed diagnosis..."})
    diagnosis_code = StringField('Diagnosis Code (ICD-10)', validators=[Optional(), Length(max=100)])
    
    # Medicine fields - we'll handle this as a JSON field but provide individual inputs
    medicine_1_name = StringField('Medicine 1 - Name', validators=[Optional(), Length(max=200)])
    medicine_1_dosage = StringField('Medicine 1 - Dosage', validators=[Optional(), Length(max=100)])
    medicine_1_frequency = StringField('Medicine 1 - Frequency', validators=[Optional(), Length(max=100)])
    medicine_1_duration = StringField('Medicine 1 - Duration', validators=[Optional(), Length(max=100)])
    
    medicine_2_name = StringField('Medicine 2 - Name', validators=[Optional(), Length(max=200)])
    medicine_2_dosage = StringField('Medicine 2 - Dosage', validators=[Optional(), Length(max=100)])
    medicine_2_frequency = StringField('Medicine 2 - Frequency', validators=[Optional(), Length(max=100)])
    medicine_2_duration = StringField('Medicine 2 - Duration', validators=[Optional(), Length(max=100)])
    
    medicine_3_name = StringField('Medicine 3 - Name', validators=[Optional(), Length(max=200)])
    medicine_3_dosage = StringField('Medicine 3 - Dosage', validators=[Optional(), Length(max=100)])
    medicine_3_frequency = StringField('Medicine 3 - Frequency', validators=[Optional(), Length(max=100)])
    medicine_3_duration = StringField('Medicine 3 - Duration', validators=[Optional(), Length(max=100)])
    
    suggestions = TextAreaField('Treatment Suggestions', validators=[Optional()],
                              render_kw={"rows": 3, "placeholder": "Additional treatment suggestions..."})
    treatment_date = DateField('Treatment Date', validators=[DataRequired()], default=date.today)
    
    submit = SubmitField('Save Encounter')

    def validate_treatment_date(self, field):
        if field.data and field.data > date.today():
            raise ValidationError('Treatment date cannot be in the future')

    def get_medicines_json(self):
        """Convert medicine fields to JSON format for storage"""
        medicines = []
        for i in range(1, 4):  # medicine_1, medicine_2, medicine_3
            name = getattr(self, f'medicine_{i}_name').data
            if name and name.strip():
                medicine = {
                    'name': name.strip(),
                    'dosage': getattr(self, f'medicine_{i}_dosage').data or '',
                    'frequency': getattr(self, f'medicine_{i}_frequency').data or '',
                    'duration': getattr(self, f'medicine_{i}_duration').data or ''
                }
                medicines.append(medicine)
        return medicines

    def populate_medicine_fields(self, medicines_json):
        """Populate medicine fields from JSON data"""
        if medicines_json:
            medicines = medicines_json if isinstance(medicines_json, list) else []
            for i, medicine in enumerate(medicines[:3], 1):  # Only handle first 3 medicines
                getattr(self, f'medicine_{i}_name').data = medicine.get('name', '')
                getattr(self, f'medicine_{i}_dosage').data = medicine.get('dosage', '')
                getattr(self, f'medicine_{i}_frequency').data = medicine.get('frequency', '')
                getattr(self, f'medicine_{i}_duration').data = medicine.get('duration', '')

class PatientSearchForm(FlaskForm):
    search_term = StringField('Search', validators=[Optional()], 
                            render_kw={"placeholder": "Search by name, phone, email, or ID..."})
    search_type = SelectField('Search By', choices=[
        ('all', 'All Fields'),
        ('name', 'Name'),
        ('phone', 'Phone'),
        ('email', 'Email'),
        ('identifier', 'ID Number')
    ], default='all')
    submit = SubmitField('Search')

class QRTokenForm(FlaskForm):
    patient_id = HiddenField('Patient ID', validators=[DataRequired()])
    purpose = SelectField('Purpose', choices=[
        ('public_emergency', 'Public Emergency Access'),
        ('hospital_transfer', 'Hospital Transfer'),
        ('specialist_referral', 'Specialist Referral'),
        ('family_access', 'Family Access')
    ], default='public_emergency', validators=[DataRequired()])
    expires_in_days = SelectField('Expires In', choices=[
        ('1', '1 Day'),
        ('7', '1 Week'),
        ('30', '1 Month'),
        ('90', '3 Months'),
        ('365', '1 Year'),
        ('', 'Never (Permanent)')
    ], default='30')
    submit = SubmitField('Generate QR Token')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[
        DataRequired(), 
        Length(min=8, message="Password must be at least 8 characters long")
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(),
        EqualTo('new_password', message='Passwords must match')
    ])
    submit = SubmitField('Change Password')

class ProfileUpdateForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=255)])
    email = EmailField('Email', validators=[Optional(), Email()])
    phone_primary = TelField('Primary Phone', validators=[Optional()])
    phone_secondary = TelField('Secondary Phone', validators=[Optional()])
    submit = SubmitField('Update Profile')

class MedicalRecordSearchForm(FlaskForm):
    patient_name = StringField('Patient Name', validators=[Optional()])
    doctor_name = StringField('Doctor Name', validators=[Optional()])
    diagnosis_keyword = StringField('Diagnosis Keyword', validators=[Optional()])
    date_from = DateField('From Date', validators=[Optional()])
    date_to = DateField('To Date', validators=[Optional()])
    submit = SubmitField('Search Records')

    def validate_date_range(self):
        if self.date_from.data and self.date_to.data:
            if self.date_from.data > self.date_to.data:
                self.date_to.errors.append('End date must be after start date')
                return False
        return True

class BulkPatientUploadForm(FlaskForm):
    csv_file = StringField('CSV File Path', validators=[DataRequired()],
                          render_kw={"placeholder": "Path to CSV file with patient data"})
    submit = SubmitField('Upload Patients')

# Utility functions for form data processing

def json_to_contact_info(phone_primary=None, phone_secondary=None, email=None, **kwargs):
    """Convert contact form fields to JSON format"""
    contact_info = {}
    if phone_primary:
        contact_info['phone_primary'] = phone_primary
    if phone_secondary:
        contact_info['phone_secondary'] = phone_secondary
    if email:
        contact_info['email'] = email
    
    # Add any additional contact fields
    for key, value in kwargs.items():
        if value and key.startswith('contact_'):
            contact_info[key] = value
    
    return contact_info if contact_info else None

def json_to_address(address_line1=None, address_line2=None, city=None, 
                   province=None, postal_code=None, country=None, **kwargs):
    """Convert address form fields to JSON format"""
    address = {}
    if address_line1:
        address['line1'] = address_line1
    if address_line2:
        address['line2'] = address_line2
    if city:
        address['city'] = city
    if province:
        address['province'] = province
    if postal_code:
        address['postal_code'] = postal_code
    if country:
        address['country'] = country
    
    # Add any additional address fields
    for key, value in kwargs.items():
        if value and key.startswith('address_'):
            address[key.replace('address_', '')] = value
    
    return address if address else None

def contact_info_to_form_data(contact_json):
    """Extract contact info from JSON for form population"""
    if not contact_json:
        return {}
    
    contact_data = contact_json if isinstance(contact_json, dict) else {}
    return {
        'phone_primary': contact_data.get('phone_primary', ''),
        'phone_secondary': contact_data.get('phone_secondary', ''),
        'email': contact_data.get('email', ''),
        'emergency_contact': contact_data.get('emergency_contact', '')
    }

def address_to_form_data(address_json):
    """Extract address info from JSON for form population"""
    if not address_json:
        return {}
    
    address_data = address_json if isinstance(address_json, dict) else {}
    return {
        'address_line1': address_data.get('line1', ''),
        'address_line2': address_data.get('line2', ''),
        'city': address_data.get('city', ''),
        'province': address_data.get('province', ''),
        'postal_code': address_data.get('postal_code', ''),
        'country': address_data.get('country', 'Sri Lanka')
    }

def specialties_to_form_data(specialties_json):
    """Extract specialties from JSON for form population"""
    if not specialties_json:
        return {'specialty_1': '', 'specialty_2': '', 'specialty_3': ''}
    
    specialties = specialties_json if isinstance(specialties_json, list) else []
    return {
        'specialty_1': specialties[0] if len(specialties) > 0 else '',
        'specialty_2': specialties[1] if len(specialties) > 1 else '',
        'specialty_3': specialties[2] if len(specialties) > 2 else ''
    }

def form_data_to_specialties(specialty_1=None, specialty_2=None, specialty_3=None):
    """Convert specialty form fields to JSON list"""
    specialties = []
    for specialty in [specialty_1, specialty_2, specialty_3]:
        if specialty and specialty.strip():
            specialties.append(specialty.strip())
    return specialties if specialties else None