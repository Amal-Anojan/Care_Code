from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date
import json

db = SQLAlchemy()


class Ministry(db.Model):
    __tablename__ = 'ministries'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    admin_username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    contact_info = db.Column(db.JSON)  # {phone, email, address}
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    hospitals = db.relationship('Hospital', backref='ministry', lazy=True)
    
    def __repr__(self):
        return f'<Ministry {self.name}>'


class Hospital(db.Model):
    __tablename__ = 'hospitals'
    
    id = db.Column(db.Integer, primary_key=True)
    ministry_id = db.Column(db.Integer, db.ForeignKey('ministries.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    code = db.Column(db.String(50), unique=True)
    location = db.Column(db.JSON)  # {address_line1, city, province, postal_code}
    contact_info = db.Column(db.JSON)  # {phone_primary, email, emergency_contact}
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    hospital_admins = db.relationship('HospitalAdmin', backref='hospital', lazy=True)
    doctors = db.relationship('Doctor', backref='hospital', lazy=True)
    patients_created = db.relationship('Patient', backref='created_hospital', 
                                     foreign_keys='Patient.created_by_hospital', lazy=True)
    medical_encounters = db.relationship('MedicalEncounter', backref='hospital', lazy=True)
    qr_tokens = db.relationship('QRToken', backref='hospital', lazy=True)
    patient_hospitals = db.relationship('PatientHospital', backref='hospital', lazy=True)
    
    def __repr__(self):
        return f'<Hospital {self.name}>'


class HospitalAdmin(db.Model):
    __tablename__ = 'hospital_admins'
    
    id = db.Column(db.Integer, primary_key=True)
    hospital_id = db.Column(db.Integer, db.ForeignKey('hospitals.id'), nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    contact_info = db.Column(db.JSON)  # {phone_primary, phone_secondary}
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<HospitalAdmin {self.full_name}>'


class Patient(db.Model):
    __tablename__ = 'patients'
    
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(255), nullable=False)
    date_of_birth = db.Column(db.Date)
    gender = db.Column(db.String(20))  # male, female, other
    address = db.Column(db.JSON)  # {address_line1, address_line2, city, province, postal_code, country}
    contact_info = db.Column(db.JSON)  # {phone_primary, phone_secondary, email}
    email = db.Column(db.String(255))
    blood_type = db.Column(db.String(10))  # A+, A-, B+, B-, AB+, AB-, O+, O-
    guardian_number = db.Column(db.String(50))  # Guardian's phone number
    created_by_hospital = db.Column(db.Integer, db.ForeignKey('hospitals.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    identifiers = db.relationship('PatientIdentifier', backref='patient', lazy=True, cascade='all, delete-orphan')
    medical_encounters = db.relationship('MedicalEncounter', backref='patient', lazy=True)
    qr_tokens = db.relationship('QRToken', backref='patient', lazy=True)
    patient_hospitals = db.relationship('PatientHospital', backref='patient', lazy=True)
    
    def __repr__(self):
        return f'<Patient {self.full_name}>'


class PatientIdentifier(db.Model):
    __tablename__ = 'patient_identifiers'
    
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    id_type = db.Column(db.String(50), nullable=False)  # nic, passport, driving_license, etc.
    id_value = db.Column(db.String(100), nullable=False)
    issued_country = db.Column(db.String(100), default='Sri Lanka')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Composite unique constraint
    __table_args__ = (db.UniqueConstraint('id_type', 'id_value', name='unique_identifier'),)
    
    def __repr__(self):
        return f'<PatientIdentifier {self.id_type}: {self.id_value}>'


class Doctor(db.Model):
    __tablename__ = 'doctors'
    
    id = db.Column(db.Integer, primary_key=True)
    hospital_id = db.Column(db.Integer, db.ForeignKey('hospitals.id'), nullable=False)
    license_no = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(255), nullable=False)
    nic = db.Column(db.String(20))  # National Identity Card
    contact_info = db.Column(db.JSON)  # {phone_primary, phone_secondary, email}
    email = db.Column(db.String(255))
    specialties = db.Column(db.JSON)  # List of specialties
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    medical_encounters = db.relationship('MedicalEncounter', backref='doctor', lazy=True)
    
    def __repr__(self):
        return f'<Doctor {self.full_name}>'


class MedicalEncounter(db.Model):
    __tablename__ = 'medical_encounters'
    
    id = db.Column(db.Integer, primary_key=True)
    receipt_number = db.Column(db.String(100))
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.id'), nullable=False)
    hospital_id = db.Column(db.Integer, db.ForeignKey('hospitals.id'), nullable=False)
    diagnosis_text = db.Column(db.Text)
    diagnosis_code = db.Column(db.String(20))  # ICD-10 or similar
    medicines = db.Column(db.JSON)  # List of prescribed medicines
    suggestions = db.Column(db.Text)  # Doctor's suggestions/instructions
    treatment_date = db.Column(db.Date, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<MedicalEncounter {self.id} - {self.patient.full_name if self.patient else "Unknown"}>'


class QRToken(db.Model):
    __tablename__ = 'qr_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(255), unique=True, nullable=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    hospital_id = db.Column(db.Integer, db.ForeignKey('hospitals.id'), nullable=False)
    purpose = db.Column(db.String(255))  # emergency, consultation, etc.
    expires_at = db.Column(db.DateTime)
    revoked = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def is_expired(self):
        if self.expires_at:
            return datetime.utcnow() > self.expires_at
        return False
    
    def is_valid(self):
        return not self.revoked and not self.is_expired()
    
    def __repr__(self):
        return f'<QRToken {self.token[:8]}... for {self.patient.full_name if self.patient else "Unknown"}>'


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    acting_user_type = db.Column(db.String(50))  # ministry, hospital_admin, doctor
    acting_user_id = db.Column(db.Integer)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=True)
    hospital_id = db.Column(db.Integer, db.ForeignKey('hospitals.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)  # login, patient_created, etc.
    details = db.Column(db.JSON)  # Additional action details
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<AuditLog {self.action} by {self.acting_user_type}>'


class PatientHospital(db.Model):
    __tablename__ = 'patient_hospitals'
    
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    hospital_id = db.Column(db.Integer, db.ForeignKey('hospitals.id'), nullable=False)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)  # Any special notes about the patient at this hospital
    
    # Composite unique constraint
    __table_args__ = (db.UniqueConstraint('patient_id', 'hospital_id', name='unique_patient_hospital'),)
    
    def __repr__(self):
        return f'<PatientHospital {self.patient.full_name if self.patient else "Unknown"} at {self.hospital.name if self.hospital else "Unknown"}>'