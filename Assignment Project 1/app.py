from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
import sqlite3
from pymongo import MongoClient
from werkzeug.security import check_password_hash
from fpdf import FPDF
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cryptography.fernet import Fernet
import bleach
import os
import datetime
from bson.objectid import ObjectId

app = Flask(__name__)
app.secret_key = 'super_secret_key_for_session_security'
csrf = CSRFProtect(app)
# STEP 3: BRUTE FORCE PROTECTION (Rate Limiting)
limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")

# --- CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SQLITE_DB = os.path.join(BASE_DIR, 'auth.db')
MONGO_URI = "mongodb://localhost:27017/"
MONGO_DB_NAME = "ltu_health_records"
STATIC_DIR = os.path.join(BASE_DIR, 'static')
KEY_FILE = os.path.join(BASE_DIR, "secret.key")

# --- ENCRYPTION HANDLER (STEP 4) ---
try:
    with open(KEY_FILE, "rb") as kf:
        cipher = Fernet(kf.read())
except FileNotFoundError:
    print("!!! ERROR: secret.key not found. Run setup_hybrid.py first!")
    cipher = None


def encrypt_data(text):
    if not text: return ""
    return cipher.encrypt(str(text).encode()).decode()


def decrypt_data(text):
    if not text: return ""
    try:
        return cipher.decrypt(str(text).encode()).decode()
    except:
        return "[Encrypted]"


# --- DATABASE CONNECTORS ---
def get_sqlite_conn():
    conn = sqlite3.connect(SQLITE_DB)
    conn.row_factory = sqlite3.Row
    return conn


def get_mongo_db():
    client = MongoClient(MONGO_URI)
    return client[MONGO_DB_NAME]


# --- AUDIT LOGGING (STEP 2) ---
def log_audit(user_email, action, details):
    db = get_mongo_db()
    db.audit_logs.insert_one({
        "user": user_email, "action": action, "details": details,
        "ip": request.remote_addr, "timestamp": datetime.datetime.now()
    })


def clean_input(text):
    if text is None: return ""
    return bleach.clean(str(text), tags=[], attributes={}, strip=True)


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


# --- RISK ENGINE ---
def calculate_stroke_risk(mongo_doc):
    score = 0
    advice = []

    age = mongo_doc.get('age', 0)
    hypertension = mongo_doc.get('hypertension', 0)
    heart_disease = mongo_doc.get('heart_disease', 0)
    glucose = mongo_doc.get('avg_glucose_level', 0)
    bmi = mongo_doc.get('bmi', 0)
    smoking = mongo_doc.get('smoking_status', 'Unknown')
    stroke_history = mongo_doc.get('stroke_history', 0)

    if stroke_history == 1: score += 30; advice.append("History of Stroke: High recurrence risk.")
    if heart_disease == 1: score += 20; advice.append("Heart Disease: Follow treatment.")
    if hypertension == 1: score += 20; advice.append("Hypertension: Monitor BP.")
    if age > 60: score += 15; advice.append("Age > 60: Increased risk.")
    if glucose > 200: score += 15; advice.append("High Glucose: Screen for diabetes.")
    if bmi > 30: score += 10; advice.append("BMI > 30: Weight management advised.")
    if smoking == 'smokes': score += 25; advice.append("Smoking: Critical risk.")

    if score == 0: advice.append("No major risks. Maintain healthy lifestyle.")
    return min(score, 100), advice


# --- ROUTES ---
@app.route('/')
def home(): return render_template('home.html')


@app.route('/login.html')
def login_page(): return render_template('login.html')


@app.route('/register.html')
def register_page(): return render_template('register.html')


@app.route('/patient.html')
def patient_page(): return render_template('patient.html')


@app.route('/doctor.html')
def doctor_page(): return render_template('doctor.html')


@app.route('/about.html')
def about_page(): return render_template('about.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.')
    return redirect(url_for('home'))


# --- AUTH (Rate Limited) ---
@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    identifier = clean_input(request.form.get('email') or request.form.get('username') or request.form.get('doctor_id'))
    password = request.form['password']

    if not identifier: return redirect(url_for('login_page'))

    conn = get_sqlite_conn()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (identifier,)).fetchone()
    conn.close()

    if user and check_password_hash(user['password_hash'], password):
        session['email'] = user['email']
        session['role'] = user['role']

        db = get_mongo_db()
        profile = db.patients.find_one({"email": user['email']})
        session['fullname'] = decrypt_data(profile.get('fullname')) if profile else "User"

        log_audit(session['email'], "LOGIN", f"Role: {user['role']}")

        if user['role'] == 'doctor': return redirect(url_for('doctor_dashboard'))
        if user['role'] == 'admin': return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))

    flash('Invalid credentials.')
    return redirect(url_for('login_page'))


@app.route('/doctor-login', methods=['POST'])
def doctor_login(): return login()


@app.route('/admin-login', methods=['POST'])
def admin_login(): return login()


@app.route('/register', methods=['POST'])
def register():
    fullname = clean_input(request.form['fullname'])
    email = clean_input(request.form['email'])
    nhs = clean_input(request.form.get('nhs-number'))
    password = request.form['password']

    if "@" not in email or len(password) < 6:
        flash("Invalid email.")
        return redirect(url_for('register_page'))

    from werkzeug.security import generate_password_hash
    hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')

    conn = get_sqlite_conn()
    try:
        conn.execute('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)',
                     (email, hashed_pw, 'patient'))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        flash('Email registered.')
        return redirect(url_for('register_page'))
    conn.close()

    db = get_mongo_db()
    if not db.patients.find_one({"email": email}):
        db.patients.insert_one({
            "email": email,
            "fullname": encrypt_data(fullname),  # Encrypt
            "nhs_number": encrypt_data(nhs),  # Encrypt
            "role": "patient",
            "stroke_risk_score": 0
        })

    flash('Registered! Please login.')
    return redirect(url_for('login_page'))


# --- PATIENT DASHBOARD ---
@app.route('/patient-dashboard')
def dashboard():
    if session.get('role') != 'patient': return redirect(url_for('login_page'))
    db = get_mongo_db()
    user = db.patients.find_one({"email": session['email']})

    user['fullname'] = decrypt_data(user.get('fullname'))
    user['nhs_number'] = decrypt_data(user.get('nhs_number'))

    doctors = [{"id": str(d['_id']), "fullname": decrypt_data(d['fullname'])} for d in
               db.patients.find({"role": "doctor"})]
    appointments = list(db.appointments.find({"patient_email": session['email']}))
    for apt in appointments: apt['doctor_name'] = decrypt_data(apt['doctor_name'])

    risk, advice = calculate_stroke_risk(user)
    return render_template('dashboard.html', user=user, risk_score=risk, advice_list=advice, appointments=appointments,
                           doctors=doctors)


# --- DOCTOR DASHBOARD ---
@app.route('/doctor-dashboard')
def doctor_dashboard():
    if session.get('role') != 'doctor': return redirect(url_for('login_page'))
    db = get_mongo_db()

    # 1. Fetch Patients & Decrypt
    patients = []
    # Limit to first 50 for performance
    for p in db.patients.find({"role": "patient"}):
        p['fullname'] = decrypt_data(p.get('fullname'))
        p['nhs_number'] = decrypt_data(p.get('nhs_number'))
        p['gender'] = p.get('gender')  # Gender is NOT encrypted in setup script, just text
        patients.append(p)

    pending = list(db.appointments.find({"doctor_email": session['email'], "status": "Pending"}))
    for a in pending: a['patient_name'] = decrypt_data(a.get('patient_name'))

    confirmed = list(db.appointments.find({"doctor_email": session['email'], "status": "Approved"}))
    for a in confirmed: a['patient_name'] = decrypt_data(a.get('patient_name'))

    return render_template('doctor_dashboard.html', patients=patients, pending_appointments=pending,
                           confirmed_appointments=confirmed, doctor_name=session['fullname'])


# --- DOCTOR EDIT PATIENT ---
@app.route('/edit_patient/<string:patient_id>')
def edit_patient(patient_id):
    if session.get('role') != 'doctor': return redirect(url_for('login_page'))

    db = get_mongo_db()
    patient = db.patients.find_one({"_id": ObjectId(patient_id)})

    if not patient:
        flash("Patient not found.")
        return redirect(url_for('doctor_dashboard'))

    # Decrypt sensitive data
    patient['fullname'] = decrypt_data(patient.get('fullname'))
    patient['nhs_number'] = decrypt_data(patient.get('nhs_number'))

    return render_template('edit_patient.html', patient=patient)


# --- UPDATE PROFILE (Shared) ---
@app.route('/update_profile', methods=['POST'])
def update_profile():
    if session.get('role') not in ['patient', 'doctor']:
        return redirect(url_for('login_page'))

    target_email = session['email'] if session['role'] == 'patient' else request.form.get('target_email')
    redirect_url = 'dashboard' if session['role'] == 'patient' else 'doctor_dashboard'

    if not target_email:
        return redirect(url_for('home'))

    try:
        def safe_float(v):
            return float(v) if v else 0.0

        update_data = {
            "nhs_number": encrypt_data(clean_input(request.form.get('nhs_number'))),
            "age": int(safe_float(request.form.get('age'))),
            "bmi": safe_float(request.form.get('bmi')),
            "avg_glucose_level": safe_float(request.form.get('avg_glucose_level')),
            "smoking_status": clean_input(request.form.get('smoking_status')),
            "hypertension": 1 if 'hypertension' in request.form else 0,
            "heart_disease": 1 if 'heart_disease' in request.form else 0,
            "stroke_history": 1 if 'stroke_history' in request.form else 0
        }

        db = get_mongo_db()
        db.patients.update_one({"email": target_email}, {"$set": update_data})

        log_audit(session['email'], "UPDATE_RECORD", f"Updated record for {target_email}")
        flash('Medical Record Updated.')
        return redirect(url_for(redirect_url))

    except ValueError:
        flash("Invalid input format.")
        return redirect(url_for(redirect_url))


# --- BOOKING & ACTIONS ---
@app.route('/book_appointment', methods=['POST'])
def book_appointment():
    if session.get('role') != 'patient': return redirect(url_for('login_page'))

    db = get_mongo_db()
    user = db.patients.find_one({"email": session['email']})
    risk, _ = calculate_stroke_risk(user)

    if risk <= 30:
        flash('Booking Denied: Risk too low.')
        return redirect(url_for('dashboard'))

    doc_id = request.form.get('doctor_id')
    doc = db.patients.find_one({"_id": ObjectId(doc_id)})

    db.appointments.insert_one({
        "patient_email": session['email'],
        "patient_name": user['fullname'],  # Already Encrypted
        "doctor_email": doc['email'],
        "doctor_name": doc['fullname'],  # Already Encrypted
        "appointment_date": clean_input(request.form['date']),
        "reason": clean_input(request.form['reason']),
        "status": "Pending"
    })
    flash('Appointment requested.')
    return redirect(url_for('dashboard'))


@app.route('/process_appointment/<string:apt_id>/<action>')
def process_appointment(apt_id, action):
    if session.get('role') != 'doctor': return redirect(url_for('login_page'))
    status = "Approved" if action == 'approve' else "Neglected"
    get_mongo_db().appointments.update_one({"_id": ObjectId(apt_id)}, {"$set": {"status": status}})
    flash(f'Appointment {status}.')
    return redirect(url_for('doctor_dashboard'))


# --- PDF REPORT ---
@app.route('/download_report')
def download_report():
    if session.get('role') != 'patient': return redirect(url_for('login_page'))
    db = get_mongo_db()
    user = db.patients.find_one({"email": session['email']})

    # Decrypt for PDF
    fullname = decrypt_data(user.get('fullname'))
    nhs_num = decrypt_data(user.get('nhs_number'))
    gender = user.get('gender')  # Gender is plaintext in Mongo setup

    risk_score, medical_advice = calculate_stroke_risk(user)

    habits = []
    if risk_score <= 20:
        persona = "The Health Guardian"
        color = (39, 174, 96)
        status_msg = "Excellent! Maintain your current path."
        habits = ["Daily: 30-minute brisk walk", "Diet: 5 portions of fruit/veg", "Mental: 10 mins meditation"]
    elif risk_score <= 50:
        persona = "The Health Optimizer"
        color = (243, 156, 18)
        status_msg = "Caution: Improvements Needed."
        habits = ["Action: Reduce sodium (salt)", "Exercise: 3 cardio sessions/week", "Check: Monitor blood pressure"]
    else:
        persona = "The Health Warrior"
        color = (192, 57, 43)
        status_msg = "High Alert: Action Required."
        habits = ["Urgent: Speak to a GP", "Strict: Zero smoking", "Daily: Track blood pressure"]

    pdf = FPDF()
    pdf.add_page()
    logo_path = os.path.join(STATIC_DIR, 'image_1.png')

    pdf.set_font("Arial", 'B', 24)
    pdf.set_text_color(0, 94, 184)
    pdf.cell(0, 10, "LTU Health Analytics", ln=1, align='C')
    pdf.set_font("Arial", '', 12)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 10, f"Report Date: {datetime.date.today()}", ln=1, align='C')
    pdf.ln(10)

    pdf.set_fill_color(245, 245, 245)
    pdf.rect(30, 40, 150, 25, 'F')
    pdf.set_y(45)
    pdf.set_font("Arial", 'B', 14)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 8, f"Patient: {fullname}", ln=1, align='C')
    pdf.set_font("Arial", '', 13)
    pdf.cell(0, 8, f"Gender: {gender} | Age: {int(user.get('age', 0))}", ln=1, align='C')

    pdf.ln(25)
    pdf.set_font("Arial", 'B', 18)
    pdf.cell(0, 10, "Stroke Risk Analysis", ln=1, align='C')

    bar_x = 45;
    bar_y = pdf.get_y() + 5;
    bar_width = 120
    pdf.set_fill_color(220, 220, 220)
    pdf.rect(bar_x, bar_y, bar_width, 10, 'F')
    pdf.set_fill_color(*color)
    fill_width = (bar_width * risk_score) / 100
    if fill_width > 0: pdf.rect(bar_x, bar_y, fill_width, 10, 'F')

    pdf.set_y(bar_y + 15)
    pdf.set_font("Arial", 'B', 16)
    pdf.set_text_color(*color)
    pdf.cell(0, 10, f"Your Risk Score: {risk_score}%", ln=1, align='C')
    pdf.set_font("Arial", 'I', 14)
    pdf.set_text_color(50, 50, 50)
    pdf.cell(0, 10, f"Health Persona: {persona}", ln=1, align='C')
    pdf.cell(0, 10, f"Status: {status_msg}", ln=1, align='C')

    pdf.ln(10)
    pdf.set_text_color(0, 94, 184)
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, "Your Personalized Action Plan", ln=1, align='C')
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Arial", '', 14)
    bullet = chr(149)
    for habit in habits: pdf.cell(0, 10, f"{bullet}  {habit}", ln=1, align='C')
    pdf.ln(10)
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, "Medical Advice:", ln=1, align='C')
    pdf.set_font("Arial", '', 13)
    for advice in medical_advice: pdf.cell(0, 9, f"{bullet} {advice}", ln=1, align='C')

    pdf.ln(15)
    pdf.set_text_color(0, 0, 255)
    pdf.set_font("Arial", 'U', 14)
    pdf.cell(0, 10, "Click here to visit the official NHS Stroke Guide", ln=1, align='C',
             link="https://www.nhs.uk/conditions/stroke/")

    if os.path.exists(logo_path):
        target_y = max(250, pdf.get_y() + 15)
        if target_y > 270: pdf.add_page(); target_y = 20
        pdf.image(logo_path, x=85, y=target_y, w=40)

    response = make_response(pdf.output(dest='S').encode('latin1'))
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=Health_Report.pdf'
    return response


# --- ADMIN ---
@app.route('/admin-dashboard')
def admin_dashboard():
    if session.get('role') != 'admin': return redirect(url_for('login_page'))

    db = get_mongo_db()
    # Stats
    patient_count = db.patients.count_documents({"role": "patient"})
    doctor_count = db.patients.count_documents({"role": "doctor"})

    # Decrypt names for lists
    doctors = list(db.patients.find({"role": "doctor"}))
    for d in doctors: d['fullname'] = decrypt_data(d.get('fullname'))

    patients = list(db.patients.find({"role": "patient"}))
    for p in patients: p['fullname'] = decrypt_data(p.get('fullname'))

    # Logs
    logs = list(db.audit_logs.find().sort("timestamp", -1).limit(20))

    return render_template('admin_dashboard.html',
                           patient_count=patient_count,
                           doctor_count=doctor_count,
                           doctors=doctors,
                           patients=patients,
                           logs=logs)


# --- ADMIN ACTIONS ---
@app.route('/admin/add_doctor', methods=['POST'])
def add_doctor():
    if session.get('role') != 'admin': return redirect(url_for('login_page'))

    fullname = clean_input(request.form.get('fullname'))
    email = clean_input(request.form.get('email'))
    password = request.form.get('password')

    from werkzeug.security import generate_password_hash
    hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')

    conn = get_sqlite_conn()
    try:
        conn.execute('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)', (email, hashed_pw, 'doctor'))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close();
        flash('Email exists.');
        return redirect(url_for('admin_dashboard'))
    conn.close()

    db = get_mongo_db()
    db.patients.insert_one({"email": email, "fullname": encrypt_data(fullname), "role": "doctor"})
    flash('Doctor Added.')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete_user/<string:user_id>')
def delete_user(user_id):
    if session.get('role') != 'admin': return redirect(url_for('login_page'))

    db = get_mongo_db()
    user = db.patients.find_one({"_id": ObjectId(user_id)})
    if user:
        email = user['email']
        conn = get_sqlite_conn()
        conn.execute("DELETE FROM users WHERE email = ?", (email,))
        conn.commit()
        conn.close()
        db.patients.delete_one({"_id": ObjectId(user_id)})
        flash('Deleted.')
    return redirect(url_for('admin_dashboard'))


if __name__ == '__main__':
    app.run(debug=True)