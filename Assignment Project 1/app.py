"""
LTU Health Analytics - Secure Web Application
---------------------------------------------
A Hybrid Polyglot Application for Stroke Risk Prediction.

Security Features:
1. Architecture: Hybrid Database (SQLite for Auth, MongoDB for Data).
2. Confidentiality: Fernet Encryption (AES) for PII (Patient Identifiable Information).
3. Integrity: Immutable Audit Logs for all sensitive actions.
4. Availability: Rate Limiting to prevent Brute Force/DDoS.
5. Input Validation: Bleach sanitization against XSS attacks.

Author: Student ID
Module: COM7033 Secure Software Development
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
import sqlite3
from pymongo import MongoClient
from werkzeug.security import check_password_hash, generate_password_hash
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

# --- SECURITY: CSRF & RATE LIMITING ---
csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")

# --- CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SQLITE_DB = os.path.join(BASE_DIR, 'auth.db')  # Relational DB for Credentials
MONGO_URI = "mongodb://localhost:27017/"
MONGO_DB_NAME = "ltu_health_records"  # NoSQL DB for Medical Records
STATIC_DIR = os.path.join(BASE_DIR, 'static')
KEY_FILE = os.path.join(BASE_DIR, "secret.key")

# --- ENCRYPTION HANDLER (Confidentiality) ---
try:
    with open(KEY_FILE, "rb") as kf:
        cipher = Fernet(kf.read())
except FileNotFoundError:
    print("!!! CRITICAL: secret.key not found. Encryption will fail.")
    cipher = None


def encrypt_data(text):
    """
    Encrypts sensitive string data using AES (Fernet).
    Args:
        text (str): The plain text to encrypt.
    Returns:
        str: The encrypted byte string decoded to utf-8.
    """
    if not text: return ""
    return cipher.encrypt(str(text).encode()).decode() if cipher else text


def decrypt_data(text):
    """
    Decrypts ciphertext back to readable string.
    Returns '[Encrypted]' if decryption fails (Graceful Degradation).
    """
    if not text: return ""
    try:
        return cipher.decrypt(str(text).encode()).decode() if cipher else text
    except:
        return "[Encrypted]"


# --- DATABASE CONNECTORS ---
def get_sqlite_conn():
    """Establishes connection to the Authentication Database (SQLite)."""
    conn = sqlite3.connect(SQLITE_DB)
    conn.row_factory = sqlite3.Row
    return conn


def get_mongo_db():
    """Establishes connection to the Medical Record Database (MongoDB)."""
    client = MongoClient(MONGO_URI)
    return client[MONGO_DB_NAME]


# --- AUDIT LOGGING (Accountability) ---
def log_audit(user_email, action, details):
    """
    Records sensitive user actions for GDPR compliance and Non-repudiation.
    Data is stored in a separate 'audit_logs' collection.
    """
    db = get_mongo_db()
    db.audit_logs.insert_one({
        "user": user_email,
        "action": action,
        "details": details,
        "ip": request.remote_addr,
        "timestamp": datetime.datetime.now()
    })


def clean_input(text):
    """
    Sanitizes user input to prevent Cross-Site Scripting (XSS).
    Uses 'bleach' to strip HTML tags like <script>.
    """
    if text is None: return ""
    return bleach.clean(str(text), tags=[], attributes={}, strip=True)


@app.after_request
def add_security_headers(response):
    """
    Injects HTTP Security Headers into every response.
    - X-Content-Type-Options: Prevents MIME-sniffing.
    - X-Frame-Options: Prevents Clickjacking.
    - X-XSS-Protection: Activates browser XSS filters.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


# --- ERROR HANDLERS (Info Leakage Prevention) ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(e):
    return render_template('500.html'), 500


# --- RISK ENGINE (Business Logic) ---
def calculate_stroke_risk(mongo_doc):
    """
    Calculates Stroke Risk % based on NHS Heuristics.
    Args:
        mongo_doc (dict): Patient record from MongoDB.
    Returns:
        tuple: (risk_score_int, list_of_advice_strings)
    """
    score = 0
    advice = []

    # Safe Extraction using .get() to prevent crashes on missing fields
    age = mongo_doc.get('age', 0)
    hypertension = mongo_doc.get('hypertension', 0)
    heart_disease = mongo_doc.get('heart_disease', 0)
    glucose = mongo_doc.get('avg_glucose_level', 0)
    bmi = mongo_doc.get('bmi', 0)
    smoking = mongo_doc.get('smoking_status', 'Unknown')
    stroke_history = mongo_doc.get('stroke_history', 0)

    # Risk Logic
    if stroke_history == 1:
        score += 30
        advice.append("History of Stroke: High recurrence risk.")
    if heart_disease == 1:
        score += 20
        advice.append("Heart Disease: Follow cardiology treatment.")
    if hypertension == 1:
        score += 20
        advice.append("Hypertension: Monitor blood pressure.")
    if age > 60:
        score += 15
        advice.append("Age > 60: Increased biological risk.")
    if glucose > 200:
        score += 15
        advice.append("High Glucose: Screen for diabetes.")
    if bmi > 30:
        score += 10
        advice.append("BMI > 30: Weight management advised.")
    if smoking == 'smokes':
        score += 25
        advice.append("Smoking: Critical risk. Stop immediately.")
    elif smoking == 'formerly smoked':
        score += 5
        advice.append("History of Smoking: Maintain smoke-free lifestyle.")

    if score == 0:
        advice.append("No major risks. Maintain healthy lifestyle.")

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


# --- AUTH (Hybrid: SQL for Auth, Mongo for Name) ---
@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")  # Rate Limiting Rule
def login():
    identifier = clean_input(request.form.get('email') or request.form.get('username') or request.form.get('doctor_id'))
    password = request.form['password']

    if not identifier: return redirect(url_for('login_page'))

    # 1. Verify Credentials against SQLite
    conn = get_sqlite_conn()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (identifier,)).fetchone()
    conn.close()

    if user and check_password_hash(user['password_hash'], password):
        session['email'] = user['email']
        session['role'] = user['role']

        # 2. Fetch Personal Details from MongoDB
        db = get_mongo_db()
        profile = db.patients.find_one({"email": user['email']})

        # Decrypt Name for Session
        session['fullname'] = decrypt_data(profile.get('fullname')) if profile else "User"

        # Audit Log
        log_audit(session['email'], "LOGIN", f"Role: {user['role']}")

        # Role-Based Redirection (RBAC)
        if user['role'] == 'doctor': return redirect(url_for('doctor_dashboard'))
        if user['role'] == 'admin': return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))

    flash('Invalid credentials.')
    return redirect(url_for('login_page'))


@app.route('/doctor-login', methods=['POST'])
def doctor_login(): return login()


@app.route('/admin-login', methods=['POST'])
def admin_login(): return login()


# --- REGISTRATION ---
@app.route('/register', methods=['POST'])
def register():
    # Sanitize inputs
    fullname = clean_input(request.form['fullname'])
    email = clean_input(request.form['email'])
    nhs = clean_input(request.form.get('nhs-number'))
    password = request.form['password']

    # Basic Validation
    if "@" not in email or len(password) < 6:
        flash("Invalid email.")
        return redirect(url_for('register_page'))

    # Password Hashing (Integrity)
    hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')

    # 1. Add to SQLite
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

    # 2. Add to MongoDB (With Encryption)
    db = get_mongo_db()
    if not db.patients.find_one({"email": email}):
        db.patients.insert_one({
            "email": email,
            "fullname": encrypt_data(fullname),  # Encrypted
            "nhs_number": encrypt_data(nhs),  # Encrypted
            "role": "patient",
            "stroke_risk_score": 0,
            # Initialize defaults to prevent dashboard errors
            "age": 0, "gender": encrypt_data("Unknown"), "bmi": 0.0,
            "avg_glucose_level": 0.0, "hypertension": 0, "heart_disease": 0,
            "stroke_history": 0, "smoking_status": "Unknown"
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

    query = request.args.get('q', '').lower()
    sort_by = request.args.get('sort', 'name')

    patients = []
    for p in db.patients.find({"role": "patient"}):
        p['fullname'] = decrypt_data(p.get('fullname'))
        p['nhs_number'] = decrypt_data(p.get('nhs_number'))
        p['gender'] = decrypt_data(p.get('gender'))

        score, _ = calculate_stroke_risk(p)
        p['risk_score'] = score

        if query and query not in p['fullname'].lower(): continue
        patients.append(p)

    if sort_by == 'risk':
        patients.sort(key=lambda x: x['risk_score'], reverse=True)
    elif sort_by == 'age':
        patients.sort(key=lambda x: x.get('age', 0), reverse=True)
    else:
        patients.sort(key=lambda x: x['fullname'].lower())

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
    if not patient: return redirect(url_for('doctor_dashboard'))

    patient['fullname'] = decrypt_data(patient.get('fullname'))
    patient['nhs_number'] = decrypt_data(patient.get('nhs_number'))
    patient['gender'] = decrypt_data(patient.get('gender'))

    return render_template('edit_patient.html', patient=patient)


# --- UPDATE PROFILE ---
@app.route('/update_profile', methods=['POST'])
def update_profile():
    if session.get('role') not in ['patient', 'doctor']: return redirect(url_for('login_page'))

    target_email = session['email'] if session['role'] == 'patient' else request.form.get('target_email')
    redirect_url = 'dashboard' if session['role'] == 'patient' else 'doctor_dashboard'

    try:
        def safe_float(v): return float(v) if v else 0.0

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
        log_audit(session['email'], "UPDATE_RECORD", f"Updated {target_email}")
        flash('Updated successfully.')
        return redirect(url_for(redirect_url))

    except ValueError:
        flash("Invalid input."); return redirect(url_for(redirect_url))


# --- BOOKING & ACTIONS ---
@app.route('/book_appointment', methods=['POST'])
def book_appointment():
    if session.get('role') != 'patient': return redirect(url_for('login_page'))

    db = get_mongo_db()
    user = db.patients.find_one({"email": session['email']})
    risk, _ = calculate_stroke_risk(user)

    if risk <= 30:
        flash('Booking Denied: Risk too low.'); return redirect(url_for('dashboard'))

    doc_id = request.form.get('doctor_id')
    doc = db.patients.find_one({"_id": ObjectId(doc_id)})

    db.appointments.insert_one({
        "patient_email": session['email'],
        "patient_name": user['fullname'],
        "doctor_email": doc['email'],
        "doctor_name": doc['fullname'],
        "appointment_date": clean_input(request.form['date']),
        "reason": clean_input(request.form['reason']),
        "status": "Pending"
    })
    flash('Requested.'); return redirect(url_for('dashboard'))


@app.route('/process_appointment/<string:apt_id>/<action>')
def process_appointment(apt_id, action):
    if session.get('role') != 'doctor': return redirect(url_for('login_page'))
    status = "Approved" if action == 'approve' else "Neglected"
    get_mongo_db().appointments.update_one({"_id": ObjectId(apt_id)}, {"$set": {"status": status}})
    flash(f'{status}.'); return redirect(url_for('doctor_dashboard'))


# --- PDF REPORT (SMART PERSONALIZED INSIGHTS) ---
@app.route('/download_report')
def download_report():
    if session.get('role') != 'patient': return redirect(url_for('login_page'))

    db = get_mongo_db()
    user = db.patients.find_one({"email": session['email']})

    fullname = decrypt_data(user.get('fullname'))
    nhs_num = decrypt_data(user.get('nhs_number'))
    gender = decrypt_data(user.get('gender'))

    # Extract Metrics for Narrative
    age = int(user.get('age', 0))
    bmi = user.get('bmi', 0)
    glucose = user.get('avg_glucose_level', 0)
    smoking = user.get('smoking_status', 'Unknown')
    history = user.get('stroke_history', 0)
    heart = user.get('heart_disease', 0)
    residence = user.get('Residence_type', 'Urban')

    risk_score, medical_advice = calculate_stroke_risk(user)

    # --- 1. PERSONA LOGIC ---
    habits = []
    if risk_score <= 20:
        persona, color, status_msg = "The Health Guardian", (39, 174, 96), "Excellent! Maintain path."
        habits = ["30-min brisk walk daily", "5 portions fruit/veg", "Mental relaxation"]
    elif risk_score <= 50:
        persona, color, status_msg = "The Health Optimizer", (243, 156, 18), "Caution Needed."
        habits = ["Reduce sodium (salt)", "3 cardio sessions/week", "Check BP weekly"]
    else:
        persona, color, status_msg = "The Health Warrior", (192, 57, 43), "High Alert."
        habits = ["Consult GP immediately", "Strict zero smoking", "Daily BP logging"]

    # --- 2. GENERATE DETAILED WELLNESS NARRATIVE ---
    insights = []

    # Smoking Insight
    if smoking == 'smokes':
        insights.append("Your smoking habit is a critical risk factor; cessation can reduce stroke risk by 50% within a year.")
    elif smoking == 'formerly smoked':
        insights.append("As a former smoker, continuing to stay smoke-free is vital for lung and heart recovery.")
    else:
        insights.append("Maintaing a smoke-free lifestyle is your strongest asset against cardiovascular disease.")

    # Medical History Insight
    if history == 1:
        insights.append("Due to previous stroke history, adherence to prescribed anticoagulants is non-negotiable.")
    elif heart == 1:
        insights.append("Your heart disease history necessitates strict cholesterol management and regular cardiology check-ups.")

    # Vitals Insight
    if glucose > 200:
        insights.append(f"Your average glucose ({glucose}) suggests diabetes risk; this damages blood vessels over time.")
    if bmi > 30:
        insights.append(f"A BMI of {bmi:.1f} indicates obesity, which increases strain on your heart.")
    elif bmi < 18.5:
        insights.append(f"Your BMI of {bmi:.1f} is low; ensure you are meeting nutritional needs.")
    else:
        insights.append(f"Great job maintaining a healthy BMI of {bmi:.1f}.")

    # Environmental/Age Insight
    if residence == 'Rural' and risk_score > 50:
        insights.append("Living in a rural area means emergency response times may be longer; have a 'FAST' action plan ready.")

    if age > 65:
        insights.append("Age is a natural risk factor, but staying active can offset biological aging.")

    wellness_narrative = " ".join(insights)

    # --- PDF GENERATION ---
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=False, margin=0)

    # HEADER
    pdf.set_y(10)
    pdf.set_font("Arial", 'B', 24)
    pdf.set_text_color(0, 94, 184)
    pdf.cell(0, 10, "LTU Health Analytics", ln=1, align='C')
    pdf.set_font("Arial", '', 12)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 10, f"Report Date: {datetime.date.today()}", ln=1, align='C')

    # SPLIT LAYOUT START
    y_start = 45
    box_height = 42

    # LEFT BOX (Patient)
    pdf.set_fill_color(245, 245, 245)
    pdf.rect(10, y_start, 95, box_height, 'F')

    # --- FIXED ALIGNMENT START ---
    pdf.set_text_color(0, 0, 0)

    # Row 1: Name
    pdf.set_xy(15, y_start + 6)
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(85, 5, f"Patient: {fullname}", 0, 0, 'L')

    # Row 2: NHS
    pdf.set_xy(15, y_start + 14)
    pdf.set_font("Arial", '', 11)
    pdf.cell(85, 5, f"NHS Number: {nhs_num or 'N/A'}", 0, 0, 'L')

    # Row 3: Gender
    pdf.set_xy(15, y_start + 22)
    pdf.cell(85, 5, f"Gender: {gender}", 0, 0, 'L')

    # Row 4: Age (Aligned with Status)
    pdf.set_xy(15, y_start + 30)
    pdf.cell(85, 5, f"Age: {age}", 0, 0, 'L')
    # --- FIXED ALIGNMENT END ---

    # RIGHT BOX (Risk)
    # Title
    pdf.set_xy(110, y_start + 6)
    pdf.set_font("Arial", 'B', 14)
    pdf.set_text_color(0, 94, 184)
    pdf.cell(90, 5, "Stroke Risk Analysis", 0, 0, 'C')

    # Bar
    bar_x = 120
    bar_y = y_start + 14
    pdf.set_fill_color(220, 220, 220)
    pdf.rect(bar_x, bar_y, 70, 6, 'F')
    pdf.set_fill_color(*color)
    if risk_score > 0: pdf.rect(bar_x, bar_y, (70 * risk_score) / 100, 6, 'F')

    # Score
    pdf.set_xy(110, y_start + 22)
    pdf.set_font("Arial", 'B', 16)
    pdf.set_text_color(*color)
    pdf.cell(90, 5, f"{risk_score}% RISK", 0, 0, 'C')

    # Status (PERFECTLY ALIGNED WITH AGE)
    pdf.set_xy(110, y_start + 30)
    pdf.set_font("Arial", 'I', 11)
    pdf.set_text_color(50, 50, 50)
    pdf.cell(90, 5, f"Status: {persona}", 0, 0, 'C')

    # COLUMNS
    y_cols = 100
    pdf.set_xy(10, y_cols)
    pdf.set_font("Arial", 'B', 16)
    pdf.set_text_color(0, 94, 184)
    pdf.cell(90, 12, "Daily Action Plan", ln=1)
    pdf.set_font("Arial", '', 14)
    pdf.set_text_color(0, 0, 0)
    bullet = chr(149)
    for h in habits:
        pdf.set_x(10)
        pdf.cell(90, 12, f"{bullet} {h}", ln=1)

    pdf.set_xy(110, y_cols)
    pdf.set_font("Arial", 'B', 16)
    pdf.set_text_color(0, 94, 184)
    pdf.cell(90, 12, "Medical Recommendations", ln=1)
    pdf.set_font("Arial", '', 14)
    pdf.set_text_color(0, 0, 0)
    current_y = pdf.get_y()
    for adv in medical_advice[:5]:
        pdf.set_xy(110, current_y)
        pdf.multi_cell(90, 10, f"{bullet} {adv}")
        current_y = pdf.get_y() + 2

    # --- NEW: WELLNESS INSIGHTS CARD ---
    y_insights = 175
    pdf.set_fill_color(245, 245, 245)
    pdf.rect(10, y_insights, 190, 45, 'F')

    pdf.set_xy(15, y_insights + 5)
    pdf.set_font("Arial", 'B', 14)
    pdf.set_text_color(0, 94, 184)
    pdf.cell(0, 10, "Personalized Wellness Insights", ln=1)

    pdf.set_x(15)
    pdf.set_font("Arial", 'I', 12)
    pdf.set_text_color(50, 50, 50)
    pdf.multi_cell(180, 7, wellness_narrative)

    # FOOTER & LOGO
    pdf.set_y(245)
    pdf.set_font("Arial", '', 10)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 5, "This is an automated report. Please consult a doctor for official diagnosis.", ln=1, align='C')

    pdf.set_font("Arial", 'U', 12)
    pdf.set_text_color(0, 0, 255)
    pdf.cell(0, 8, "Click here for the official NHS Stroke Guide", ln=1, align='C', link="https://www.nhs.uk/conditions/stroke/")

    logo_path = os.path.join(STATIC_DIR, 'image_1.png')
    if os.path.exists(logo_path):
        pdf.image(logo_path, x=85, y=260, w=40)

    log_audit(session['email'], "DOWNLOAD_REPORT", "PDF Generated")
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

    # Lists (Decrypt names)
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

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

if __name__ == '__main__':
    app.run(debug=True)