from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from fpdf import FPDF
from flask_wtf.csrf import CSRFProtect
import bleach
import os
import datetime

app = Flask(__name__)
app.secret_key = 'super_secret_key_for_session_security'

# --- SECURITY 1: CSRF PROTECTION ---
csrf = CSRFProtect(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, 'database.db')
STATIC_DIR = os.path.join(BASE_DIR, 'static')


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# --- SECURITY 2: INPUT SANITISATION ---
def clean_input(text):
    if text is None: return ""
    return bleach.clean(str(text), tags=[], attributes={}, strip=True)


# --- SECURITY 3: SECURE HEADERS ---
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


# --- AUTO-REPAIR DATABASE ---
def auto_repair_database():
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='appointments'")
        if not cursor.fetchone():
            cursor.execute('''CREATE TABLE appointments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_id INTEGER, doctor_id INTEGER,
                appointment_date TEXT, reason TEXT, status TEXT DEFAULT 'Pending')''')

        cursor.execute("PRAGMA table_info(appointments)")
        cols = [i[1] for i in cursor.fetchall()]
        if 'doctor_id' not in cols:
            cursor.execute("ALTER TABLE appointments ADD COLUMN doctor_id INTEGER")

        pw = generate_password_hash('Doctor123!', method='pbkdf2:sha256')
        docs = [("Dr. Alistair Sterling", "dr.sterling@ltu.ac.uk", "GMC12345"),
                ("Dr. Priya Kapoor", "dr.kapoor@ltu.ac.uk", "GMC67890"),
                ("Dr. Thomas Wu", "dr.thomaswu@ltu.ac.uk", "GMC54321")]

        for name, email, nhs in docs:
            cursor.execute("SELECT id FROM patients WHERE email=?", (email,))
            if cursor.fetchone():
                cursor.execute("UPDATE patients SET password_hash=?, fullname=?, role='doctor' WHERE email=?",
                               (pw, name, email))
            else:
                cursor.execute(
                    "INSERT INTO patients (fullname, email, nhs_number, password_hash, role, stroke_risk_score) VALUES (?,?,?,?,'doctor',0)",
                    (name, email, nhs, pw))

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"DB Error: {e}")


auto_repair_database()


# --- RISK ENGINE ---
def calculate_stroke_risk(user):
    score = 0
    advice = []
    try:
        age = int(user['age']) if user['age'] else 0
        glucose = float(user['avg_glucose_level']) if user['avg_glucose_level'] else 0
        bmi = float(user['bmi']) if user['bmi'] else 0
    except ValueError:
        age, glucose, bmi = 0, 0, 0

    if age > 60: score += 20; advice.append("Age > 60: Higher risk factor.")
    if user['hypertension'] == 1: score += 20; advice.append("Hypertension: Monitor BP.")
    if user['heart_disease'] == 1: score += 20; advice.append("Heart Disease: Follow treatment.")
    if glucose > 200: score += 15; advice.append("High Glucose: Screen for diabetes.")
    if bmi > 30: score += 10; advice.append("BMI > 30: Weight management advised.")
    if user['smoking_status'] == 'smokes': score += 25; advice.append("Stop smoking immediately.")

    if score == 0: advice.append("No major risks detected. Maintain healthy lifestyle.")
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


@app.route('/login', methods=['POST'])
def login():
    identifier = clean_input(request.form.get('email') or request.form.get('username') or request.form.get('doctor_id'))
    password = request.form['password']

    if not identifier:
        flash('Please enter your email, username, or Medical ID.')
        return redirect(url_for('login_page'))

    conn = get_db()
    user = conn.execute('SELECT * FROM patients WHERE email = ? OR nhs_number = ?', (identifier, identifier)).fetchone()
    conn.close()

    if user and check_password_hash(user['password_hash'], password):
        session['user_id'] = user['id']
        session['role'] = user['role']
        session['fullname'] = user['fullname']

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
        flash("Invalid email or password too short.")
        return redirect(url_for('register_page'))

    hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
    conn = get_db()
    try:
        conn.execute(
            'INSERT INTO patients (fullname, email, nhs_number, password_hash, role, stroke_risk_score) VALUES (?,?,?,?,"patient",0)',
            (fullname, email, nhs, hashed_pw))
        conn.commit()
        flash('Registered! Please login.')
        return redirect(url_for('login_page'))
    except sqlite3.IntegrityError:
        flash('Email taken.')
        return redirect(url_for('register_page'))
    finally:
        conn.close()


@app.route('/patient-dashboard')
def dashboard():
    if session.get('role') != 'patient': return redirect(url_for('login_page'))
    conn = get_db()
    user = conn.execute('SELECT * FROM patients WHERE id = ?', (session['user_id'],)).fetchone()
    doctors = conn.execute("SELECT id, fullname FROM patients WHERE role = 'doctor'").fetchall()

    try:
        apps = conn.execute(
            'SELECT a.*, d.fullname as doctor_name FROM appointments a LEFT JOIN patients d ON a.doctor_id = d.id WHERE a.patient_id = ?',
            (session['user_id'],)).fetchall()
    except:
        apps = []

    risk, advice = calculate_stroke_risk(user)
    conn.close()
    return render_template('dashboard.html', user=user, risk_score=risk, advice_list=advice, appointments=apps,
                           doctors=doctors)


@app.route('/doctor-dashboard')
def doctor_dashboard():
    if session.get('role') != 'doctor': return redirect(url_for('login_page'))
    conn = get_db()
    pts = conn.execute("SELECT * FROM patients WHERE role = 'patient'").fetchall()
    try:
        pending = conn.execute(
            "SELECT a.*, p.fullname as patient_name FROM appointments a JOIN patients p ON a.patient_id = p.id WHERE a.doctor_id = ? AND a.status = 'Pending'",
            (session['user_id'],)).fetchall()
        confirmed = conn.execute(
            "SELECT a.*, p.fullname as patient_name FROM appointments a JOIN patients p ON a.patient_id = p.id WHERE a.doctor_id = ? AND a.status = 'Approved' ORDER BY a.appointment_date",
            (session['user_id'],)).fetchall()
    except:
        pending, confirmed = [], []
    conn.close()
    return render_template('doctor_dashboard.html', patients=pts, pending_appointments=pending,
                           confirmed_appointments=confirmed, doctor_name=session['fullname'])


@app.route('/process_appointment/<int:id>/<action>')
def process_appointment(id, action):
    if session.get('role') != 'doctor': return redirect(url_for('login_page'))
    if action not in ['approve', 'neglect']: return redirect(url_for('doctor_dashboard'))

    status = "Approved" if action == 'approve' else "Neglected"
    conn = get_db()
    conn.execute("UPDATE appointments SET status = ? WHERE id = ?", (status, id))
    conn.commit()
    conn.close()
    flash(f'Appointment {status}.')
    return redirect(url_for('doctor_dashboard'))


@app.route('/book_appointment', methods=['POST'])
def book_appointment():
    if 'user_id' not in session: return redirect(url_for('login_page'))

    conn = get_db()
    user = conn.execute('SELECT * FROM patients WHERE id = ?', (session['user_id'],)).fetchone()
    risk, _ = calculate_stroke_risk(user)

    # RISK CHECK: Prevent booking if low risk (Backend Validation)
    if risk <= 30:
        conn.close()
        flash('Booking Denied: Risk too low (≤30%) for urgent appointments.')
        return redirect(url_for('dashboard'))

    reason = clean_input(request.form['reason'])
    date = clean_input(request.form['date'])
    doc_id = request.form.get('doctor_id')

    if not doc_id:
        conn.close()
        flash("Please select a doctor.")
        return redirect(url_for('dashboard'))

    conn.execute(
        'INSERT INTO appointments (patient_id, doctor_id, appointment_date, reason, status) VALUES (?,?,?,?,"Pending")',
        (session['user_id'], doc_id, date, reason))
    conn.commit()
    conn.close()
    flash('Urgent appointment requested successfully!')
    return redirect(url_for('dashboard'))


@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session: return redirect(url_for('login_page'))

    nhs = clean_input(request.form.get('nhs_number'))
    smoking = clean_input(request.form.get('smoking_status'))
    try:
        age = int(request.form.get('age'))
        glucose = float(request.form.get('avg_glucose_level'))
        bmi = float(request.form.get('bmi'))
    except (ValueError, TypeError):
        flash("Invalid numeric input.")
        return redirect(url_for('dashboard'))

    hypertension = 1 if 'hypertension' in request.form else 0
    heart = 1 if 'heart_disease' in request.form else 0

    conn = get_db()
    conn.execute(
        'UPDATE patients SET nhs_number=?, age=?, smoking_status=?, avg_glucose_level=?, bmi=?, hypertension=?, heart_disease=? WHERE id=?',
        (nhs, age, smoking, glucose, bmi, hypertension, heart, session['user_id']))
    conn.commit()
    conn.close()
    flash('Profile updated!')
    return redirect(url_for('dashboard'))


# --- CREATIVE & INTERACTIVE PDF GENERATOR ---
@app.route('/download_report')
def download_report():
    if 'user_id' not in session: return redirect(url_for('login_page'))

    conn = get_db()
    user = conn.execute('SELECT * FROM patients WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()

    risk_score, medical_advice = calculate_stroke_risk(user)

    # 1. Determine "Health Persona" & Habits
    habits = []
    if risk_score <= 20:
        persona = "The Health Guardian"
        color = (39, 174, 96)  # Green
        status_msg = "Excellent! Maintain your current path."
        habits = [
            "Daily: 30-minute brisk walk",
            "Diet: 5 portions of fruit/veg",
            "Mental: 10 mins meditation"
        ]
    elif risk_score <= 50:
        persona = "The Health Optimizer"
        color = (243, 156, 18)  # Orange
        status_msg = "Caution: Improvements Needed."
        habits = [
            "Action: Reduce sodium (salt) intake",
            "Exercise: 3 cardio sessions/week",
            "Check: Monitor blood pressure weekly"
        ]
    else:
        persona = "The Health Warrior"
        color = (192, 57, 43)  # Red
        status_msg = "High Alert: Immediate Action Required."
        habits = [
            "Urgent: Speak to a GP immediately",
            "Strict: Zero smoking policy",
            "Daily: Track and log blood pressure"
        ]

    # 2. Generate PDF
    pdf = FPDF()
    pdf.add_page()

    # --- HEADER ---
    pdf.set_font("Arial", 'B', 24)
    pdf.set_text_color(0, 94, 184)  # NHS Blue
    pdf.cell(0, 10, "LTU Health Analytics", ln=1, align='C')

    # Date Centered
    pdf.set_font("Arial", '', 12)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 10, f"Report Date: {datetime.date.today()}", ln=1, align='C')
    pdf.ln(10)

    # --- PATIENT INFO CARD (CENTERED) ---
    pdf.set_fill_color(245, 245, 245)
    # Centered box: (210 - 150) / 2 = 30
    pdf.rect(30, 40, 150, 25, 'F')

    pdf.set_y(45)
    pdf.set_font("Arial", 'B', 14)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 8, f"Patient: {user['fullname']}", ln=1, align='C')
    pdf.set_font("Arial", '', 13)
    pdf.cell(0, 8, f"NHS Number: {user['nhs_number'] or 'N/A'}", ln=1, align='C')

    # --- RISK VISUALIZATION ---
    pdf.ln(25)
    pdf.set_font("Arial", 'B', 18)
    pdf.cell(0, 10, "Stroke Risk Analysis", ln=1, align='C')

    # Calculate Center Position for Bar (Width 120mm)
    # Start X = (210 - 120) / 2 = 45
    bar_x = 45
    bar_y = pdf.get_y() + 5
    bar_width = 120

    # Background Bar
    pdf.set_fill_color(220, 220, 220)
    pdf.rect(bar_x, bar_y, bar_width, 10, 'F')

    # Active Risk Portion
    pdf.set_fill_color(*color)
    fill_width = (bar_width * risk_score) / 100
    if fill_width > 0:
        pdf.rect(bar_x, bar_y, fill_width, 10, 'F')

    pdf.set_y(bar_y + 15)

    pdf.set_font("Arial", 'B', 16)
    pdf.set_text_color(*color)
    pdf.cell(0, 10, f"Your Risk Score: {risk_score}%", ln=1, align='C')

    pdf.set_font("Arial", 'I', 14)
    pdf.set_text_color(50, 50, 50)
    pdf.cell(0, 10, f"Health Persona: {persona}", ln=1, align='C')
    pdf.cell(0, 10, f"Status: {status_msg}", ln=1, align='C')

    # --- ACTION PLAN ---
    pdf.ln(10)
    pdf.set_text_color(0, 94, 184)
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, "Your Personalized Action Plan", ln=1, align='C')

    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Arial", '', 14)

    bullet = chr(149)
    for habit in habits:
        pdf.cell(0, 10, f"{bullet}  {habit}", ln=1, align='C')

    pdf.ln(10)
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, "Medical Advice:", ln=1, align='C')
    pdf.set_font("Arial", '', 13)
    for advice in medical_advice:
        pdf.cell(0, 9, f"{bullet} {advice}", ln=1, align='C')

    # --- INTERACTIVE ELEMENT ---
    pdf.ln(15)
    pdf.set_text_color(0, 0, 255)
    pdf.set_font("Arial", 'U', 14)
    link_url = "https://www.nhs.uk/conditions/stroke/"
    pdf.cell(0, 10, "Click here to visit the official NHS Stroke Guide", ln=1, align='C', link=link_url)

    # --- LOGO AT BOTTOM (Smart Positioning) ---
    logo_path = os.path.join(STATIC_DIR, 'image_1.png')
    if os.path.exists(logo_path):
        # Calculate Y: Ensure it is at least at 260mm, or well below current text
        current_y = pdf.get_y()
        target_y = max(260, current_y + 15)

        # If running off page, new page
        if target_y > 280:
            pdf.add_page()
            target_y = 20

        # X=85 centers a 40mm image on A4
        pdf.image(logo_path, x=85, y=target_y, w=40)

    response = make_response(pdf.output(dest='S').encode('latin1'))
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=Health_Report.pdf'
    return response


@app.route('/admin-dashboard')
def admin_dashboard():
    if session.get('role') != 'admin': return redirect(url_for('login_page'))
    return render_template('admin_dashboard.html')


if __name__ == '__main__':
    app.run(debug=True)