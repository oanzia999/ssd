from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from fpdf import FPDF
import datetime

app = Flask(__name__)
app.secret_key = 'super_secret_key_for_session_security'


def get_db():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn


# --- RISK CALCULATION ENGINE ---
def calculate_stroke_risk(user):
    score = 0
    advice = []

    # Safe access to fields (handle NoneType)
    age = user['age'] if user['age'] else 0
    hypertension = user['hypertension'] if user['hypertension'] else 0
    heart_disease = user['heart_disease'] if user['heart_disease'] else 0
    glucose = user['avg_glucose_level'] if user['avg_glucose_level'] else 0
    bmi = user['bmi'] if user['bmi'] else 0
    smoking = user['smoking_status'] if user['smoking_status'] else 'Unknown'

    # 1. Age Factor
    if age > 60:
        score += 20
        advice.append("Age > 60: Higher risk factor.")

    # 2. Medical Conditions
    if hypertension == 1:
        score += 20
        advice.append("Hypertension: Monitor blood pressure daily.")
    if heart_disease == 1:
        score += 20
        advice.append("Heart Disease: Follow cardiology treatment plan.")

    # 3. Lifestyle
    if glucose > 200:
        score += 15
        advice.append("High Glucose: Screen for diabetes.")

    if bmi > 30:
        score += 10
        advice.append("BMI > 30: Consider weight management.")

    if smoking == 'smokes':
        score += 25
        advice.append("Smoking: Critical risk factor. Stop smoking immediately.")

    # Base advice if healthy
    if score == 0:
        advice.append("No major risk factors detected. Maintain healthy lifestyle.")

    return min(score, 100), advice


# --- ROUTES ---

@app.route('/')
def home(): return render_template('home.html')


@app.route('/home.html')
def home_redirect(): return redirect(url_for('home'))


@app.route('/patient.html')
def patient_page(): return render_template('patient.html')


@app.route('/doctor.html')
def doctor_page(): return render_template('doctor.html')


@app.route('/about.html')
def about_page(): return render_template('about.html')


@app.route('/login.html')
def login_page(): return render_template('login.html')


@app.route('/register.html')
def register_page(): return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.')
    return redirect(url_for('home'))


# --- AUTH ---
@app.route('/login', methods=['POST'])
def login():
    identifier = request.form.get('email') or request.form.get('doctor_id') or request.form.get('username')
    password = request.form['password']

    conn = get_db()
    user = conn.execute('SELECT * FROM patients WHERE email = ? OR nhs_number = ?', (identifier, identifier)).fetchone()
    conn.close()

    if user and check_password_hash(user['password_hash'], password):
        session['user_id'] = user['id']
        session['role'] = user['role']
        session['fullname'] = user['fullname']

        if user['role'] == 'doctor':
            return redirect(url_for('doctor_dashboard'))
        elif user['role'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('dashboard'))
    else:
        flash('Invalid credentials.')
        return redirect(url_for('login_page'))


@app.route('/doctor-login', methods=['POST'])
def doctor_login(): return login()


@app.route('/admin-login', methods=['POST'])
def admin_login(): return login()


@app.route('/register', methods=['POST'])
def register():
    fullname = request.form['fullname']
    email = request.form['email']
    nhs = request.form.get('nhs-number')
    password = request.form['password']
    hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')

    conn = get_db()
    try:
        conn.execute('''
            INSERT INTO patients (fullname, email, nhs_number, password_hash, role, stroke_risk_score) 
            VALUES (?, ?, ?, ?, 'patient', 0)
        ''', (fullname, email, nhs, hashed_pw))
        conn.commit()
        conn.close()
        flash('Registered! Please login.')
        return redirect(url_for('login_page'))
    except sqlite3.IntegrityError:
        flash('Email taken.')
        return redirect(url_for('register_page'))


# --- PATIENT DASHBOARD ---
@app.route('/patient-dashboard')
def dashboard():
    if 'user_id' not in session or session['role'] != 'patient':
        return redirect(url_for('login_page'))

    conn = get_db()
    user = conn.execute('SELECT * FROM patients WHERE id = ?', (session['user_id'],)).fetchone()

    # 1. Calculate Risk
    risk_score, advice_list = calculate_stroke_risk(user)

    # 2. Get Appointments
    appointments = conn.execute('SELECT * FROM appointments WHERE patient_id = ?', (session['user_id'],)).fetchall()
    conn.close()

    # 3. PASS VARIABLES TO TEMPLATE (This fixes your error)
    return render_template('dashboard.html',
                           user=user,
                           risk_score=risk_score,
                           advice_list=advice_list,
                           appointments=appointments)


# --- PATIENT ACTIONS ---
@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session: return redirect(url_for('login_page'))

    # Get form data (handling checkboxes for booleans)
    nhs = request.form['nhs_number']
    age = request.form['age']
    smoking = request.form['smoking_status']
    glucose = request.form['avg_glucose_level']
    bmi = request.form['bmi']

    # Checkboxes don't send "0" if unchecked, they send nothing.
    hypertension = 1 if 'hypertension' in request.form else 0
    heart_disease = 1 if 'heart_disease' in request.form else 0

    conn = get_db()
    conn.execute('''
        UPDATE patients 
        SET nhs_number=?, age=?, smoking_status=?, avg_glucose_level=?, bmi=?, hypertension=?, heart_disease=?
        WHERE id=?
    ''', (nhs, age, smoking, glucose, bmi, hypertension, heart_disease, session['user_id']))
    conn.commit()
    conn.close()

    flash('Medical profile updated! Risk score recalculated.')
    return redirect(url_for('dashboard'))


@app.route('/book_appointment', methods=['POST'])
def book_appointment():
    if 'user_id' not in session: return redirect(url_for('login_page'))
    conn = get_db()
    conn.execute('INSERT INTO appointments (patient_id, appointment_date, reason) VALUES (?, ?, ?)',
                 (session['user_id'], request.form['date'], request.form['reason']))
    conn.commit()
    conn.close()
    flash('Appointment request sent!')
    return redirect(url_for('dashboard'))


@app.route('/download_report')
def download_report():
    if 'user_id' not in session: return redirect(url_for('login_page'))
    conn = get_db()
    user = conn.execute('SELECT * FROM patients WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()

    risk_score, advice_list = calculate_stroke_risk(user)

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"Health Report for {user['fullname']}", ln=1, align='C')
    pdf.ln(10)
    pdf.cell(200, 10, txt=f"Risk Score: {risk_score}%", ln=1)
    pdf.cell(200, 10, txt="Advice:", ln=1)
    for item in advice_list:
        pdf.cell(200, 10, txt=f"- {item}", ln=1)

    response = make_response(pdf.output(dest='S').encode('latin1'))
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=report.pdf'
    return response


# --- DOCTOR/ADMIN ROUTES ---
@app.route('/doctor-dashboard')
def doctor_dashboard():
    if session.get('role') != 'doctor': return redirect(url_for('login_page'))
    conn = get_db()
    patients = conn.execute("SELECT * FROM patients WHERE role = 'patient'").fetchall()
    conn.close()
    return render_template('doctor_dashboard.html', patients=patients, doctor_name=session['fullname'])


@app.route('/update_risk', methods=['POST'])
def update_risk():
    if session.get('role') != 'doctor': return redirect(url_for('login_page'))
    conn = get_db()
    conn.execute('UPDATE patients SET risk_level = ? WHERE id = ?',
                 (request.form['risk_level'], request.form['patient_id']))
    conn.commit()
    conn.close()
    return redirect(url_for('doctor_dashboard'))


@app.route('/admin-dashboard')
def admin_dashboard():
    if session.get('role') != 'admin': return redirect(url_for('login_page'))
    conn = get_db()
    users = conn.execute("SELECT * FROM patients").fetchall()
    conn.close()
    return render_template('admin_dashboard.html', users=users)


@app.route('/admin_delete_user', methods=['POST'])
def admin_delete_user():
    if session.get('role') != 'admin': return redirect(url_for('login_page'))
    conn = get_db()
    conn.execute('DELETE FROM patients WHERE id = ?', (request.form['user_id'],))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_dashboard'))


@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'user_id' not in session: return redirect(url_for('login_page'))
    conn = get_db()
    conn.execute('DELETE FROM patients WHERE id = ?', (session['user_id'],))
    conn.commit()
    conn.close()
    session.clear()
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)