from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'super_secret_key_for_session_security'


# --- DATABASE CONNECTION ---
def get_db():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn


# --- 1. PAGE NAVIGATION ROUTES ---
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/home.html')
def home_redirect():
    return redirect(url_for('home'))


@app.route('/patient.html')
def patient_page():
    return render_template('patient.html')


@app.route('/doctor.html')
def doctor_page():
    return render_template('doctor.html')


@app.route('/about.html')
def about_page():
    return render_template('about.html')


@app.route('/login.html')
def login_page():
    return render_template('login.html')


@app.route('/register.html')
def register_page():
    return render_template('register.html')


# --- 2. AUTHENTICATION ROUTES ---

# Register (Create - Default Role: Patient)
@app.route('/register', methods=['POST'])
def register():
    fullname = request.form['fullname']
    email = request.form['email']
    nhs = request.form.get('nhs-number')
    password = request.form['password']

    hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')

    conn = get_db()
    try:
        conn.execute('INSERT INTO patients (fullname, email, nhs_number, password_hash, role) VALUES (?, ?, ?, ?, ?)',
                     (fullname, email, nhs, hashed_pw, 'patient'))
        conn.commit()
        conn.close()
        flash('Registration successful! Please login.')
        return redirect(url_for('login_page'))
    except sqlite3.IntegrityError:
        flash('Email already registered.')
        return redirect(url_for('register_page'))


# Universal Login (Handles Patient, Doctor, and Admin)
@app.route('/login', methods=['POST'])
def login():
    # Identify user by Email (Patients/Admins) OR Doctor ID/NHS Number
    identifier = request.form.get('email') or request.form.get('doctor_id') or request.form.get('username')
    password = request.form['password']

    conn = get_db()
    # Check if user exists
    user = conn.execute('SELECT * FROM patients WHERE email = ? OR nhs_number = ?', (identifier, identifier)).fetchone()
    conn.close()

    if user and check_password_hash(user['password_hash'], password):
        # Store user details in session
        session['user_id'] = user['id']
        session['user_name'] = user['fullname']
        session['role'] = user['role']

        # --- ROLE BASED REDIRECT ---
        if user['role'] == 'doctor':
            return redirect(url_for('doctor_dashboard'))
        elif user['role'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('dashboard'))

    else:
        flash('Invalid credentials.')
        return redirect(url_for('login_page'))


# Route proxies for HTML form actions (redirects to main login)
@app.route('/doctor-login', methods=['POST'])
def doctor_login(): return login()


@app.route('/admin-login', methods=['POST'])
def admin_login(): return login()


# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('home'))


# --- 3. DASHBOARDS (READ) ---

# Patient Dashboard
@app.route('/patient-dashboard')
def dashboard():
    if 'user_id' not in session or session.get('role') != 'patient':
        return redirect(url_for('login_page'))

    conn = get_db()
    user = conn.execute('SELECT * FROM patients WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    return render_template('dashboard.html', user=user)


# Doctor Dashboard (See all patients)
@app.route('/doctor-dashboard')
def doctor_dashboard():
    if 'user_id' not in session or session.get('role') != 'doctor':
        flash("Access Denied: Doctors Only")
        return redirect(url_for('login_page'))

    conn = get_db()
    # Fetch only patients (exclude other doctors/admins)
    patients = conn.execute("SELECT * FROM patients WHERE role = 'patient'").fetchall()
    conn.close()

    return render_template('doctor_dashboard.html', patients=patients, doctor_name=session['user_name'])


# Admin Dashboard (See all users)
@app.route('/admin-dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Access Denied: Admins Only")
        return redirect(url_for('login_page'))

    conn = get_db()
    users = conn.execute("SELECT * FROM patients").fetchall()
    conn.close()

    return render_template('admin_dashboard.html', users=users)


# --- 4. CRUD ACTIONS (UPDATE & DELETE) ---

# Patient: Update Profile
@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session: return redirect(url_for('login_page'))

    new_nhs = request.form['nhs_number']
    conn = get_db()
    conn.execute('UPDATE patients SET nhs_number = ? WHERE id = ?', (new_nhs, session['user_id']))
    conn.commit()
    conn.close()

    flash('Profile updated!')
    return redirect(url_for('dashboard'))


# Patient: Delete Account
@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'user_id' not in session: return redirect(url_for('login_page'))

    conn = get_db()
    conn.execute('DELETE FROM patients WHERE id = ?', (session['user_id'],))
    conn.commit()
    conn.close()

    session.clear()
    flash('Account deleted.')
    return redirect(url_for('home'))


# Doctor: Update Risk Level
@app.route('/update_risk', methods=['POST'])
def update_risk():
    if session.get('role') != 'doctor': return redirect(url_for('login_page'))

    patient_id = request.form['patient_id']
    new_risk = request.form['risk_level']

    conn = get_db()
    conn.execute('UPDATE patients SET risk_level = ? WHERE id = ?', (new_risk, patient_id))
    conn.commit()
    conn.close()

    flash('Patient risk updated.')
    return redirect(url_for('doctor_dashboard'))


# Admin: Delete User
@app.route('/admin_delete_user', methods=['POST'])
def admin_delete_user():
    if session.get('role') != 'admin': return redirect(url_for('login_page'))

    user_id_to_delete = request.form['user_id']

    conn = get_db()
    conn.execute('DELETE FROM patients WHERE id = ?', (user_id_to_delete,))
    conn.commit()
    conn.close()

    flash('User removed from system.')
    return redirect(url_for('admin_dashboard'))


if __name__ == '__main__':
    app.run(debug=True)