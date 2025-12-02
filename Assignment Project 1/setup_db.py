import sqlite3
import pandas as pd
from werkzeug.security import generate_password_hash


def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # 1. DROP old tables to ensure clean schema
    cursor.execute('DROP TABLE IF EXISTS patients')
    cursor.execute('DROP TABLE IF EXISTS appointments')

    # 2. CREATE patients table with MEDICAL DATA columns
    cursor.execute('''
        CREATE TABLE patients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fullname TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            nhs_number TEXT,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'patient',

            -- Medical Data for Risk Calculation
            age INTEGER DEFAULT 0,
            gender TEXT DEFAULT 'Other',
            hypertension INTEGER DEFAULT 0,
            heart_disease INTEGER DEFAULT 0,
            avg_glucose_level REAL DEFAULT 0.0,
            bmi REAL DEFAULT 0.0,
            smoking_status TEXT DEFAULT 'Unknown',
            stroke_risk_score INTEGER DEFAULT 0
        )
    ''')

    # 3. CREATE appointments table
    cursor.execute('''
        CREATE TABLE appointments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER,
            appointment_date TEXT,
            reason TEXT,
            status TEXT DEFAULT 'Pending'
        )
    ''')

    # 4. SEED: Admin & Doctor Accounts
    # Admin: admin@ltu.ac.uk / Admin123!
    admin_pw = generate_password_hash('Admin123!', method='pbkdf2:sha256')
    cursor.execute('''INSERT INTO patients (fullname, email, nhs_number, password_hash, role) 
                      VALUES (?, ?, ?, ?, ?)''',
                   ('System Administrator', 'admin@ltu.ac.uk', '0000000000', admin_pw, 'admin'))

    # Doctor: dr.sterling@ltu.ac.uk / Doctor123!
    doc_pw = generate_password_hash('Doctor123!', method='pbkdf2:sha256')
    cursor.execute('''INSERT INTO patients (fullname, email, nhs_number, password_hash, role) 
                      VALUES (?, ?, ?, ?, ?)''',
                   ('Dr. Alistair Sterling', 'dr.sterling@ltu.ac.uk', 'GMC12345', doc_pw, 'doctor'))

    # 5. IMPORT CSV with Medical Data
    try:
        df = pd.read_csv('patients.csv')
        df.columns = df.columns.str.strip().str.lower()

        # Helper to safely get value or return default if column missing
        def get_val(row, col, default):
            return row[col] if col in row else default

        print("Importing data from CSV...")

        for index, row in df.iterrows():
            # Generate dummy email/pass since CSV doesn't have them
            fake_email = f"patient{index + 1}@test.com"
            hashed_pw = generate_password_hash("Password123!", method='pbkdf2:sha256')

            # Basic Risk Calculation for initial load
            risk = 0
            if get_val(row, 'age', 0) > 60: risk += 20
            if get_val(row, 'hypertension', 0) == 1: risk += 15
            if get_val(row, 'heart_disease', 0) == 1: risk += 15
            if get_val(row, 'avg_glucose_level', 0) > 200: risk += 10

            # Handle BMI 'N/A' string in dataset
            bmi_val = get_val(row, 'bmi', 0)
            if str(bmi_val).strip() == 'N/A':
                bmi_val = 0
            elif float(bmi_val) > 30:
                risk += 10

            if get_val(row, 'smoking_status', '') == 'smokes': risk += 20
            if get_val(row, 'stroke', 0) == 1: risk = 100

            try:
                cursor.execute('''
                    INSERT INTO patients (fullname, email, nhs_number, password_hash, role, 
                                          age, gender, hypertension, heart_disease, 
                                          avg_glucose_level, bmi, smoking_status, stroke_risk_score)
                    VALUES (?, ?, ?, ?, 'patient', ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (f"Patient {row['id']}", fake_email, str(row['id']), hashed_pw,
                      get_val(row, 'age', 0), get_val(row, 'gender', 'Other'),
                      get_val(row, 'hypertension', 0), get_val(row, 'heart_disease', 0),
                      get_val(row, 'avg_glucose_level', 0), bmi_val,
                      get_val(row, 'smoking_status', 'Unknown'), risk))
            except Exception as e:
                pass  # Skip duplicates or errors

        print("✅ Database initialized successfully!")
        print("   -> Admin Login: admin@ltu.ac.uk / Admin123!")
        print("   -> Doctor Login: dr.sterling@ltu.ac.uk / Doctor123!")
        print("   -> Test Patient: patient1@test.com / Password123!")

    except FileNotFoundError:
        print("⚠️ 'patients.csv' not found. Created empty DB with Admin/Doctor only.")

    conn.commit()
    conn.close()


if __name__ == '__main__':
    init_db()