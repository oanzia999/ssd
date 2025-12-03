import sqlite3
import pandas as pd
from pymongo import MongoClient
from werkzeug.security import generate_password_hash
from cryptography.fernet import Fernet
from faker import Faker  # NEW LIBRARY
import os

# --- CONFIGURATION ---
SQLITE_DB = 'auth.db'
MONGO_URI = "mongodb://localhost:27017/"
MONGO_DB_NAME = "ltu_health_records"
DATA_FILE = "health_data.csv"  # Your file name
KEY_FILE = "secret.key"

# Initialize Faker for AI names
fake = Faker()


# --- ENCRYPTION SETUP ---
def load_or_generate_key():
    if os.path.exists(KEY_FILE):
        return open(KEY_FILE, "rb").read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
        return key


cipher = Fernet(load_or_generate_key())


def encrypt_data(text):
    if not text: return None
    return cipher.encrypt(str(text).encode()).decode()


def setup_databases():
    print("--- STARTING SMART HYBRID MIGRATION ---")

    # 1. SETUP SQLITE (Authentication)
    if os.path.exists(SQLITE_DB):
        try:
            os.remove(SQLITE_DB)
        except PermissionError:
            print(f"!!! ERROR: Close DB Browser/App first.");
            return

    conn = sqlite3.connect(SQLITE_DB)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            original_id INTEGER
        )
    ''')
    print(">>> SQLite 'users' table created.")

    # 2. SETUP MONGODB (Data)
    client = MongoClient(MONGO_URI)
    try:
        client.admin.command('ping')
    except Exception as e:
        print(f"!!! MongoDB Error: {e}"); return

    client.drop_database(MONGO_DB_NAME)
    mongo_db = client[MONGO_DB_NAME]
    patients_col = mongo_db['patients']
    print(">>> MongoDB ready.")

    # 3. CREATE DOCTORS & ADMIN
    # Different passwords for Doctor and Admin
    doctor_pw = generate_password_hash('Doctor123!', method='pbkdf2:sha256')
    admin_pw = generate_password_hash('Admin123!', method='pbkdf2:sha256')  # UPDATED

    staff = [
        ("Dr. Alistair Sterling", "dr.sterling@ltu.ac.uk", "doctor"),
        ("Dr. Priya Kapoor", "dr.kapoor@ltu.ac.uk", "doctor"),
        ("Dr. Thomas Wu", "dr.thomaswu@ltu.ac.uk", "doctor"),
        ("System Admin", "admin@ltu.ac.uk", "admin")
    ]

    for name, email, role in staff:
        pw = admin_pw if role == 'admin' else doctor_pw
        cursor.execute("INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
                       (email, pw, role))

        patients_col.insert_one({
            "email": email,
            "fullname": encrypt_data(name),
            "role": role
        })

    # 4. MIGRATE PATIENTS (SMART IMPORT)
    try:
        print(f">>> Reading {DATA_FILE}...")
        # Smart Read: Try Excel, fallback to CSV
        try:
            df = pd.read_excel(DATA_FILE, engine='openpyxl')
        except:
            df = pd.read_csv(DATA_FILE)

        print(f">>> Found {len(df)} records.")
        patient_pw = generate_password_hash('Patient123!', method='pbkdf2:sha256')

        count = 0
        gen_count = 0

        for index, row in df.iterrows():
            p_id = row.get('id', index + 1)
            email = f"patient{p_id}@ltu.ac.uk"

            # --- AI NAME GENERATION LOGIC ---
            real_name = row.get('fullname')

            # Check if name is missing (NaN) or empty string
            if pd.isna(real_name) or str(real_name).strip() == "":
                gender = str(row.get('gender', 'Other')).strip().capitalize()

                if gender == 'Male':
                    fullname = fake.name_male()
                elif gender == 'Female':
                    fullname = fake.name_female()
                else:
                    fullname = fake.name()

                gen_count += 1
            else:
                fullname = real_name
            # --------------------------------

            # SQLite (Auth)
            try:
                cursor.execute("INSERT INTO users (email, password_hash, role, original_id) VALUES (?, ?, ?, ?)",
                               (email, patient_pw, 'patient', int(p_id)))
            except sqlite3.IntegrityError:
                continue

            # Clean Numeric Data
            try:
                bmi_val = float(row['bmi'])
            except:
                bmi_val = 0.0

            # MongoDB (Data)
            patient_doc = {
                "email": email,
                "fullname": encrypt_data(fullname),  # Encrypt Generated Name
                "gender": encrypt_data(row.get('gender')),
                "age": float(row.get('age', 0)),
                "hypertension": int(row.get('hypertension', 0)),
                "heart_disease": int(row.get('heart_disease', 0)),
                "ever_married": row.get('ever_married'),
                "work_type": encrypt_data(row.get('work_type')),
                "Residence_type": row.get('Residence_type'),
                "avg_glucose_level": float(row.get('avg_glucose_level', 0)),
                "bmi": bmi_val,
                "smoking_status": row.get('smoking_status'),
                "stroke_history": int(row.get('stroke', 0)),
                "role": "patient",
                "nhs_number": encrypt_data(f"NHS-{p_id}")
            }
            patients_col.insert_one(patient_doc)
            count += 1

            if count % 1000 == 0: print(f"Processed {count} patients...")

        conn.commit()
        print(f"\n>>> MIGRATION COMPLETE.")
        print(f">>> Total Patients: {count}")
        print(f">>> AI Names Generated: {gen_count} (for missing values)")
        print(f">>> Admin Password set to: Admin123!")

    except Exception as e:
        print(f"!!! MIGRATION ERROR: {e}")

    conn.close()
    client.close()


if __name__ == "__main__":
    setup_databases()