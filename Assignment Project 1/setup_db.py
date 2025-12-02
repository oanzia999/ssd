import sqlite3
import pandas as pd
from werkzeug.security import generate_password_hash


def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # 1. Reset the table to ensure we have the new 'role' column
    cursor.execute('DROP TABLE IF EXISTS patients')

    # 2. Create the table with the 'role' and 'risk_level' columns
    cursor.execute('''
        CREATE TABLE patients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fullname TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            nhs_number TEXT,
            password_hash TEXT NOT NULL,
            risk_level TEXT DEFAULT 'Low',
            role TEXT DEFAULT 'patient'
        )
    ''')

    # 3. Create Special Accounts (Admin & Doctor)
    # Admin Account
    admin_pw = generate_password_hash('Admin123!', method='pbkdf2:sha256')
    cursor.execute('''
        INSERT INTO patients (fullname, email, nhs_number, password_hash, role) 
        VALUES (?, ?, ?, ?, ?)
    ''', ('System Administrator', 'admin@ltu.ac.uk', '0000000000', admin_pw, 'admin'))

    # Doctor Account
    doc_pw = generate_password_hash('Doctor123!', method='pbkdf2:sha256')
    cursor.execute('''
        INSERT INTO patients (fullname, email, nhs_number, password_hash, role) 
        VALUES (?, ?, ?, ?, ?)
    ''', ('Dr. Alistair Sterling', 'dr.sterling@ltu.ac.uk', 'GMC12345', doc_pw, 'doctor'))

    # 4. Import regular patients from CSV
    try:
        df = pd.read_csv('patients.csv')
        # Clean up headers
        df.columns = df.columns.str.strip().str.lower()

        for index, row in df.iterrows():
            # Hash password
            hashed_pw = generate_password_hash(str(row['password']), method='pbkdf2:sha256')

            # Default role is 'patient'
            try:
                cursor.execute('''
                    INSERT INTO patients (fullname, email, nhs_number, password_hash, role)
                    VALUES (?, ?, ?, ?, 'patient')
                ''', (row['fullname'], row['email'], row['nhs_number'], hashed_pw))
            except sqlite3.IntegrityError:
                pass  # Skip duplicates

        print("✅ Database initialized successfully!")
        print("   -> Admin: admin@ltu.ac.uk / Admin123!")
        print("   -> Doctor: dr.sterling@ltu.ac.uk / Doctor123!")

    except FileNotFoundError:
        print("⚠️ 'patients.csv' not found. Database created with Admin & Doctor only.")
    except Exception as e:
        print(f"❌ Error reading CSV: {e}")

    conn.commit()
    conn.close()


if __name__ == '__main__':
    init_db()