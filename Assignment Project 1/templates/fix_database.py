import sqlite3

DATABASE = 'database.db'


def rebuild_appointments_table():
    print(f"--- REPAIRING DATABASE: {DATABASE} ---")
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # 1. Check if table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='appointments'")
        table_exists = cursor.fetchone()

        if not table_exists:
            print(">>> WARNING: Table 'appointments' is missing. Creating it now...")
            cursor.execute('''
                CREATE TABLE appointments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    patient_id INTEGER,
                    doctor_id INTEGER,
                    appointment_date TEXT,
                    reason TEXT,
                    status TEXT DEFAULT 'Pending'
                )
            ''')
            print(">>> SUCCESS: Created 'appointments' table with 'doctor_id' column.")

        else:
            # 2. If table exists, check for the column
            cursor.execute("PRAGMA table_info(appointments)")
            columns = [info[1] for info in cursor.fetchall()]

            if 'doctor_id' not in columns:
                print(">>> FIXING: Table exists but missing 'doctor_id'. Adding it...")
                cursor.execute("ALTER TABLE appointments ADD COLUMN doctor_id INTEGER")
                print(">>> SUCCESS: Column added.")
            else:
                print(">>> CHECK: Database structure is correct.")

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"CRITICAL ERROR: {e}")


if __name__ == "__main__":
    rebuild_appointments_table()