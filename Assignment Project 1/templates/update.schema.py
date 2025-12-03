import sqlite3

DATABASE = 'database.db'


def add_doctor_column():
    print("--- UPDATING DATABASE SCHEMA ---")
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Add doctor_id column to appointments table
        cursor.execute("ALTER TABLE appointments ADD COLUMN doctor_id INTEGER")

        conn.commit()
        conn.close()
        print("SUCCESS: 'doctor_id' column added to appointments table.")
    except sqlite3.OperationalError as e:
        print(f"NOTE: {e} (This likely means the column already exists, which is fine.)")


if __name__ == "__main__":
    add_doctor_column()