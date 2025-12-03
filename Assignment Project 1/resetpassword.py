import sqlite3
from werkzeug.security import generate_password_hash

# Configuration
SQLITE_DB = 'auth.db'
TARGET_EMAIL = 'admin@ltu.ac.uk'
NEW_PASSWORD = 'Admin123!'


def change_password():
    print(f"--- RESETTING PASSWORD FOR {TARGET_EMAIL} ---")

    # 1. Generate new hash
    hashed_pw = generate_password_hash(NEW_PASSWORD, method='pbkdf2:sha256')

    # 2. Connect to Auth Database
    try:
        conn = sqlite3.connect(SQLITE_DB)
        cursor = conn.cursor()

        # 3. Update the password
        cursor.execute("UPDATE users SET password_hash = ? WHERE email = ?", (hashed_pw, TARGET_EMAIL))

        if cursor.rowcount > 0:
            conn.commit()
            print(f"SUCCESS: Password changed to '{NEW_PASSWORD}'")
        else:
            print("ERROR: User not found. Make sure the email is correct.")

        conn.close()

    except Exception as e:
        print(f"Database Error: {e}")


if __name__ == "__main__":
    change_password()