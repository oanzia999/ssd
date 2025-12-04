\# LTU Health - Secure Stroke Prediction System



\*\*Module:\*\* COM7033 Secure Software Development  

\*\*Author:\*\* 2504886  

\*\*Date:\*\* 2025



---



\## 📖 Project Overview

The \*\*LTU Health System\*\* is a secure web application designed to manage patient medical records and predict stroke risk. 



It implements a \*\*Hybrid Polyglot Architecture\*\*, utilizing \*\*SQLite\*\* for high-speed, transactional authentication and \*\*MongoDB\*\* for flexible, scalable medical record storage. This design enforces a separation of concerns, ensuring that a compromise in the authentication layer does not grant direct access to sensitive medical data.



\### 🛡️ Key Security Features

1\.  \*\*Hybrid Database Architecture:\*\* \* \*\*SQLite (`auth.db`)\*\*: Stores user credentials (hashed).

&nbsp;   \* \*\*MongoDB (`ltu\_health\_records`)\*\*: Stores patient medical profiles.

2\.  \*\*Encryption at Rest:\*\* All Personally Identifiable Information (PII) such as Names and NHS Numbers are encrypted using \*\*Fernet (AES-128)\*\* before being stored in MongoDB.

3\.  \*\*Role-Based Access Control (RBAC):\*\* Strict separation between Patient, Doctor, and Admin dashboards.

4\.  \*\*Audit Logging:\*\* All sensitive actions (Login, View Records, Update Profile) are immutably logged to the database for non-repudiation.

5\.  \*\*Brute Force Protection:\*\* Rate limiting (10 requests/minute) applied to login endpoints via `Flask-Limiter`.

6\.  \*\*Input Sanitization:\*\* All user inputs are scrubbed using `Bleach` to prevent Cross-Site Scripting (XSS).

7\.  \*\*CSRF Protection:\*\* All forms utilize secure tokens to prevent Cross-Site Request Forgery.



---



\## ⚙️ Installation Instructions



\### Prerequisites

\* \*\*Python 3.8+\*\*

\* \*\*MongoDB Community Server\*\* (Must be installed and running on `localhost:27017`)



\### Step 1: Setup Environment

Open your terminal in the project folder and install the dependencies:



```bash

pip install -r requirements.txt

