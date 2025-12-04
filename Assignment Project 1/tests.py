import unittest
from app import app, calculate_stroke_risk, encrypt_data, decrypt_data, clean_input

class LtuHealthTestSuite(unittest.TestCase):

    # --- 1. BUSINESS LOGIC TEST (Risk Engine) ---
    def test_risk_calculation(self):
        """Verify risk logic identifies high-risk patients correctly."""
        high_risk_patient = {
            'age': 70, 'stroke_history': 1, 'heart_disease': 1, 'smoking_status': 'smokes'
        }
        score, advice = calculate_stroke_risk(high_risk_patient)
        self.assertTrue(score > 80)
        self.assertIn("History of Stroke: High recurrence risk.", advice)
        print("[PASS] Risk Engine Logic verified.")

    # --- 2. CONFIDENTIALITY TEST (Encryption) ---
    def test_encryption(self):
        """Verify data is securely encrypted and recoverable."""
        original = "Secret Patient Name"
        encrypted = encrypt_data(original)
        self.assertNotEqual(original, encrypted) # It should look different
        decrypted = decrypt_data(encrypted)
        self.assertEqual(original, decrypted) # It should recover
        print("[PASS] Encryption Integrity verified.")

    # --- 3. INPUT SECURITY TEST (XSS) ---
    def test_sanitization(self):
        """Verify malicious scripts are stripped from input."""
        bad_input = "<script>alert('hack')</script>John"
        clean = clean_input(bad_input)
        self.assertNotIn("<script>", clean)
        print("[PASS] XSS Sanitization verified.")

    # --- 4. WEB APP AVAILABILITY TEST ---
    def test_home_page(self):
        """Verify the web server is running and serving pages."""
        tester = app.test_client(self)
        response = tester.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"LTU Health", response.data)
        print("[PASS] Web Server Availability verified.")

if __name__ == '__main__':
    print("\n--- RUNNING COMPREHENSIVE SECURITY SUITE ---\n")
    unittest.main()