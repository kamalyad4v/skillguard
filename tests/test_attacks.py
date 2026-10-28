import unittest
from engine.attacks.sqli import SQLiAttack
from engine.attacks.xss import XSSAttack
from engine.attacks.dirbuster import DirBusterAttack
from engine.attacks.csrf import CSRFAttack
from engine.attacks.auth_brute import AuthBruteAttack


class TestAttackModulesDetailed(unittest.TestCase):
    def setUp(self):
        self.target = "http://127.0.0.1:8000"
        self.domain = "127.0.0.1"

    def test_dirbuster_wordlist_loading(self):
        dirbuster = DirBusterAttack(self.target, self.domain)
        dirs = dirbuster._load_wordlist("dirs.txt", dirbuster.DEFAULT_DIRS)
        self.assertGreater(len(dirs), 0)
        # Should load entries from wordlists/dirs.txt
        self.assertIn("admin", dirs)
        self.assertIn("api", dirs)

    def test_auth_brute_wordlist_loading(self):
        auth_brute = AuthBruteAttack(self.target, self.domain)
        passwords = auth_brute._load_wordlist("passwords.txt", auth_brute.DEFAULT_PASSWORDS)
        self.assertGreater(len(passwords), 0)
        # Should load entries from wordlists/passwords.txt
        self.assertIn("admin", passwords)
        self.assertIn("password", passwords)

    def test_csrf_form_parsing_with_token(self):
        csrf = CSRFAttack(self.target, self.domain)
        html = '''
        <form method="POST" action="/transfer">
            <input type="hidden" name="csrf_token" value="abc123xyz">
            <input type="text" name="amount">
            <input type="submit" value="Send">
        </form>
        '''
        forms = csrf._parse_forms(html)
        self.assertEqual(len(forms), 1)
        self.assertTrue(forms[0]["has_csrf_token"])
        self.assertTrue(forms[0]["is_state_changing"])

    def test_csrf_form_parsing_without_token(self):
        csrf = CSRFAttack(self.target, self.domain)
        html = '''
        <form method="POST" action="/update-password">
            <input type="password" name="password">
            <input type="submit" value="Change">
        </form>
        '''
        forms = csrf._parse_forms(html)
        self.assertEqual(len(forms), 1)
        self.assertFalse(forms[0]["has_csrf_token"])
        self.assertTrue(forms[0]["is_state_changing"])

    def test_sqli_error_patterns_matching(self):
        sqli = SQLiAttack(self.target, self.domain)
        mysql_error = "You have an error in your SQL syntax near '1' at line 1"
        postgres_error = "ERROR: syntax error at or near 'SELECT'"
        clean_text = "Profile updated successfully."

        matched_mysql = any(
            re_pattern for re_pattern, db in sqli.SQL_ERROR_PATTERNS
            if db == "MySQL" and __import__("re").search(re_pattern, mysql_error)
        )
        matched_pg = any(
            re_pattern for re_pattern, db in sqli.SQL_ERROR_PATTERNS
            if db == "PostgreSQL" and __import__("re").search(re_pattern, postgres_error)
        )
        matched_clean = any(
            re_pattern for re_pattern, _ in sqli.SQL_ERROR_PATTERNS
            if __import__("re").search(re_pattern, clean_text)
        )

        self.assertTrue(matched_mysql)
        self.assertTrue(matched_pg)
        self.assertFalse(matched_clean)

    def test_xss_reflection_validation(self):
        xss = XSSAttack(self.target, self.domain)
        marker = "sgxss12345"
        payload = f"<script>alert('{marker}')</script>"
        clean_reflected = f"&lt;script&gt;alert('{marker}')&lt;/script&gt;"
        raw_reflected = f"Search query: {payload}"

        self.assertTrue(xss._is_reflected(raw_reflected, marker, payload))
        self.assertFalse(xss._is_reflected(clean_reflected, marker, payload))

    def test_xss_injection_points_fallback_on_bare_url(self):
        xss = XSSAttack("https://example.com", "example.com")
        points = xss._get_injection_points(context={})
        self.assertGreater(len(points), 0)
        point_names = [p["name"] for p in points]
        self.assertIn("q", point_names)
        self.assertIn("search", point_names)

    def test_sqli_injection_points_fallback_on_bare_url(self):
        sqli = SQLiAttack("https://example.com", "example.com")
        points = sqli._get_injection_points(context={})
        self.assertGreater(len(points), 0)
        point_names = [p["name"] for p in points]
        self.assertIn("id", point_names)
        self.assertIn("user", point_names)


if __name__ == "__main__":
    unittest.main()
