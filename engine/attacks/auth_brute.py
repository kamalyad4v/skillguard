import requests
import re
import time
import os


class AuthBruteAttack:
    """Login form discovery and authentication brute-force testing."""

    NAME = "auth_brute"
    DESCRIPTION = "Authentication Brute-Force Testing"

    DEFAULT_USERNAMES = [
        "admin", "administrator", "root", "user", "test", "demo", "guest",
    ]

    DEFAULT_PASSWORDS = [
        "password", "123456", "admin", "12345678", "qwerty",
        "abc123", "letmein", "welcome", "monkey", "dragon",
        "master", "login", "princess", "passw0rd", "shadow",
        "password1", "admin123", "root", "toor", "test",
    ]

    LOGIN_PATHS = [
        "/login", "/signin", "/sign-in", "/auth", "/authenticate",
        "/wp-login.php", "/admin/login", "/user/login", "/account/login",
        "/admin", "/portal", "",
    ]

    FAILURE_INDICATORS = [
        "invalid", "incorrect", "wrong", "failed", "error",
        "denied", "unauthorized", "bad credentials", "try again",
        "does not match", "not found", "authentication failed",
    ]

    SUCCESS_INDICATORS = [
        "welcome", "dashboard", "logout", "my account",
        "profile", "settings", "logged in", "session",
    ]

    LOCKOUT_INDICATORS = [
        "locked", "blocked", "too many", "rate limit",
        "captcha", "try later", "temporarily", "exceeded",
    ]

    def __init__(self, base_url: str, domain: str, session: requests.Session = None):
        self.base_url = base_url
        self.domain = domain
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": "SkillGuard-PenTest/1.0"})
        self.findings = []

    def _load_wordlist(self, filename: str, default: list) -> list:
        wordlist_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "wordlists", filename)
        )
        if os.path.exists(wordlist_path):
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                return [
                    line.strip() for line in f
                    if line.strip() and not line.startswith("#")
                ]
        return default

    def _discover_login_forms(self, context: dict = None) -> list[dict]:
        """Heuristically find login forms by looking for password-type inputs."""
        login_forms = []
        paths_to_check = list(self.LOGIN_PATHS)

        if context and "discovered_paths" in context:
            for p in context["discovered_paths"]:
                if p not in paths_to_check:
                    paths_to_check.append(p)

        for path in paths_to_check:
            url = self.base_url + ("/" + path.lstrip("/") if not path.startswith("/") else path)
            try:
                resp = self.session.get(url, timeout=8)
                if resp.status_code != 200:
                    continue

                # Must have a password field
                if not re.search(
                    r'type=["\']password["\']', resp.text, re.IGNORECASE
                ):
                    continue

                form_matches = re.findall(
                    r"<form([^>]*)>(.*?)</form>", resp.text, re.DOTALL | re.IGNORECASE
                )

                for attrs, body in form_matches:
                    if not re.search(r'type=["\']password["\']', body, re.IGNORECASE):
                        continue

                    action_match = re.search(
                        r'action=["\']([^"\']*)["\']', attrs, re.IGNORECASE
                    )
                    method_match = re.search(
                        r'method=["\'](\w+)["\']', attrs, re.IGNORECASE
                    )

                    action = action_match.group(1) if action_match else path
                    method = method_match.group(1).upper() if method_match else "POST"

                    if not action.startswith("http"):
                        action = self.base_url + "/" + action.lstrip("/")

                    # Find username and password field names
                    username_field = None
                    password_field = None

                    for inp in re.findall(r"<input\b([^>]*)>", body, re.IGNORECASE):
                        name_match = re.search(
                            r'name=["\']([^"\']+)["\']', inp, re.IGNORECASE
                        )
                        type_match = re.search(
                            r'type=["\']([^"\']+)["\']', inp, re.IGNORECASE
                        )
                        if not name_match:
                            continue
                        name = name_match.group(1)
                        input_type = type_match.group(1).lower() if type_match else "text"

                        if input_type == "password":
                            password_field = name
                        elif input_type in ["text", "email"] and not username_field:
                            username_field = name

                    if password_field:
                        login_forms.append({
                            "url": url,
                            "action": action,
                            "method": method,
                            "username_field": username_field or "username",
                            "password_field": password_field,
                        })
                        break  # One form per page is enough

            except requests.RequestException:
                continue

        return login_forms

    def _detect_lockout(
        self, action_url: str, username_field: str, password_field: str
    ) -> bool:
        """Send a few bad login attempts to detect account lockout mechanisms."""
        for _ in range(3):
            try:
                resp = self.session.post(
                    action_url,
                    data={
                        username_field: "lockout_test_user_xyz",
                        password_field: "wrong_password_xyz",
                    },
                    timeout=8,
                )
                text = resp.text.lower()
                if any(word in text for word in self.LOCKOUT_INDICATORS):
                    return True
            except requests.RequestException:
                pass
            time.sleep(0.3)
        return False

    def _attempt_login(
        self,
        action_url: str,
        username_field: str,
        password_field: str,
        username: str,
        password: str,
    ) -> dict | None:
        """Attempt a single login and heuristically determine success or failure."""
        try:
            resp = self.session.post(
                action_url,
                data={username_field: username, password_field: password},
                timeout=10,
                allow_redirects=True,
            )

            text = resp.text.lower()
            has_success = any(ind in text for ind in self.SUCCESS_INDICATORS)
            has_failure = any(ind in text for ind in self.FAILURE_INDICATORS)

            if has_success and not has_failure:
                return {
                    "rule": "AUTH_WEAK_CREDS",
                    "description": f"Successful login with credentials {username}:{password}",
                    "severity": "HIGH",
                    "username": username,
                    "password": password,
                    "url": action_url,
                }

            # Check redirect-after-login pattern
            if resp.history and resp.url != action_url:
                final_text = resp.text.lower()
                if not has_failure and any(
                    ind in final_text for ind in self.SUCCESS_INDICATORS
                ):
                    return {
                        "rule": "AUTH_WEAK_CREDS",
                        "description": (
                            f"Successful login with credentials {username}:{password} "
                            f"(redirected to {resp.url})"
                        ),
                        "severity": "HIGH",
                        "username": username,
                        "password": password,
                        "url": action_url,
                        "redirect": resp.url,
                    }

        except requests.RequestException:
            pass
        return None

    def run(self, context: dict = None) -> list[dict]:
        """Run authentication brute-force testing."""
        self.findings = []

        login_forms = self._discover_login_forms(context)

        if not login_forms:
            self.findings.append({
                "rule": "AUTH_NO_LOGIN",
                "description": (
                    "No login forms discovered — authentication brute-force testing skipped"
                ),
                "severity": "INFO",
            })
            return self.findings

        for form in login_forms:
            self.findings.append({
                "rule": "AUTH_LOGIN_FOUND",
                "description": (
                    f"Login form discovered at {form['url']} — "
                    f"fields: {form['username_field']}, {form['password_field']}"
                ),
                "severity": "INFO",
                "url": form["url"],
            })

            # Check for lockout before brute-forcing
            has_lockout = self._detect_lockout(
                form["action"], form["username_field"], form["password_field"]
            )

            if has_lockout:
                self.findings.append({
                    "rule": "AUTH_LOCKOUT_EXISTS",
                    "description": (
                        f"Account lockout mechanism detected on {form['url']} — "
                        f"brute-force resistance present"
                    ),
                    "severity": "INFO",
                })
                continue  # Respect lockout, don't brute-force

            self.findings.append({
                "rule": "AUTH_NO_LOCKOUT",
                "description": (
                    f"No account lockout mechanism detected on {form['url']} — "
                    f"unlimited login attempts possible"
                ),
                "severity": "MEDIUM",
            })

            # Load credentials
            usernames = self._load_wordlist("usernames.txt", self.DEFAULT_USERNAMES)
            passwords = self._load_wordlist("passwords.txt", self.DEFAULT_PASSWORDS)

            # Test common credential combos (capped)
            tested = 0
            max_attempts = 50

            for username in usernames:
                if tested >= max_attempts:
                    break
                for password in passwords:
                    if tested >= max_attempts:
                        break
                    result = self._attempt_login(
                        form["action"],
                        form["username_field"],
                        form["password_field"],
                        username,
                        password,
                    )
                    if result:
                        self.findings.append(result)
                    tested += 1
                    time.sleep(0.2)  # Rate-limit ourselves

        return self.findings
