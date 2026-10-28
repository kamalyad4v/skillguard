import requests
import re


class CSRFAttack:
    """CSRF vulnerability detection — form analysis, token validation, and cookie checks."""

    NAME = "csrf"
    DESCRIPTION = "Cross-Site Request Forgery (CSRF) Detection"

    CSRF_TOKEN_PATTERNS = [
        r'name=["\']csrf[_-]?token["\']',
        r'name=["\']_token["\']',
        r'name=["\']authenticity_token["\']',
        r'name=["\']__RequestVerificationToken["\']',
        r'name=["\']csrfmiddlewaretoken["\']',
        r'name=["\']_csrf["\']',
        r'name=["\']nonce["\']',
        r'name=["\']anti[-_]?forgery["\']',
        r'name=["\']__VIEWSTATE["\']',
    ]

    def __init__(self, base_url: str, domain: str, session: requests.Session = None):
        self.base_url = base_url
        self.domain = domain
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": "SkillGuard-PenTest/1.0"})
        self.findings = []

    def _parse_forms(self, html: str) -> list[dict]:
        """Extract forms from HTML with method, action, fields, and CSRF token info."""
        forms = []
        form_blocks = re.findall(
            r"<form([^>]*)>(.*?)</form>", html, re.DOTALL | re.IGNORECASE
        )
        for attrs, body in form_blocks:
            method_match = re.search(r'method=["\'](\w+)["\']', attrs, re.IGNORECASE)
            action_match = re.search(r'action=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            method = method_match.group(1).upper() if method_match else "GET"
            action = action_match.group(1) if action_match else ""

            has_csrf_token = any(
                re.search(p, body, re.IGNORECASE) for p in self.CSRF_TOKEN_PATTERNS
            )

            hidden_fields = re.findall(
                r'<input[^>]+type=["\']hidden["\'][^>]*>', body, re.IGNORECASE
            )

            fields = []
            for tag in re.findall(r"<input\b([^>]*)>", body, re.IGNORECASE):
                name_match = re.search(r'name=["\']([^"\']+)["\']', tag, re.IGNORECASE)
                type_match = re.search(r'type=["\']([^"\']+)["\']', tag, re.IGNORECASE)
                if name_match:
                    fields.append({
                        "name": name_match.group(1),
                        "type": type_match.group(1).lower() if type_match else "text",
                    })

            forms.append({
                "method": method,
                "action": action,
                "has_csrf_token": has_csrf_token,
                "hidden_field_count": len(hidden_fields),
                "fields": fields,
                "is_state_changing": method in ["POST", "PUT", "DELETE", "PATCH"],
            })

        return forms

    def _check_samesite_cookies(self) -> list[dict]:
        """Check if cookies have the SameSite attribute set."""
        findings = []
        try:
            resp = self.session.get(self.base_url, timeout=10)
            raw_cookies = resp.headers.get("Set-Cookie", "")

            if not raw_cookies:
                return findings

            # Handle multiple Set-Cookie headers
            if hasattr(resp.raw.headers, "getlist"):
                cookies_raw = resp.raw.headers.getlist("Set-Cookie")
            else:
                cookies_raw = [raw_cookies]

            for cookie in cookies_raw:
                cookie_name = cookie.split("=")[0].strip()
                cookie_lower = cookie.lower()
                has_samesite = "samesite" in cookie_lower

                if not has_samesite:
                    findings.append({
                        "rule": "CSRF_COOKIE",
                        "description": (
                            f"Cookie '{cookie_name}' missing SameSite attribute — "
                            f"vulnerable to cross-site request forgery"
                        ),
                        "severity": "MEDIUM",
                        "cookie": cookie_name,
                    })
                elif "samesite=none" in cookie_lower:
                    findings.append({
                        "rule": "CSRF_COOKIE_NONE",
                        "description": (
                            f"Cookie '{cookie_name}' has SameSite=None — "
                            f"provides no CSRF protection"
                        ),
                        "severity": "MEDIUM",
                        "cookie": cookie_name,
                    })

        except requests.RequestException:
            pass

        return findings

    def _check_forms_for_csrf(self, context: dict = None) -> list[dict]:
        """Analyze all forms for CSRF protection and test token enforcement."""
        findings = []
        urls_to_check = [self.base_url]
        if context and "discovered_paths" in context:
            for p in context["discovered_paths"][:5]:  # sample top discovered paths
                urls_to_check.append(
                    self.base_url + ("/" + p.lstrip("/") if not p.startswith("/") else p)
                )

        seen_forms = set()
        for page_url in urls_to_check:
            try:
                resp = self.session.get(page_url, timeout=8)
                forms = self._parse_forms(resp.text)

                for i, form in enumerate(forms):
                    field_names = [f["name"] for f in form["fields"]]
                    form_key = (form["action"], tuple(sorted(field_names)))
                    if form_key in seen_forms:
                        continue
                    seen_forms.add(form_key)

                    if form["is_state_changing"] and not form["has_csrf_token"]:
                        has_password = any(f["type"] == "password" for f in form["fields"])
                        severity = "HIGH" if has_password else "MEDIUM"
                        desc = (
                            f"State-changing form ({form['method']}) at {page_url} with fields {field_names} "
                            f"has no CSRF token"
                        )
                        if has_password:
                            desc += " — contains password field, login CSRF possible"

                        findings.append({
                            "rule": "CSRF_NO_TOKEN",
                            "description": desc,
                            "severity": severity,
                            "form_index": i,
                            "url": page_url,
                            "method": form["method"],
                            "action": form["action"],
                            "fields": field_names,
                        })

                    elif form["is_state_changing"] and form["has_csrf_token"]:
                        # Try submitting without the CSRF token to see if it's validated
                        action_url = form["action"]
                        if not action_url or not action_url.startswith("http"):
                            action_url = (
                                self.base_url + "/" + action_url.lstrip("/")
                                if action_url
                                else self.base_url
                            )

                        form_data = {}
                        for field in form["fields"]:
                            is_token = any(
                                re.search(p, f'name="{field["name"]}"', re.IGNORECASE)
                                for p in self.CSRF_TOKEN_PATTERNS
                            )
                            if not is_token:
                                form_data[field["name"]] = "skillguard_test"

                        try:
                            test_resp = self.session.post(
                                action_url, data=form_data, timeout=8, allow_redirects=False
                            )
                            if test_resp.status_code in [200, 301, 302]:
                                findings.append({
                                    "rule": "CSRF_TOKEN_NOT_VALIDATED",
                                    "description": (
                                        f"CSRF token present on {page_url} but not validated — form accepted "
                                        f"submission without token (HTTP {test_resp.status_code})"
                                    ),
                                    "severity": "HIGH",
                                    "form_index": i,
                                    "url": page_url,
                                    "method": form["method"],
                                    "action": form["action"],
                                })
                        except requests.RequestException:
                            pass

            except requests.RequestException:
                pass

        return findings

    def run(self, context: dict = None) -> list[dict]:
        """Run all CSRF detection checks."""
        self.findings = []
        self.findings.extend(self._check_forms_for_csrf(context))
        self.findings.extend(self._check_samesite_cookies())

        if not self.findings:
            self.findings.append({
                "rule": "CSRF_NONE",
                "description": "No CSRF vulnerabilities detected — forms appear to have proper token protection",
                "severity": "INFO",
            })

        return self.findings
