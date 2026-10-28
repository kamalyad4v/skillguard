import requests
import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse


class DirBusterAttack:
    """Directory and subdomain brute-forcing with concurrent requests and false-positive filtering."""

    NAME = "dirbuster"
    DESCRIPTION = "Directory & Subdomain Brute-Force"

    # Fallback if wordlist file is missing
    DEFAULT_DIRS = [
        "admin", "administrator", "wp-admin", "login", "dashboard",
        "panel", "cpanel", "phpmyadmin", "api", "api/v1", "api/v2",
        "backup", "backups", "db", "database", "config", "conf",
        "debug", "test", "staging", "dev", "old", "temp", "tmp",
        "upload", "uploads", "files", "static", "assets", "media",
        "docs", "private", "secret", "hidden", "internal", "console",
        ".htaccess", ".htpasswd", "robots.txt", "sitemap.xml",
        "wp-content", "wp-includes", "wp-login.php", "xmlrpc.php",
        "server-status", "server-info", ".DS_Store", "swagger",
        "swagger-ui", "graphql", "graphiql", "health", "status",
        "info", "metrics", ".git", ".svn", "vendor", "node_modules",
        "package.json", "composer.json", ".env",
    ]

    DEFAULT_SUBDOMAINS = [
        "www", "mail", "ftp", "webmail", "smtp", "pop",
        "ns1", "ns2", "dns", "mx", "cdn", "api",
        "dev", "staging", "test", "beta", "admin",
        "portal", "vpn", "remote", "git", "blog",
        "shop", "store", "app", "mobile", "m",
        "docs", "wiki", "support", "help", "forum",
        "dashboard", "panel", "secure", "login", "auth",
        "sso", "id", "accounts", "intranet", "internal",
        "jenkins", "ci", "jira", "grafana", "monitor", "status",
    ]

    # High-value paths that deserve HIGH severity
    HIGH_VALUE_PATHS = {
        "admin", "administrator", "phpmyadmin", ".git", ".git/config",
        ".env", "debug", "console", "server-status", "server-info",
        ".htpasswd", "wp-config.php", "backup", "database",
    }

    def __init__(self, base_url: str, domain: str, session: requests.Session = None):
        self.base_url = base_url
        self.domain = domain
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": "SkillGuard-PenTest/1.0"})
        self.findings = []
        self._soft_404_signature = None

    def _load_wordlist(self, filename: str, default: list) -> list:
        """Load wordlist from file, falling back to built-in defaults."""
        wordlist_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "wordlists", filename)
        )
        if os.path.exists(wordlist_path):
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("#")]
        return default

    def _detect_soft_404(self):
        """Fingerprint the custom 404 page to filter false positives later."""
        try:
            resp = self.session.get(
                f"{self.base_url}/skillguard-nonexistent-path-xyz789",
                timeout=5,
                allow_redirects=False,
            )
            if resp.status_code == 200:
                self._soft_404_signature = len(resp.text)
        except requests.RequestException:
            pass

    def _check_path(self, path: str) -> dict | None:
        """Probe a single path and return a finding if it's interesting."""
        url = f"{self.base_url}/{path}"
        try:
            resp = self.session.get(url, timeout=5, allow_redirects=False)

            if resp.status_code in [404, 410, 500, 502, 503]:
                return None

            # Filter soft 404s
            if resp.status_code == 200 and self._soft_404_signature:
                if abs(len(resp.text) - self._soft_404_signature) < 100:
                    return None

            if resp.status_code == 200:
                severity = "HIGH" if path in self.HIGH_VALUE_PATHS else "MEDIUM"
                return {
                    "rule": "DIR_FOUND",
                    "description": (
                        f"Accessible path discovered: /{path} "
                        f"(HTTP {resp.status_code}, {len(resp.text)} bytes)"
                    ),
                    "severity": severity,
                    "path": f"/{path}",
                    "status_code": resp.status_code,
                }
            elif resp.status_code == 403:
                return {
                    "rule": "DIR_FORBIDDEN",
                    "description": (
                        f"Forbidden but existing path: /{path} (HTTP 403) — "
                        f"path exists but access denied"
                    ),
                    "severity": "LOW",
                    "path": f"/{path}",
                    "status_code": 403,
                }
            elif resp.status_code in [301, 302]:
                location = resp.headers.get("Location", "unknown")
                return {
                    "rule": "DIR_REDIRECT",
                    "description": (
                        f"Path /{path} redirects to {location} — "
                        f"may indicate protected resource"
                    ),
                    "severity": "LOW",
                    "path": f"/{path}",
                    "status_code": resp.status_code,
                    "redirect_to": location,
                }

        except requests.RequestException:
            return None
        return None

    def _check_subdomain(self, subdomain: str) -> dict | None:
        """Check if a subdomain resolves and is reachable."""
        fqdn = f"{subdomain}.{self.domain}"
        try:
            ip = socket.gethostbyname(fqdn)

            # Try to reach it
            status = None
            for scheme in ["https", "http"]:
                try:
                    resp = requests.get(
                        f"{scheme}://{fqdn}", timeout=5, allow_redirects=False
                    )
                    status = resp.status_code
                    break
                except requests.RequestException:
                    continue

            return {
                "rule": "SUBDOMAIN_FOUND",
                "description": (
                    f"Live subdomain discovered: {fqdn} → {ip}"
                    + (f" (HTTP {status})" if status else "")
                ),
                "severity": "INFO",
                "subdomain": fqdn,
                "ip": ip,
                "status_code": status,
            }
        except socket.gaierror:
            return None

    def brute_directories(self) -> list[dict]:
        """Brute-force directories with concurrent requests."""
        findings = []
        self._detect_soft_404()
        dirs = self._load_wordlist("dirs.txt", self.DEFAULT_DIRS)

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self._check_path, d): d for d in dirs}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    findings.append(result)

        return findings

    def brute_subdomains(self) -> list[dict]:
        """Enumerate subdomains via DNS brute-force."""
        findings = []
        subdomains = self.DEFAULT_SUBDOMAINS  # Use built-in list

        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = {executor.submit(self._check_subdomain, s): s for s in subdomains}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    findings.append(result)

        return findings

    def run(self, context: dict = None) -> list[dict]:
        """Run directory and subdomain brute-force."""
        self.findings = []
        self.findings.extend(self.brute_directories())
        self.findings.extend(self.brute_subdomains())

        if not self.findings:
            self.findings.append({
                "rule": "DIRBUST_NONE",
                "description": "No additional directories or subdomains discovered",
                "severity": "INFO",
            })

        return self.findings
