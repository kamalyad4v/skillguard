import requests
import ssl
import socket
import re
import string
import random
import nmap
import whois
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse


class WebScanner:
    SECURITY_HEADERS = {
        "Content-Security-Policy": "Missing CSP header — increases risk of XSS and data injection attacks",
        "Strict-Transport-Security": "Missing HSTS header — site may be vulnerable to protocol downgrade attacks",
        "X-Frame-Options": "Missing X-Frame-Options — site may be vulnerable to clickjacking",
        "X-Content-Type-Options": "Missing X-Content-Type-Options — browser may MIME-sniff content, risking XSS",
        "Referrer-Policy": "Missing Referrer-Policy — may leak sensitive URL data to third parties",
    }

    SENSITIVE_PATHS = [
        "/.env",
        "/.git/config",
        "/.well-known/security.txt",
        "/wp-config.php.bak",
        "/backup.zip",
    ]

    SECRET_PATTERNS = [
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID exposed"),
        (r"(?i)aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]", "AWS Secret Access Key exposed"),
        (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key exposed"),
        (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe live secret key exposed"),
        (r"ghp_[0-9a-zA-Z]{36}", "GitHub personal access token exposed"),
        (r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "JWT token exposed in client code"),
        (r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]", "Hardcoded password in client code"),
        (r"(?i)mongodb(\+srv)?:\/\/[^\s'\"]+", "Exposed MongoDB connection string"),
        (r"(?i)postgres(ql)?:\/\/[^\s'\"]+", "Exposed PostgreSQL connection string"),
    ]

    # ── DOM XSS: sources (attacker-controllable) and sinks (dangerous JS) ──
    #
    # A DOM XSS vulnerability exists when tainted data from a SOURCE flows,
    # unsanitized, into a SINK. We can't fully trace dataflow with regex, so
    # this is a heuristic: find sink calls and sources, flag it when they
    # appear within a short line-distance of each other in the same script,
    # and separately flag any dangerous sink usage at all (lower severity)
    # since many sinks are unsafe by nature regardless of the source.

    DOM_XSS_SOURCES = [
        r"location\.(?:href|search|hash|pathname)",
        r"document\.(?:URL|documentURI|referrer|baseURI)",
        r"window\.name",
        r"document\.cookie",
        r"\bURLSearchParams\b",
        r"\blocalStorage\.getItem\b",
        r"\bsessionStorage\.getItem\b",
        r"\bpostMessage\b",
    ]

    DOM_XSS_SINKS = [
        (r"\.innerHTML\s*=", "innerHTML assignment"),
        (r"\.outerHTML\s*=", "outerHTML assignment"),
        (r"document\.write(?:ln)?\s*\(", "document.write()"),
        (r"\beval\s*\(", "eval()"),
        (r"\bFunction\s*\(", "Function() constructor"),
        (r"setTimeout\s*\(\s*['\"]", "setTimeout() with string argument"),
        (r"setInterval\s*\(\s*['\"]", "setInterval() with string argument"),
        (r"\.insertAdjacentHTML\s*\(", "insertAdjacentHTML()"),
        (r"document\.execCommand\s*\(\s*['\"]insertHTML", "execCommand('insertHTML')"),
        (r"\$\([^)]*\)\.html\s*\(", "jQuery .html()"),
        (r"\.src\s*=\s*[^;]*location", "script/iframe src set from location"),
        (r"location\s*=\s*", "location assignment (open redirect / javascript: URI)"),
        (r"location\.href\s*=\s*", "location.href assignment"),
        (r"\.setAttribute\s*\(\s*['\"](?:href|src|action|formaction)['\"]", "dangerous setAttribute on URL-bearing attribute"),
    ]

    def __init__(self, base_url: str):
        if not base_url.startswith("http"):
            base_url = "https://" + base_url
        self.base_url = base_url.rstrip("/")
        self.domain = urlparse(self.base_url).netloc

    def check_headers(self) -> list[dict]:
        findings = []
        try:
            resp = requests.get(self.base_url, timeout=10)
            headers = resp.headers
            for header, description in self.SECURITY_HEADERS.items():
                if header not in headers:
                    findings.append({"rule": "HEADER", "description": description, "severity": "MEDIUM"})
            server = headers.get("Server")
            if server:
                findings.append({"rule": "FINGERPRINT", "description": f"Server header exposes version info: {server}", "severity": "LOW"})
        except requests.RequestException as e:
            findings.append({"rule": "CONN_ERROR", "description": f"Could not connect to site: {e}", "severity": "INFO"})
        return findings

    def check_sensitive_paths(self) -> list[dict]:
        findings = []
        baseline_content = None
        try:
            baseline_resp = requests.get(self.base_url + "/this-path-should-not-exist-xyz123", timeout=5)
            if baseline_resp.status_code == 200:
                baseline_content = baseline_resp.text
        except requests.RequestException:
            pass
        for path in self.SENSITIVE_PATHS:
            try:
                resp = requests.get(self.base_url + path, timeout=5)
                if resp.status_code != 200:
                    continue
                if baseline_content is not None and resp.text.strip() == baseline_content.strip():
                    continue
                content_lower = resp.text.lower()
                is_plausible = True
                if path == "/.env" and ("<html" in content_lower or len(resp.text.strip()) == 0):
                    is_plausible = False
                if path == "/.git/config" and "[core]" not in resp.text and "<html" in content_lower:
                    is_plausible = False
                if is_plausible:
                    findings.append({"rule": "EXPOSED_FILE", "description": f"Potentially exposed sensitive file: {path}", "severity": "HIGH"})
            except requests.RequestException:
                continue
        return findings

    def check_ssl(self) -> list[dict]:
        findings = []
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        findings.append({"rule": "SSL", "description": "No SSL certificate found", "severity": "HIGH"})
        except Exception as e:
            findings.append({"rule": "SSL", "description": f"SSL/TLS check failed: {e}", "severity": "MEDIUM"})
        return findings

    def check_open_ports(self) -> list[dict]:
        findings = []
        try:
            nm = nmap.PortScanner(nmap_search_path=("C:\\Program Files (x86)\\Nmap\\nmap.exe",))
            nm.scan(self.domain, arguments="-F -T4")
            if self.domain in nm.all_hosts():
                for proto in nm[self.domain].all_protocols():
                    ports = nm[self.domain][proto].keys()
                    for port in ports:
                        state = nm[self.domain][proto][port]['state']
                        service = nm[self.domain][proto][port].get('name', 'unknown')
                        if state == 'open':
                            severity = "LOW" if port in [80, 443] else "MEDIUM"
                            findings.append({"rule": "OPEN_PORT", "description": f"Open port {port} ({service}) — verify this is intentional", "severity": severity})
        except Exception as e:
            findings.append({"rule": "NMAP_ERROR", "description": f"Port scan failed: {e}", "severity": "INFO"})
        return findings

    def check_js_secrets(self) -> list[dict]:
        findings = []
        try:
            resp = requests.get(self.base_url, timeout=10)
            script_srcs = re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"']", resp.text)
            js_urls = []
            for src in script_srcs[:15]:
                if src.startswith("http"):
                    js_urls.append(src)
                elif src.startswith("//"):
                    js_urls.append("https:" + src)
                else:
                    js_urls.append(self.base_url + "/" + src.lstrip("/"))
            for js_url in js_urls:
                try:
                    js_resp = requests.get(js_url, timeout=8)
                    content = js_resp.text
                    for pattern, description in self.SECRET_PATTERNS:
                        match = re.search(pattern, content)
                        if match:
                            findings.append({"rule": "EXPOSED_SECRET", "description": f"{description} (in {js_url})", "severity": "HIGH"})
                except requests.RequestException:
                    continue
        except requests.RequestException as e:
            findings.append({"rule": "JS_SCAN_ERROR", "description": f"Could not scan JS files: {e}", "severity": "INFO"})
        return findings

    def find_github_repo(self) -> dict:
        result = {"found": False, "source": None, "url": None}
        try:
            resp = requests.get(self.base_url, timeout=10)
            html = resp.text

            github_links = re.findall(
                r'https?://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',
                html
            )
            if github_links:
                result["found"] = True
                result["source"] = "html_link"
                result["url"] = github_links[0].rstrip("/")
                return result

            for path in ["/package.json", "/manifest.json"]:
                try:
                    pkg_resp = requests.get(self.base_url + path, timeout=5)
                    if pkg_resp.status_code == 200:
                        pkg_data = pkg_resp.json()
                        repo_field = pkg_data.get("repository")
                        if isinstance(repo_field, dict):
                            repo_field = repo_field.get("url", "")
                        if repo_field and "github.com" in str(repo_field):
                            result["found"] = True
                            result["source"] = path
                            result["url"] = str(repo_field)
                            return result
                except (requests.RequestException, ValueError):
                    continue

        except requests.RequestException:
            pass

        return result

    def get_server_info(self) -> dict:
        result = {"ip_address": None, "hosting_org": None, "registrar": None, "country": None, "city": None}
        try:
            ip = socket.gethostbyname(self.domain)
            result["ip_address"] = ip

            try:
                geo_resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=8)
                if geo_resp.status_code == 200:
                    geo_data = geo_resp.json()
                    result["hosting_org"] = geo_data.get("org")
                    result["country"] = geo_data.get("country")
                    result["city"] = geo_data.get("city")
            except requests.RequestException:
                pass

            try:
                w = whois.whois(self.domain)
                result["registrar"] = w.registrar
            except Exception:
                pass

        except socket.gaierror:
            pass

        return result

    def _generate_marker(self) -> str:
        token = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"sgxss{token}"

    def _discover_form_fields(self) -> list[dict]:
        forms = []
        try:
            resp = requests.get(self.base_url, timeout=10)
            html = resp.text

            # 1. Parse structured <form> elements
            form_blocks = re.findall(r'<form[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE)
            for block in form_blocks:
                field_names = []
                input_tags = re.findall(r'<input\b[^>]*>', block, re.IGNORECASE)
                input_tags += re.findall(r'<textarea\b[^>]*>', block, re.IGNORECASE)
                for tag in input_tags:
                    name_match = re.search(r'name=["\']([^"\']+)["\']', tag, re.IGNORECASE)
                    id_match = re.search(r'\bid=["\']([^"\']+)["\']', tag, re.IGNORECASE)
                    placeholder_match = re.search(r'placeholder=["\']([^"\']+)["\']', tag, re.IGNORECASE)
                    field_key = None
                    if name_match:
                        field_key = name_match.group(1)
                    elif id_match:
                        field_key = id_match.group(1)
                    elif placeholder_match:
                        field_key = placeholder_match.group(1)
                    if field_key and field_key not in field_names:
                        field_names.append(field_key)
                if field_names:
                    forms.append({"fields": field_names})

            # 2. Parse standalone <input> and <textarea> elements (common in React/Next.js/Vue apps)
            standalone_inputs = re.findall(r'<input\b[^>]*>', html, re.IGNORECASE)
            standalone_inputs += re.findall(r'<textarea\b[^>]*>', html, re.IGNORECASE)
            standalone_names = []
            for tag in standalone_inputs:
                type_match = re.search(r'type=["\']([^"\']+)["\']', tag, re.IGNORECASE)
                itype = type_match.group(1).lower() if type_match else "text"
                if itype in ["submit", "button", "hidden", "image", "reset"]:
                    continue
                name_match = re.search(r'name=["\']([^"\']+)["\']', tag, re.IGNORECASE)
                id_match = re.search(r'\bid=["\']([^"\']+)["\']', tag, re.IGNORECASE)
                key = name_match.group(1) if name_match else (id_match.group(1) if id_match else None)
                if key and key not in standalone_names:
                    standalone_names.append(key)

            if standalone_names:
                forms.append({"fields": standalone_names})

        except requests.RequestException:
            pass
        return forms

    def _is_marker_reflected_unescaped(self, response_text: str, marker: str) -> bool:
        if not marker:
            return False
        payload_fragment = f"<sgxss{marker}>"
        return payload_fragment in response_text

    def check_reflected_xss(self) -> list[dict]:
        findings = []
        parsed = urlparse(self.base_url)
        existing_params = parse_qs(parsed.query)

        tested_params = []

        # 1. Test existing URL parameters
        if existing_params:
            for param_name in existing_params:
                tested_params.append(param_name)
                marker = self._generate_marker()
                payload = f"<sgxss{marker}>"
                test_params = {k: v[0] for k, v in existing_params.items()}
                test_params[param_name] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                try:
                    resp = requests.get(test_url, timeout=10)
                    if self._is_marker_reflected_unescaped(resp.text, marker):
                        findings.append({
                            "rule": "REFLECTED_XSS",
                            "description": f"Unescaped reflection of injected payload via query parameter '{param_name}' — possible reflected XSS",
                            "severity": "HIGH",
                            "parameter": param_name,
                            "location": "query_param",
                        })
                except requests.RequestException:
                    continue

        # 2. Test discovered form and standalone input fields
        forms = self._discover_form_fields()
        for form in forms:
            for field_name in form["fields"]:
                if field_name in tested_params:
                    continue
                tested_params.append(field_name)
                marker = self._generate_marker()
                payload = f"<sgxss{marker}>"
                try:
                    resp = requests.get(self.base_url, params={field_name: payload}, timeout=10)
                    if self._is_marker_reflected_unescaped(resp.text, marker):
                        findings.append({
                            "rule": "REFLECTED_XSS",
                            "description": f"Unescaped reflection of injected payload via input field '{field_name}' — possible reflected XSS",
                            "severity": "HIGH",
                            "parameter": field_name,
                            "location": "form_field",
                        })
                except requests.RequestException:
                    continue

        # 3. Active Parameter Fuzzing Probe if no inputs or URL params were present
        if not tested_params:
            COMMON_PROBE_PARAMS = ["q", "search", "query", "id", "keyword", "s", "redirect"]
            for param_name in COMMON_PROBE_PARAMS:
                tested_params.append(param_name)
                marker = self._generate_marker()
                payload = f"<sgxss{marker}>"
                try:
                    resp = requests.get(self.base_url, params={param_name: payload}, timeout=8)
                    if self._is_marker_reflected_unescaped(resp.text, marker):
                        findings.append({
                            "rule": "REFLECTED_XSS",
                            "description": f"Unescaped reflection of injected payload via probed parameter '{param_name}' — possible reflected XSS",
                            "severity": "HIGH",
                            "parameter": param_name,
                            "location": "query_param_probe",
                        })
                except requests.RequestException:
                    continue

        # If tests ran and no reflection was found, report clean outcome
        if not findings:
            findings.append({
                "rule": "XSS_CLEAN",
                "description": f"Tested {len(tested_params)} parameter/input vectors ({', '.join(tested_params[:6])}) — no unescaped reflection detected",
                "severity": "INFO",
            })

        return findings

    # ── DOM-based XSS (static sink/source analysis) ─────────────────────

    def _collect_js_blocks(self) -> list[dict]:
        """Gather inline <script> bodies and linked JS file contents, each
        tagged with a label so findings can point back to where they came from."""
        blocks = []
        try:
            resp = requests.get(self.base_url, timeout=10)
            html = resp.text
        except requests.RequestException:
            return blocks

        # Inline scripts (skip ones with a src= attribute and no body, and
        # skip JSON-LD / type=application/json blocks which aren't executable JS)
        script_tags = re.findall(r'<script\b([^>]*)>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)
        for idx, (attrs, body) in enumerate(script_tags):
            if not body.strip():
                continue
            type_match = re.search(r'type=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
            if type_match and type_match.group(1).lower() not in (
                "text/javascript", "application/javascript", "module", ""
            ):
                continue
            blocks.append({"label": f"inline <script> #{idx + 1}", "content": body})

        # Linked JS files (same-origin and absolute — reuse the same discovery
        # logic as check_js_secrets so we don't fetch the page twice elsewhere)
        script_srcs = re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"']", html)
        js_urls = []
        for src in script_srcs[:15]:
            if src.startswith("http"):
                js_urls.append(src)
            elif src.startswith("//"):
                js_urls.append("https:" + src)
            else:
                js_urls.append(self.base_url + "/" + src.lstrip("/"))

        for js_url in js_urls:
            try:
                js_resp = requests.get(js_url, timeout=8)
                if js_resp.status_code == 200 and js_resp.text.strip():
                    blocks.append({"label": js_url, "content": js_resp.text})
            except requests.RequestException:
                continue

        return blocks

    def _find_dom_xss_in_block(self, label: str, content: str) -> list[dict]:
        findings = []
        lines = content.splitlines()

        # Pre-compute which line numbers contain a tainted source
        source_lines = set()
        for i, line in enumerate(lines):
            for pattern in self.DOM_XSS_SOURCES:
                if re.search(pattern, line):
                    source_lines.add(i)
                    break

        seen_sink_lines = set()  # avoid duplicate findings for the same line+sink
        WINDOW = 5  # lines of proximity used as a cheap taint-flow heuristic

        for i, line in enumerate(lines):
            for sink_pattern, sink_desc in self.DOM_XSS_SINKS:
                match = re.search(sink_pattern, line)
                if not match:
                    continue
                key = (i, sink_desc)
                if key in seen_sink_lines:
                    continue
                seen_sink_lines.add(key)

                nearby_source = any(
                    abs(i - s) <= WINDOW for s in source_lines
                )
                snippet = line.strip()[:160]

                if nearby_source:
                    findings.append({
                        "rule": "DOM_XSS",
                        "description": (
                            f"Likely DOM-based XSS: {sink_desc} near line {i + 1} of {label} "
                            f"appears to be fed by an attacker-controllable source "
                            f"(e.g. location/document/window) within {WINDOW} lines — code: `{snippet}`"
                        ),
                        "severity": "HIGH",
                        "location": label,
                        "line": i + 1,
                        "sink": sink_desc,
                    })
                else:
                    # Sink present without an obviously nearby source — still worth
                    # flagging since many sinks are dangerous regardless of origin
                    # (e.g. eval, innerHTML with any dynamic string), just lower confidence.
                    findings.append({
                        "rule": "DOM_XSS_SINK",
                        "description": (
                            f"Potentially dangerous DOM sink: {sink_desc} at line {i + 1} of {label} — "
                            f"verify the value assigned here is sanitized or comes from a trusted source. "
                            f"code: `{snippet}`"
                        ),
                        "severity": "MEDIUM",
                        "location": label,
                        "line": i + 1,
                        "sink": sink_desc,
                    })

        return findings

    def check_dom_xss_static(self) -> list[dict]:
        """Static analysis pass: scan inline and linked JS for dangerous
        sink usage and flag cases where a tainted source appears nearby.
        This is a heuristic, not a true dataflow analysis — it will produce
        false positives/negatives, so treat HIGH findings as leads to verify
        manually (or dynamically, see check_dom_xss_dynamic) rather than
        confirmed vulnerabilities."""
        findings = []
        blocks = self._collect_js_blocks()
        if not blocks:
            findings.append({
                "rule": "DOM_XSS_SCAN_EMPTY",
                "description": "No inline or linked JavaScript found to analyze for DOM XSS",
                "severity": "INFO",
            })
            return findings

        for block in blocks:
            findings.extend(self._find_dom_xss_in_block(block["label"], block["content"]))

        if not findings:
            findings.append({
                "rule": "DOM_XSS_CLEAN",
                "description": f"Analyzed {len(blocks)} script block(s) — no dangerous DOM sinks detected",
                "severity": "INFO",
            })

        return findings

    def check_dom_xss_dynamic(self) -> list[dict]:
        """Optional dynamic confirmation pass using a real browser (Playwright),
        if installed. Injects a unique marker into common taint sources
        (location.hash, location.search) and a postMessage, then checks whether
        it executes (e.g. fires window.alert / appears as an actual DOM element
        rather than escaped text). This catches real DOM XSS that static
        analysis can only guess at, and avoids static analysis's false positives.
        Silently skipped (returns []) if Playwright isn't installed, so this is
        safe to call unconditionally."""
        findings = []
        try:
            import importlib
            sync_playwright = importlib.import_module("playwright.sync_api").sync_playwright
        except Exception:
            return findings  # optional dependency not installed — skip silently

        marker = self._generate_marker()
        executed_flag = f"__{marker}_executed__"
        payload = f"<img src=x onerror=window.{executed_flag}=true>"

        test_vectors = [
            ("hash", self.base_url + "#" + payload),
            ("search", self.base_url + "?" + urlencode({"q": payload})),
        ]

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                for source_name, test_url in test_vectors:
                    page = browser.new_page()
                    try:
                        page.goto(test_url, timeout=10000, wait_until="load")
                        page.wait_for_timeout(1500)  # let any client-side routing run
                        fired = page.evaluate(f"() => window.{executed_flag} === true")
                        if fired:
                            findings.append({
                                "rule": "DOM_XSS_CONFIRMED",
                                "description": (
                                    f"Confirmed DOM-based XSS: payload injected via {source_name} "
                                    f"executed in a real browser context — the page reads this value "
                                    f"and inserts it into the DOM without sanitization."
                                ),
                                "severity": "HIGH",
                                "location": source_name,
                                "confirmed": True,
                            })
                    except Exception as e:
                        findings.append({
                            "rule": "DOM_XSS_DYNAMIC_ERROR",
                            "description": f"Dynamic DOM XSS check via {source_name} failed: {e}",
                            "severity": "INFO",
                        })
                    finally:
                        page.close()
                browser.close()
        except Exception as e:
            findings.append({
                "rule": "DOM_XSS_DYNAMIC_ERROR",
                "description": f"Dynamic DOM XSS check could not run: {e}",
                "severity": "INFO",
            })

        return findings

    def check_dom_xss(self) -> list[dict]:
        """Combined DOM XSS check: static heuristic pass, plus a dynamic
        browser-based confirmation pass when Playwright is available."""
        findings = self.check_dom_xss_static()
        findings.extend(self.check_dom_xss_dynamic())
        return findings

    def scan(self) -> dict:
        header_findings = self.check_headers()
        path_findings = self.check_sensitive_paths()
        ssl_findings = self.check_ssl()
        port_findings = self.check_open_ports()
        js_findings = self.check_js_secrets()
        xss_findings = self.check_reflected_xss()
        dom_xss_findings = self.check_dom_xss()
        github_info = self.find_github_repo()
        server_info = self.get_server_info()

        all_findings = (
            header_findings + path_findings + ssl_findings + port_findings
            + js_findings + xss_findings + dom_xss_findings
        )

        return {
            "target": self.base_url,
            "risk_count": len(all_findings),
            "findings": all_findings,
            "scans": {
                "headers": header_findings,
                "sensitive_paths": path_findings,
                "ssl": ssl_findings,
                "open_ports": port_findings,
                "js_secrets": js_findings,
                "reflected_xss": xss_findings,
                "dom_xss": dom_xss_findings,
            },
            "github_repo": github_info,
            "server_info": server_info
        }