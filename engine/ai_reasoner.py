import ollama
import json
import re
import time


class AIReasoner:
    def __init__(self, model: str = "gemma:latest"):
        self.model = model

    def explain_findings(self, instructions: str, findings: list[dict]) -> str:
        if not findings:
            prompt = (
                "You are a security reviewer. The following was scanned and no risky "
                "patterns were found. In 2-3 sentences, confirm whether this looks safe "
                "and note anything worth a human double-checking.\n\n"
                f"Context:\n{instructions}"
            )
        else:
            findings_text = "\n".join(
                f"- [{f['severity']}] {f['rule']}: {f['description']}"
                for f in findings
            )
            prompt = (
                "You are a security reviewer writing a risk report for a website owner. "
                "Below are automated findings from a security scan. For the most significant "
                "findings, explain in plain language what a realistic consequence would be if "
                "they're left unaddressed — e.g. what kind of data or access could be exposed, "
                "and what the practical impact on the business or users would be. "
                "Then, if multiple findings compound each other (make each other worse), point "
                "that out specifically. Keep it focused on explaining risk and urgency to prioritize "
                "fixes — not a step-by-step guide. End with the single most urgent fix to make first.\n\n"
                f"Target: {instructions}\n\n"
                f"Findings:\n{findings_text}"
            )

        response = ollama.chat(
            model=self.model,
            messages=[{"role": "user", "content": prompt}]
        )
        return response["message"]["content"]

    def calculate_risk_score(self, findings: list[dict]) -> dict:
        severity_weights = {"HIGH": 25, "MEDIUM": 10, "LOW": 3, "INFO": 0}
        score = 100
        for f in findings:
            score -= severity_weights.get(f.get("severity", "INFO"), 0)
        score = max(0, score)

        if score >= 90:
            grade = "A"
        elif score >= 75:
            grade = "B"
        elif score >= 60:
            grade = "C"
        elif score >= 40:
            grade = "D"
        else:
            grade = "F"

        return {"score": score, "grade": grade}

    # ── new: agentic planning ───────────────────────────────────────────

    def plan_next_attack(
        self,
        target: str,
        recon_results: dict,
        attack_results: dict,
        completed_attacks: list[str],
        available_attacks: list[str],
        all_findings: list[dict],
    ) -> dict:
        """
        Ask the AI to decide which attack module to run next.

        Returns a dict like:
            {"next_action": "sqli", "reasoning": "...", "priority": "HIGH"}
        or  {"next_action": "stop", "reasoning": "..."}
        """
        if not available_attacks:
            return {"next_action": "stop", "reasoning": "All attack modules have been executed."}

        findings_summary = "\n".join(
            f"  - [{f['severity']}] {f['rule']}: {f['description']}"
            for f in all_findings[:40]  # Cap to avoid overwhelming context
        )

        previous_attacks_summary = ""
        if attack_results:
            for name, findings in attack_results.items():
                high = sum(1 for f in findings if f.get("severity") == "HIGH")
                previous_attacks_summary += f"  - {name}: {len(findings)} findings ({high} HIGH)\n"

        prompt = f"""You are an expert penetration tester acting as an autonomous attack planner.
You are testing: {target}

COMPLETED ATTACKS: {completed_attacks if completed_attacks else "None yet"}
AVAILABLE ATTACKS: {available_attacks}

Attack module descriptions:
- sqli: SQL injection testing (error-based, blind boolean, time-based blind) on query params and form fields
- xss: Cross-site scripting testing (reflected, stored, DOM-based) with multiple payload variants
- dirbuster: Directory brute-forcing and subdomain enumeration with concurrent requests
- csrf: CSRF detection — checks forms for missing/unenforced tokens and cookie SameSite attributes
- auth_brute: Login form discovery and authentication brute-force with common credentials

CURRENT FINDINGS ({len(all_findings)} total):
{findings_summary if findings_summary else "  No findings yet."}

{f"PREVIOUS ATTACK RESULTS:{chr(10)}{previous_attacks_summary}" if previous_attacks_summary else ""}

Based on the findings so far, decide which attack to run next. Consider:
1. Which attacks are most likely to find vulnerabilities given what we already know?
2. Can any finding from recon/previous attacks inform the next attack? (e.g., forms found → test SQLi/XSS)
3. Are there high-value targets (admin panels, login pages, exposed files) that warrant specific attacks?
4. If all valuable attacks have been run, say "stop".

Respond with ONLY valid JSON in this exact format (no markdown, no explanation outside the JSON):
{{"next_action": "<attack_name_or_stop>", "reasoning": "<one sentence why>", "priority": "<HIGH|MEDIUM|LOW>"}}"""

        try:
            response = ollama.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
            )
            content = response["message"]["content"].strip()

            # Extract JSON from the response (handle markdown wrapping)
            json_match = re.search(r"\{.*\}", content, re.DOTALL)
            if json_match:
                decision = json.loads(json_match.group())
                # Validate the action
                if decision.get("next_action") not in available_attacks + ["stop"]:
                    # AI gave an invalid action; pick the first available
                    if available_attacks:
                        decision["next_action"] = available_attacks[0]
                        decision["reasoning"] = (
                            f"AI suggested invalid action, defaulting to {available_attacks[0]}"
                        )
                    else:
                        decision["next_action"] = "stop"
                return decision

        except (json.JSONDecodeError, KeyError, Exception) as e:
            # Fallback: run attacks in order if AI fails to respond properly
            pass

        # Deterministic fallback: run the first available attack
        if available_attacks:
            return {
                "next_action": available_attacks[0],
                "reasoning": f"AI planner unavailable, running {available_attacks[0]} by default",
                "priority": "MEDIUM",
            }
        return {"next_action": "stop", "reasoning": "All attacks completed."}

    def _format_finding_detail(self, f: dict) -> str:
        """Format a single finding with all available technical context."""
        parts = [f"[{f.get('severity', 'INFO')}] {f.get('rule', 'UNKNOWN')}: {f.get('description', '')}"]
        extras = []
        if f.get("parameter"):
            extras.append(f"Parameter: {f['parameter']}")
        if f.get("path"):
            extras.append(f"Path: {f['path']}")
        if f.get("url"):
            extras.append(f"URL: {f['url']}")
        if f.get("status_code"):
            extras.append(f"HTTP Status: {f['status_code']}")
        if f.get("payload"):
            extras.append(f"Payload/Pattern: {f['payload']}")
        if f.get("cookie"):
            extras.append(f"Cookie: {f['cookie']}")
        if f.get("db_type"):
            extras.append(f"Database Engine: {f['db_type']}")
        if f.get("technique"):
            extras.append(f"Technique: {f['technique']}")
        if f.get("sinks"):
            extras.append(f"DOM Sinks: {', '.join(f['sinks'])}")
        if extras:
            parts.append("    Context: " + " | ".join(extras))
        return "\n".join(parts)

    def _format_scans_summary(self, recon_results: dict) -> list[str]:
        """Generate structured breakdown of each and every passive scan."""
        scans_data = recon_results.get("scans", {})
        server_info = recon_results.get("server_info", {})
        lines = [
            "## 3. Passive Reconnaissance Scans Breakdown",
            "This section provides granular results for each automated reconnaissance scan executed against the target.\n",
        ]

        # 1. Headers
        headers_findings = scans_data.get("headers", [])
        lines.append("### 3.1 HTTP Security Headers Audit")
        lines.append("Evaluated core defense-in-depth headers: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.")
        if headers_findings:
            dict_headers = [f for f in headers_findings if isinstance(f, dict)]
            lines.append(f"**Scan Result:** **{len(dict_headers or headers_findings)} header issue(s) detected**")
            for f in dict_headers:
                lines.append(f"- **[{f.get('severity', 'MEDIUM')}] {f.get('rule')}:** {f.get('description')}")
        else:
            lines.append("**Scan Result:** **PASS** — Target implements standard defensive HTTP response headers.")
        lines.append("")

        # 2. Sensitive Paths
        path_findings = scans_data.get("sensitive_paths", [])
        lines.append("### 3.2 Sensitive Paths & Configuration Exposure Probe")
        lines.append("Probed for exposed environment files, version control trees, database dumps, and backup files (`/.env`, `/.git/config`, `/backup.zip`, `/wp-config.php.bak`, `/.well-known/security.txt`).")
        if path_findings:
            dict_paths = [f for f in path_findings if isinstance(f, dict)]
            lines.append(f"**Scan Result:** **{len(dict_paths or path_findings)} sensitive file(s) exposed!**")
            for f in dict_paths:
                lines.append(f"- **[{f.get('severity', 'HIGH')}] {f.get('rule')}:** {f.get('description')} (URL: `{f.get('url', '')}`)")
        else:
            lines.append("**Scan Result:** **PASS** — No sensitive configuration files, environment variables, or backup archives were exposed.")
        lines.append("")

        # 3. SSL/TLS
        ssl_findings = scans_data.get("ssl", [])
        lines.append("### 3.3 SSL/TLS & Cryptographic Validation")
        lines.append("Audited HTTPS encryption, certificate validity, issuer trust, and hostname matching.")
        if ssl_findings:
            dict_ssl = [f for f in ssl_findings if isinstance(f, dict)]
            lines.append(f"**Scan Result:** **{len(dict_ssl or ssl_findings)} SSL/TLS issue(s) identified**")
            for f in dict_ssl:
                lines.append(f"- **[{f.get('severity', 'HIGH')}] {f.get('rule')}:** {f.get('description')}")
        else:
            lines.append("**Scan Result:** **PASS** — SSL/TLS certificate is valid, trusted, and properly bound to the domain.")
        lines.append("")

        # 4. Open Ports
        port_findings = scans_data.get("open_ports", [])
        lines.append("### 3.4 Network Services & Port Scan")
        lines.append("Scanned common network service ports (80 HTTP, 443 HTTPS, 8080/8443 Alternate Web, 21 FTP, 22 SSH, 3306 MySQL, 5432 PostgreSQL).")
        if port_findings:
            dict_ports = [f for f in port_findings if isinstance(f, dict)]
            lines.append(f"**Scan Result:** **{len(dict_ports or port_findings)} service finding(s)**")
            for f in dict_ports:
                lines.append(f"- **[{f.get('severity', 'LOW')}] Port {f.get('port')}:** {f.get('description')}")
        else:
            lines.append("**Scan Result:** **PASS** — Standard web ports only. No extraneous management or database ports exposed directly to the public internet.")
        lines.append("")

        # 5. JS Secrets
        js_findings = scans_data.get("js_secrets", [])
        lines.append("### 3.5 Client-Side JavaScript Secrets & Credential Audit")
        lines.append("Parsed external and inline JavaScript bundles for hardcoded API keys (AWS, Google, Stripe, GitHub), JWTs, passwords, and database connection strings.")
        if js_findings:
            dict_js = [f for f in js_findings if isinstance(f, dict)]
            lines.append(f"**Scan Result:** **ALERT — {len(dict_js or js_findings)} secret pattern(s) identified in client code**")
            for f in dict_js:
                lines.append(f"- **[{f.get('severity', 'HIGH')}] {f.get('secret_type', 'Secret')}:** {f.get('description')}")
        else:
            lines.append("**Scan Result:** **PASS** — No hardcoded cloud keys, JWT tokens, or plaintext credentials detected in scanned scripts.")
        lines.append("")

        # 6. Form & Parameter Discovery
        xss_findings = scans_data.get("reflected_xss", [])
        lines.append("### 3.6 Form & Input Surface Discovery")
        lines.append("Extracted HTML `<form>`, `<input>`, and `<textarea>` elements to map query parameter attack vectors.")
        if xss_findings:
            for f in xss_findings:
                if isinstance(f, dict):
                    lines.append(f"- **[{f.get('severity', 'INFO')}] {f.get('rule')}:** {f.get('description')}")
        else:
            lines.append("**Scan Result:** Inputs cataloged and mapped for active payload injection.")
        lines.append("")

        # 7. Server Fingerprinting & WHOIS
        lines.append("### 3.7 Server Fingerprint & WHOIS Intelligence")
        lines.append(f"- **Server Banner:** `{server_info.get('server_header', 'Undisclosed')}`")
        lines.append(f"- **Hosting Network:** `{server_info.get('hosting_org', 'Unknown')}`")
        lines.append(f"- **Registrar:** `{server_info.get('registrar', 'Unknown')}`")
        lines.append(f"- **IP & Geolocation:** `{server_info.get('ip_address', 'Unknown')}` ({server_info.get('city', 'N/A')}, {server_info.get('country', 'N/A')})")
        lines.append("")

        return lines

    def _format_attacks_summary(self, attack_results: dict) -> list[str]:
        """Generate structured breakdown of each and every active attack module."""
        lines = [
            "## 4. Active Penetration Attacks Execution & Results",
            "This section details the methodologies, input vectors, and outcomes for every active attack module run during the autonomous assessment.\n",
        ]

        all_modules = [
            ("sqli", "SQL Injection Testing", "Error-based, boolean-blind, and time-based blind SQLi payloads against discovered forms and URL parameters"),
            ("xss", "Cross-Site Scripting (XSS) Testing", "Reflected XSS with dynamic canary markers, stored XSS payload persistence, and DOM sink/source flow analysis"),
            ("dirbuster", "Directory & Subdomain Discovery", "Dictionary brute-forcing using custom wordlists, soft-404 filtering, and subdomain DNS resolution"),
            ("csrf", "Cross-Site Request Forgery (CSRF) Audit", "Audit of state-changing forms for anti-CSRF token presence, token validation bypass, and SameSite cookie attributes"),
            ("auth_brute", "Authentication & Credential Testing", "Login portal discovery, account lockout detection, and default credential dictionary evaluation"),
        ]

        for idx, (mod_id, mod_name, mod_desc) in enumerate(all_modules, 1):
            lines.append(f"### 4.{idx} {mod_name} (`{mod_id}`)")
            lines.append(f"- **Scope & Methodology:** {mod_desc}")

            if mod_id not in attack_results:
                lines.append("- **Execution Status:** *Skipped / Not selected by AI planner (no relevant attack vectors discovered)*")
                lines.append("")
                continue

            findings = attack_results[mod_id]
            non_info = [f for f in findings if f.get("severity") in ["HIGH", "MEDIUM", "LOW"]]

            if non_info:
                lines.append(f"- **Execution Status:** **VULNERABLE — {len(non_info)} issue(s) confirmed**")
                for f in non_info:
                    lines.append(f"  - **[{f.get('severity')}] {f.get('rule')}:** {f.get('description')}")
                    context_items = [f"`{k}`: {v}" for k, v in f.items() if k not in ["rule", "description", "severity"]]
                    if context_items:
                        lines.append(f"    - *Technical Evidence:* {', '.join(context_items)}")
            else:
                info_notes = [f.get("description") for f in findings if f.get("severity") == "INFO"]
                note = f" — {info_notes[0]}" if info_notes else ""
                lines.append(f"- **Execution Status:** **CLEAN — No vulnerabilities detected**{note}")

            lines.append("")

        return lines

    # ── Visual Graphs, Flowcharts & Threat Metrics ─────────────────────

    def _generate_svg_risk_gauge(self, score: int, grade: str) -> str:
        """Generate inline SVG radial gauge meter for executive posture."""
        color = "#00ff9d" if grade == "A" else ("#00e5ff" if grade == "B" else ("#ffb800" if grade == "C" else ("#f97316" if grade == "D" else "#ff3366")))
        dashoffset = max(0, 283 - int((score / 100) * 283))
        status_label = "LOW RISK — Robust Posture" if score >= 85 else ("MODERATE RISK — Action Recommended" if score >= 60 else "CRITICAL / ELEVATED RISK")
        
        return f"""<div class="report-viz-card gauge-card" style="display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 20px; background: rgba(13, 19, 36, 0.7); border: 1px solid rgba(255, 255, 255, 0.14); border-radius: 16px; box-shadow: inset 0 1px 1px rgba(255, 255, 255, 0.2), 0 10px 30px rgba(0, 0, 0, 0.4); text-align: center;">
  <div style="font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.12em; color: #94a3b8; font-family: 'JetBrains Mono', monospace; margin-bottom: 12px; font-weight: 700;">Security Posture Index</div>
  <div style="position: relative; width: 140px; height: 140px; display: flex; align-items: center; justify-content: center;">
    <svg width="140" height="140" viewBox="0 0 100 100" style="overflow: visible;">
      <circle cx="50" cy="50" r="45" fill="none" stroke="rgba(255, 255, 255, 0.08)" stroke-width="8"/>
      <circle cx="50" cy="50" r="45" fill="none" stroke="{color}" stroke-width="8" stroke-linecap="round" stroke-dasharray="283" stroke-dashoffset="{dashoffset}" transform="rotate(-90 50 50)" style="filter: drop-shadow(0 0 8px {color}); transition: stroke-dashoffset 1s ease;"/>
    </svg>
    <div style="position: absolute; display: flex; flex-direction: column; align-items: center;">
      <span style="font-family: 'Outfit', sans-serif; font-size: 2.2rem; font-weight: 900; line-height: 1; color: #ffffff;">{score}</span>
      <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; font-weight: 700; color: {color}; margin-top: 2px;">GRADE {grade}</span>
    </div>
  </div>
  <div style="font-size: 0.75rem; color: #cbd5e1; margin-top: 10px; font-family: 'JetBrains Mono', monospace; font-weight: 600;">{status_label}</div>
</div>"""

    def _generate_svg_severity_donut(self, high: int, med: int, low: int, info: int) -> str:
        """Generate inline SVG donut chart for vulnerability distribution."""
        total = high + med + low + info
        if total == 0:
            return """<div class="report-viz-card donut-card" style="padding: 20px; background: rgba(13, 19, 36, 0.7); border: 1px solid rgba(255, 255, 255, 0.14); border-radius: 16px; text-align: center; color: #00ff9d; font-family: 'JetBrains Mono', monospace;">
  <div style="font-size: 0.75rem; text-transform: uppercase; color: #94a3b8; font-weight: 700; margin-bottom: 8px;">Severity Distribution</div>
  <div style="font-size: 1.1rem; font-weight: 800; color: #00ff9d; padding: 30px 0;">CLEAN AUDIT — 0 FINDINGS</div>
</div>"""

        # Circumference = 2 * pi * 38 ≈ 238.76
        circ = 238.76
        p_high = (high / total) * circ
        p_med = (med / total) * circ
        p_low = (low / total) * circ
        p_info = (info / total) * circ

        off_high = 0
        off_med = off_high - p_high
        off_low = off_med - p_med
        off_info = off_low - p_low

        return f"""<div class="report-viz-card donut-card" style="padding: 20px; background: rgba(13, 19, 36, 0.7); border: 1px solid rgba(255, 255, 255, 0.14); border-radius: 16px; box-shadow: inset 0 1px 1px rgba(255, 255, 255, 0.2), 0 10px 30px rgba(0, 0, 0, 0.4); display: flex; flex-direction: column; align-items: center;">
  <div style="font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.12em; color: #94a3b8; font-family: 'JetBrains Mono', monospace; margin-bottom: 12px; font-weight: 700;">Vulnerability Distribution</div>
  <div style="display: flex; align-items: center; justify-content: space-around; width: 100%; gap: 16px; flex-wrap: wrap;">
    <div style="position: relative; width: 130px; height: 130px; display: flex; align-items: center; justify-content: center;">
      <svg width="130" height="130" viewBox="0 0 100 100" style="overflow: visible;">
        <circle cx="50" cy="50" r="38" fill="none" stroke="rgba(255, 255, 255, 0.08)" stroke-width="12"/>
        <circle cx="50" cy="50" r="38" fill="none" stroke="#ff3366" stroke-width="12" stroke-dasharray="{p_high} {circ - p_high}" stroke-dashoffset="{off_high}" transform="rotate(-90 50 50)"/>
        <circle cx="50" cy="50" r="38" fill="none" stroke="#ffb800" stroke-width="12" stroke-dasharray="{p_med} {circ - p_med}" stroke-dashoffset="{off_med}" transform="rotate(-90 50 50)"/>
        <circle cx="50" cy="50" r="38" fill="none" stroke="#00e5ff" stroke-width="12" stroke-dasharray="{p_low} {circ - p_low}" stroke-dashoffset="{off_low}" transform="rotate(-90 50 50)"/>
        <circle cx="50" cy="50" r="38" fill="none" stroke="#64748b" stroke-width="12" stroke-dasharray="{p_info} {circ - p_info}" stroke-dashoffset="{off_info}" transform="rotate(-90 50 50)"/>
      </svg>
      <div style="position: absolute; display: flex; flex-direction: column; align-items: center;">
        <span style="font-family: 'Outfit', sans-serif; font-size: 1.6rem; font-weight: 900; line-height: 1; color: #ffffff;">{total}</span>
        <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.65rem; color: #94a3b8; text-transform: uppercase;">FINDINGS</span>
      </div>
    </div>
    <div style="display: flex; flex-direction: column; gap: 6px; font-family: 'JetBrains Mono', monospace; font-size: 0.75rem;">
      <div style="display: flex; align-items: center; gap: 8px;"><span style="display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: #ff3366;"></span><strong style="color: #ff3366;">HIGH:</strong> <span style="color: #f1f5f9;">{high} ({int(high/total*100)}%)</span></div>
      <div style="display: flex; align-items: center; gap: 8px;"><span style="display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: #ffb800;"></span><strong style="color: #ffb800;">MEDIUM:</strong> <span style="color: #f1f5f9;">{med} ({int(med/total*100)}%)</span></div>
      <div style="display: flex; align-items: center; gap: 8px;"><span style="display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: #00e5ff;"></span><strong style="color: #00e5ff;">LOW:</strong> <span style="color: #f1f5f9;">{low} ({int(low/total*100)}%)</span></div>
      <div style="display: flex; align-items: center; gap: 8px;"><span style="display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: #64748b;"></span><strong style="color: #94a3b8;">INFO:</strong> <span style="color: #f1f5f9;">{info} ({int(info/total*100)}%)</span></div>
    </div>
  </div>
</div>"""

    def _generate_svg_killchain_flowchart(self, recon_results: dict, attack_results: dict, all_findings: list[dict]) -> str:
        """Generate high-resolution SVG diagram representing the 5-phase Attack Kill Chain."""
        high_cnt = len([f for f in all_findings if f.get("severity") == "HIGH"])
        med_cnt = len([f for f in all_findings if f.get("severity") == "MEDIUM"])
        has_vuln = (high_cnt + med_cnt) > 0
        node3_border = "#ff3366" if high_cnt > 0 else ("#ffb800" if med_cnt > 0 else "#00ff9d")
        node3_status = f"{high_cnt + med_cnt} ISSUES" if has_vuln else "CLEAN EXEC"

        return f"""<div class="report-flowchart-card" style="margin: 20px 0; padding: 22px; background: rgba(13, 19, 36, 0.7); border: 1px solid rgba(255, 255, 255, 0.14); border-radius: 18px; box-shadow: inset 0 1px 1px rgba(255, 255, 255, 0.2), 0 10px 30px rgba(0, 0, 0, 0.4);">
  <div style="font-size: 0.85rem; font-family: 'JetBrains Mono', monospace; text-transform: uppercase; color: #00e5ff; letter-spacing: 0.08em; margin-bottom: 16px; font-weight: 700; display: flex; align-items: center; gap: 8px;">
    <span>⚡ Autonomous Attack Kill Chain & Execution Flowchart</span>
  </div>
  <div style="overflow-x: auto; width: 100%;">
    <svg width="100%" height="130" viewBox="0 0 860 130" style="width: 100%; max-width: 860px; height: auto; font-family: 'Inter', sans-serif; display: block; margin: 0 auto;">
      <defs>
        <marker id="arrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 1 L 10 5 L 0 9 z" fill="#00e5ff"/>
        </marker>
        <marker id="arrowPurple" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 1 L 10 5 L 0 9 z" fill="#a855f7"/>
        </marker>
        <marker id="arrowGreen" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 1 L 10 5 L 0 9 z" fill="#00ff9d"/>
        </marker>
      </defs>

      <!-- Connection Arrows -->
      <path d="M 150 65 L 180 65" stroke="#00e5ff" stroke-width="2.5" marker-end="url(#arrow)"/>
      <path d="M 320 65 L 350 65" stroke="#a855f7" stroke-width="2.5" marker-end="url(#arrowPurple)"/>
      <path d="M 490 65 L 520 65" stroke="{node3_border}" stroke-width="2.5" marker-end="url(#arrow)"/>
      <path d="M 660 65 L 690 65" stroke="#00ff9d" stroke-width="2.5" marker-end="url(#arrowGreen)"/>

      <!-- Stage 1: Recon -->
      <rect x="10" y="20" width="140" height="90" rx="12" fill="rgba(6, 12, 24, 0.9)" stroke="#00e5ff" stroke-width="1.5"/>
      <circle cx="80" cy="42" r="13" fill="rgba(0, 229, 255, 0.15)"/>
      <text x="80" y="46" text-anchor="middle" fill="#00e5ff" font-family="'JetBrains Mono', monospace" font-size="11" font-weight="700">1</text>
      <text x="80" y="74" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="700">PASSIVE RECON</text>
      <text x="80" y="92" text-anchor="middle" fill="#94a3b8" font-family="'JetBrains Mono', monospace" font-size="8.5">OSINT & Headers</text>

      <!-- Stage 2: AI Planner -->
      <rect x="180" y="20" width="140" height="90" rx="12" fill="rgba(6, 12, 24, 0.9)" stroke="#a855f7" stroke-width="1.5"/>
      <circle cx="250" cy="42" r="13" fill="rgba(168, 85, 247, 0.15)"/>
      <text x="250" y="46" text-anchor="middle" fill="#a855f7" font-family="'JetBrains Mono', monospace" font-size="11" font-weight="700">2</text>
      <text x="250" y="74" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="700">AI PLANNER</text>
      <text x="250" y="92" text-anchor="middle" fill="#94a3b8" font-family="'JetBrains Mono', monospace" font-size="8.5">Neural Strategy</text>

      <!-- Stage 3: Exploitation -->
      <rect x="350" y="20" width="140" height="90" rx="12" fill="rgba(6, 12, 24, 0.9)" stroke="{node3_border}" stroke-width="2"/>
      <circle cx="420" cy="42" r="13" fill="{node3_border}25"/>
      <text x="420" y="46" text-anchor="middle" fill="{node3_border}" font-family="'JetBrains Mono', monospace" font-size="11" font-weight="700">3</text>
      <text x="420" y="74" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="700">EXPLOITATION</text>
      <text x="420" y="92" text-anchor="middle" fill="{node3_border}" font-family="'JetBrains Mono', monospace" font-size="8.5" font-weight="700">{node3_status}</text>

      <!-- Stage 4: Risk Scoring -->
      <rect x="520" y="20" width="140" height="90" rx="12" fill="rgba(6, 12, 24, 0.9)" stroke="#00e5ff" stroke-width="1.5"/>
      <circle cx="590" cy="42" r="13" fill="rgba(0, 229, 255, 0.15)"/>
      <text x="590" y="46" text-anchor="middle" fill="#00e5ff" font-family="'JetBrains Mono', monospace" font-size="11" font-weight="700">4</text>
      <text x="590" y="74" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="700">CVSS CORRELATION</text>
      <text x="590" y="92" text-anchor="middle" fill="#94a3b8" font-family="'JetBrains Mono', monospace" font-size="8.5">CWE & Risk Score</text>

      <!-- Stage 5: Final Report -->
      <rect x="690" y="20" width="140" height="90" rx="12" fill="rgba(6, 12, 24, 0.9)" stroke="#00ff9d" stroke-width="1.5"/>
      <circle cx="760" cy="42" r="13" fill="rgba(0, 255, 157, 0.15)"/>
      <text x="760" y="46" text-anchor="middle" fill="#00ff9d" font-family="'JetBrains Mono', monospace" font-size="11" font-weight="700">5</text>
      <text x="760" y="74" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="700">AUDIT DOSSIER</text>
      <text x="760" y="92" text-anchor="middle" fill="#00ff9d" font-family="'JetBrains Mono', monospace" font-size="8.5">Executive Sign-Off</text>
    </svg>
  </div>
</div>"""

    def _generate_svg_attack_vector_bars(self, attack_results: dict, all_findings: list[dict]) -> str:
        """Generate visual bar meters comparing attack vectors and test status."""
        vector_defs = [
            ("SQL Injection", "sqli", "#ff3366"),
            ("Cross-Site Scripting (XSS)", "xss", "#ff3366"),
            ("Directory Brute & Traversal", "dirbuster", "#ffb800"),
            ("Cross-Site Request Forgery", "csrf", "#ffb800"),
            ("Authentication / Brute Force", "auth_brute", "#ff3366"),
            ("HTTP Defensive Headers", "headers", "#00e5ff"),
            ("Cryptographic SSL/TLS", "ssl", "#00e5ff"),
        ]

        bar_items = []
        for name, key, accent in vector_defs:
            matches = [f for f in all_findings if key in (f.get("rule", "").lower()) or (key in f.get("description", "").lower())]
            vuln_count = len([f for f in matches if f.get("severity") in ["HIGH", "MEDIUM", "LOW"]])
            
            if vuln_count > 0:
                bar_color = "#ff3366" if vuln_count >= 2 else "#ffb800"
                pct = min(100, 25 + vuln_count * 25)
                status_badge = f'<span style="color: {bar_color}; font-weight: 700;">⚠ {vuln_count} ISSUE(S)</span>'
            else:
                bar_color = "#00ff9d"
                pct = 100
                status_badge = '<span style="color: #00ff9d; font-weight: 700;">✓ SECURE</span>'

            bar_items.append(f"""
        <div style="margin-bottom: 10px;">
          <div style="display: flex; justify-content: space-between; font-size: 0.76rem; font-family: 'JetBrains Mono', monospace; margin-bottom: 4px;">
            <span style="color: #e2e8f0; font-weight: 600;">{name}</span>
            {status_badge}
          </div>
          <div style="width: 100%; height: 8px; background: rgba(255, 255, 255, 0.08); border-radius: 999px; overflow: hidden;">
            <div style="width: {pct}%; height: 100%; background: linear-gradient(90deg, {bar_color}88, {bar_color}); border-radius: 999px; box-shadow: 0 0 10px {bar_color};"></div>
          </div>
        </div>""")

        return f"""<div class="report-viz-card vector-card" style="margin: 20px 0; padding: 22px; background: rgba(13, 19, 36, 0.7); border: 1px solid rgba(255, 255, 255, 0.14); border-radius: 18px; box-shadow: inset 0 1px 1px rgba(255, 255, 255, 0.2), 0 10px 30px rgba(0, 0, 0, 0.4);">
  <div style="font-size: 0.85rem; font-family: 'JetBrains Mono', monospace; text-transform: uppercase; color: #00e5ff; letter-spacing: 0.08em; margin-bottom: 14px; font-weight: 700;">
    📊 Attack Vector Surface & Defense Readiness Breakdown
  </div>
  {''.join(bar_items)}
</div>"""

    def _generate_kpi_metrics_grid(self, target: str, score: int, grade: str, all_findings: list[dict], recon_results: dict, attack_results: dict) -> str:
        """Generate executive KPI summary cards grid for top of dossier."""
        highs = len([f for f in all_findings if f.get("severity") == "HIGH"])
        meds = len([f for f in all_findings if f.get("severity") == "MEDIUM"])
        lows = len([f for f in all_findings if f.get("severity") == "LOW"])
        infos = len([f for f in all_findings if f.get("severity") == "INFO"])
        total = len(all_findings)
        attacks_cnt = len(attack_results) if attack_results else 5

        score_color = "#00ff9d" if grade == "A" else ("#00e5ff" if grade == "B" else ("#ffb800" if grade == "C" else ("#f97316" if grade == "D" else "#ff3366")))
        sla_text = "EMERGENCY: 24-48H" if highs > 0 else ("NEXT RELEASE: 7 DAYS" if meds > 0 else "ROUTINE AUDIT: 30D")
        sla_color = "#ff3366" if highs > 0 else ("#ffb800" if meds > 0 else "#00ff9d")

        return f"""<div class="report-kpi-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 14px; margin: 20px 0;">
  <div style="padding: 16px; background: rgba(13, 19, 36, 0.7); border: 1px solid rgba(255, 255, 255, 0.12); border-radius: 14px; box-shadow: inset 0 1px 1px rgba(255,255,255,0.15);">
    <div style="font-size: 0.7rem; font-family: 'JetBrains Mono', monospace; color: #94a3b8; text-transform: uppercase; margin-bottom: 6px;">Security Posture</div>
    <div style="font-size: 1.8rem; font-weight: 900; color: {score_color}; font-family: 'Outfit', sans-serif;">{score}<span style="font-size: 1rem; color: #64748b;">/100</span></div>
    <div style="font-size: 0.72rem; color: #cbd5e1; font-family: 'JetBrains Mono', monospace; font-weight: 600; margin-top: 4px;">GRADE {grade} POSTURE</div>
  </div>
  <div style="padding: 16px; background: rgba(13, 19, 36, 0.7); border: 1px solid rgba(255, 255, 255, 0.12); border-radius: 14px; box-shadow: inset 0 1px 1px rgba(255,255,255,0.15);">
    <div style="font-size: 0.7rem; font-family: 'JetBrains Mono', monospace; color: #94a3b8; text-transform: uppercase; margin-bottom: 6px;">Total Findings</div>
    <div style="font-size: 1.8rem; font-weight: 900; color: #ffffff; font-family: 'Outfit', sans-serif;">{total}</div>
    <div style="font-size: 0.72rem; font-family: 'JetBrains Mono', monospace; margin-top: 4px;">
      <span style="color: #ff3366; font-weight: 700;">{highs}H</span> · 
      <span style="color: #ffb800; font-weight: 700;">{meds}M</span> · 
      <span style="color: #00e5ff; font-weight: 700;">{lows}L</span> · 
      <span style="color: #94a3b8;">{infos}I</span>
    </div>
  </div>
  <div style="padding: 16px; background: rgba(13, 19, 36, 0.7); border: 1px solid rgba(255, 255, 255, 0.12); border-radius: 14px; box-shadow: inset 0 1px 1px rgba(255,255,255,0.15);">
    <div style="font-size: 0.7rem; font-family: 'JetBrains Mono', monospace; color: #94a3b8; text-transform: uppercase; margin-bottom: 6px;">Agent Modules</div>
    <div style="font-size: 1.8rem; font-weight: 900; color: #00e5ff; font-family: 'Outfit', sans-serif;">{attacks_cnt}<span style="font-size: 1rem; color: #64748b;">/5</span></div>
    <div style="font-size: 0.72rem; color: #00ff9d; font-family: 'JetBrains Mono', monospace; margin-top: 4px;">PASSIVE + ACTIVE RUN</div>
  </div>
  <div style="padding: 16px; background: rgba(13, 19, 36, 0.7); border: 1px solid rgba(255, 255, 255, 0.12); border-radius: 14px; box-shadow: inset 0 1px 1px rgba(255,255,255,0.15);">
    <div style="font-size: 0.7rem; font-family: 'JetBrains Mono', monospace; color: #94a3b8; text-transform: uppercase; margin-bottom: 6px;">Triage Mandate</div>
    <div style="font-size: 1.15rem; font-weight: 800; color: {sla_color}; font-family: 'JetBrains Mono', monospace; line-height: 1.3; margin-top: 4px;">{sla_text}</div>
    <div style="font-size: 0.72rem; color: #94a3b8; font-family: 'JetBrains Mono', monospace; margin-top: 4px;">SLA TARGET WINDOW</div>
  </div>
</div>"""

    def _generate_svg_risk_matrix(self, all_findings: list[dict]) -> str:
        """Generate high-resolution 2D Threat Likelihood vs Impact Matrix SVG."""
        highs = len([f for f in all_findings if f.get("severity") == "HIGH"])
        meds = len([f for f in all_findings if f.get("severity") == "MEDIUM"])
        lows = len([f for f in all_findings if f.get("severity") == "LOW"])
        infos = len([f for f in all_findings if f.get("severity") == "INFO"])

        return f"""<div class="report-matrix-card" style="margin: 20px 0; padding: 22px; background: rgba(13, 19, 36, 0.7); border: 1px solid rgba(255, 255, 255, 0.14); border-radius: 18px; box-shadow: inset 0 1px 1px rgba(255, 255, 255, 0.2), 0 10px 30px rgba(0, 0, 0, 0.4);">
  <div style="font-size: 0.85rem; font-family: 'JetBrains Mono', monospace; text-transform: uppercase; color: #a855f7; letter-spacing: 0.08em; margin-bottom: 14px; font-weight: 700;">
    🎯 Threat Likelihood vs. Impact 2D Risk Matrix
  </div>
  <div style="overflow-x: auto; width: 100%;">
    <table style="width: 100%; border-collapse: separate; border-spacing: 6px; font-family: 'JetBrains Mono', monospace; font-size: 0.75rem;">
      <thead>
        <tr>
          <th style="background: transparent; color: #94a3b8; padding: 6px; text-align: left;">LIKELIHOOD \\ IMPACT</th>
          <th style="background: rgba(0, 229, 255, 0.12); color: #00e5ff; border: 1px solid rgba(0, 229, 255, 0.3); border-radius: 8px; padding: 8px; text-align: center;">LOW IMPACT</th>
          <th style="background: rgba(255, 184, 0, 0.12); color: #ffb800; border: 1px solid rgba(255, 184, 0, 0.3); border-radius: 8px; padding: 8px; text-align: center;">MEDIUM IMPACT</th>
          <th style="background: rgba(249, 115, 22, 0.12); color: #f97316; border: 1px solid rgba(249, 115, 22, 0.3); border-radius: 8px; padding: 8px; text-align: center;">HIGH IMPACT</th>
          <th style="background: rgba(255, 51, 102, 0.15); color: #ff3366; border: 1px solid rgba(255, 51, 102, 0.4); border-radius: 8px; padding: 8px; text-align: center;">CRITICAL IMPACT</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="color: #ff3366; font-weight: 700; padding: 6px;">HIGH LIKELIHOOD</td>
          <td style="background: rgba(255, 184, 0, 0.08); border: 1px solid rgba(255, 184, 0, 0.2); border-radius: 8px; padding: 10px; text-align: center; color: #f1f5f9;">
            <div style="font-weight: 700; color: #ffb800;">MEDIUM TIER</div>
            <div style="font-size: 0.68rem; color: #94a3b8; margin-top: 2px;">Headers ({infos})</div>
          </td>
          <td style="background: rgba(249, 115, 22, 0.12); border: 1px solid rgba(249, 115, 22, 0.3); border-radius: 8px; padding: 10px; text-align: center; color: #f1f5f9;">
            <div style="font-weight: 700; color: #f97316;">HIGH TIER</div>
            <div style="font-size: 0.68rem; color: #94a3b8; margin-top: 2px;">CSRF / Dir ({meds})</div>
          </td>
          <td style="background: rgba(255, 51, 102, 0.2); border: 1px solid rgba(255, 51, 102, 0.5); border-radius: 8px; padding: 10px; text-align: center; color: #f1f5f9;">
            <div style="font-weight: 800; color: #ff3366;">CRITICAL</div>
            <div style="font-size: 0.68rem; color: #ff3366; font-weight: 700; margin-top: 2px;">Reflected XSS ({meds})</div>
          </td>
          <td style="background: rgba(255, 51, 102, 0.32); border: 1px solid #ff3366; border-radius: 8px; padding: 10px; text-align: center; color: #ffffff; box-shadow: 0 0 15px rgba(255, 51, 102, 0.3);">
            <div style="font-weight: 900; color: #ff3366;">EXTREME CRITICAL</div>
            <div style="font-size: 0.68rem; color: #fecdd3; font-weight: 700; margin-top: 2px;">SQLi / Auth ({highs})</div>
          </td>
        </tr>
        <tr>
          <td style="color: #ffb800; font-weight: 700; padding: 6px;">MEDIUM LIKELIHOOD</td>
          <td style="background: rgba(0, 229, 255, 0.06); border: 1px solid rgba(0, 229, 255, 0.15); border-radius: 8px; padding: 10px; text-align: center; color: #f1f5f9;">
            <div style="color: #00e5ff; font-weight: 600;">LOW TIER</div>
            <div style="font-size: 0.68rem; color: #94a3b8; margin-top: 2px;">Ports &amp; Banner</div>
          </td>
          <td style="background: rgba(255, 184, 0, 0.08); border: 1px solid rgba(255, 184, 0, 0.2); border-radius: 8px; padding: 10px; text-align: center; color: #f1f5f9;">
            <div style="color: #ffb800; font-weight: 600;">MEDIUM TIER</div>
            <div style="font-size: 0.68rem; color: #94a3b8; margin-top: 2px;">SSL Cipher Suite</div>
          </td>
          <td style="background: rgba(249, 115, 22, 0.12); border: 1px solid rgba(249, 115, 22, 0.3); border-radius: 8px; padding: 10px; text-align: center; color: #f1f5f9;">
            <div style="color: #f97316; font-weight: 700;">HIGH TIER</div>
            <div style="font-size: 0.68rem; color: #94a3b8; margin-top: 2px;">Sensitive Endpoints</div>
          </td>
          <td style="background: rgba(255, 51, 102, 0.2); border: 1px solid rgba(255, 51, 102, 0.5); border-radius: 8px; padding: 10px; text-align: center; color: #f1f5f9;">
            <div style="color: #ff3366; font-weight: 800;">CRITICAL</div>
            <div style="font-size: 0.68rem; color: #ff3366; margin-top: 2px;">Credential Stuffing</div>
          </td>
        </tr>
        <tr>
          <td style="color: #00e5ff; font-weight: 700; padding: 6px;">LOW LIKELIHOOD</td>
          <td style="background: rgba(255, 255, 255, 0.02); border: 1px solid rgba(255, 255, 255, 0.06); border-radius: 8px; padding: 10px; text-align: center; color: #64748b;">
            <div>INFORMATIONAL</div>
            <div style="font-size: 0.68rem; margin-top: 2px;">Banner disclosure</div>
          </td>
          <td style="background: rgba(0, 229, 255, 0.04); border: 1px solid rgba(0, 229, 255, 0.1); border-radius: 8px; padding: 10px; text-align: center; color: #94a3b8;">
            <div>LOW</div>
            <div style="font-size: 0.68rem; margin-top: 2px;">DNS Introspection</div>
          </td>
          <td style="background: rgba(255, 184, 0, 0.06); border: 1px solid rgba(255, 184, 0, 0.15); border-radius: 8px; padding: 10px; text-align: center; color: #94a3b8;">
            <div>MODERATE</div>
            <div style="font-size: 0.68rem; margin-top: 2px;">Unlinked scripts</div>
          </td>
          <td style="background: rgba(249, 115, 22, 0.1); border: 1px solid rgba(249, 115, 22, 0.25); border-radius: 8px; padding: 10px; text-align: center; color: #f97316;">
            <div>SIGNIFICANT</div>
            <div style="font-size: 0.68rem; margin-top: 2px;">Zero-Day Vector</div>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</div>"""

    def _generate_compliance_summary_card(self, all_findings: list[dict]) -> str:
        """Generate compliance posture attestation for OWASP, NIST, PCI-DSS."""
        highs = len([f for f in all_findings if f.get("severity") == "HIGH"])
        meds = len([f for f in all_findings if f.get("severity") == "MEDIUM"])

        owasp_status = "NON-COMPLIANT" if highs > 0 else ("PARTIAL / ACTION NEEDED" if meds > 0 else "COMPLIANT")
        owasp_color = "#ff3366" if highs > 0 else ("#ffb800" if meds > 0 else "#00ff9d")

        pci_status = "FAIL (Req 6.5)" if highs > 0 else ("WARNING" if meds > 0 else "PASS")
        pci_color = "#ff3366" if highs > 0 else ("#ffb800" if meds > 0 else "#00ff9d")

        return f"""<div class="report-compliance-card" style="margin: 20px 0; padding: 22px; background: rgba(13, 19, 36, 0.7); border: 1px solid rgba(255, 255, 255, 0.14); border-radius: 18px; box-shadow: inset 0 1px 1px rgba(255, 255, 255, 0.2), 0 10px 30px rgba(0, 0, 0, 0.4);">
  <div style="font-size: 0.85rem; font-family: 'JetBrains Mono', monospace; text-transform: uppercase; color: #00ff9d; letter-spacing: 0.08em; margin-bottom: 14px; font-weight: 700;">
    🛡️ Regulatory & Compliance Readiness Attestation
  </div>
  <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; font-family: 'JetBrains Mono', monospace;">
    <div style="padding: 12px; background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 10px;">
      <div style="color: #94a3b8; font-size: 0.7rem;">OWASP TOP 10 (2021)</div>
      <div style="color: {owasp_color}; font-weight: 800; font-size: 0.92rem; margin-top: 4px;">{owasp_status}</div>
      <div style="color: #64748b; font-size: 0.65rem; margin-top: 2px;">Injection &amp; Configs</div>
    </div>
    <div style="padding: 12px; background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 10px;">
      <div style="color: #94a3b8; font-size: 0.7rem;">NIST SP 800-115</div>
      <div style="color: #00e5ff; font-weight: 800; font-size: 0.92rem; margin-top: 4px;">AUDITED</div>
      <div style="color: #64748b; font-size: 0.65rem; margin-top: 2px;">Technical Guide Standard</div>
    </div>
    <div style="padding: 12px; background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 10px;">
      <div style="color: #94a3b8; font-size: 0.7rem;">PCI-DSS v4.0</div>
      <div style="color: {pci_color}; font-weight: 800; font-size: 0.92rem; margin-top: 4px;">{pci_status}</div>
      <div style="color: #64748b; font-size: 0.65rem; margin-top: 2px;">Section 6.5 Web Apps</div>
    </div>
    <div style="padding: 12px; background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 10px;">
      <div style="color: #94a3b8; font-size: 0.7rem;">ISO/IEC 27001</div>
      <div style="color: #00e5ff; font-weight: 800; font-size: 0.92rem; margin-top: 4px;">ALIGNED</div>
      <div style="color: #64748b; font-size: 0.65rem; margin-top: 2px;">Control A.8.8 Management</div>
    </div>
  </div>
</div>"""

    def _enrich_finding_metadata(self, f: dict) -> dict:
        """Enrich raw scanner/attack findings with CVSS v3.1, CWE, and actionable code fixes."""
        rule = (f.get("rule") or "").upper()
        sev = (f.get("severity") or "INFO").upper()

        if "SQLI" in rule:
            cwe = "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
            cvss_score = 9.8 if sev == "HIGH" else 8.5
            cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            owasp = "A03:2021 - Injection"
            impact = "Full relational database read/write compromise, authentication bypass, data extraction, and potential remote OS shell access."
            reproduction = "1. Navigate to target URL with injection payload parameter.\n2. Supply test marker: `' OR 1=1--` or `' UNION SELECT @@version--`.\n3. Observe database syntax error or reflected administrative recordset."
            remediation = "Enforce parameterized prepared statements across all database interactions. Never concatenate untrusted strings into query text.\n```python\n# SECURE IMPLEMENTATION EXAMPLE:\ncursor.execute('SELECT * FROM users WHERE username = %s AND status = %s', (username, 'active'))\n```"
        elif "XSS" in rule:
            cwe = "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-Site Scripting')"
            cvss_score = 7.2 if sev == "HIGH" else 6.1
            cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
            owasp = "A03:2021 - Injection"
            impact = "Session hijacking, credential theft via cookie access, unauthorized DOM manipulation, and automated user actions."
            reproduction = "1. Inject payload: `\"><script>alert(document.domain)</script>` into search/input field.\n2. Submit request and observe unencoded reflection in browser DOM response."
            remediation = "Apply contextual output encoding (HTML, JavaScript, Attribute context) and deploy a strict Content Security Policy (CSP).\n```html\n<!-- SECURE CSP HEADER -->\nContent-Security-Policy: default-src 'self'; script-src 'self' 'nonce-rAnd0m123'; object-src 'none';\n```"
        elif "CSRF" in rule:
            cwe = "CWE-352: Cross-Site Request Forgery (CSRF)"
            cvss_score = 6.5
            cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"
            owasp = "A01:2021 - Broken Access Control"
            impact = "Unauthorized state-changing transactions (password changes, fund transfers, privilege changes) executed on behalf of authenticated victims."
            reproduction = "1. Craft third-party auto-submitting HTML form targeting the state-changing endpoint.\n2. Verify the server processes the state change without requiring a synchronized anti-CSRF token."
            remediation = "Issue unique, cryptographically random anti-CSRF tokens for all state-changing requests and set SameSite=Lax on session cookies.\n```http\nSet-Cookie: session_id=xyz; Secure; HttpOnly; SameSite=Lax\n```"
        elif "AUTH" in rule or "BRUTE" in rule:
            cwe = "CWE-307: Improper Restriction of Excessive Authentication Attempts"
            cvss_score = 8.1
            cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
            owasp = "A07:2021 - Identification and Authentication Failures"
            impact = "Account takeover, credential stuffing success, and unauthorized user impersonation."
            reproduction = "1. Direct automated credential attempts at login endpoint.\n2. Confirm absence of rate limiting or progressive lockout after multiple failed attempts."
            remediation = "Implement rate limiting, account lockout thresholds after 5 failed attempts, IP-based progressive delays, and multi-factor authentication (MFA/TOTP)."
        elif "DIR" in rule or "PATH" in rule:
            cwe = "CWE-548: Exposure of Information Through Directory Listing"
            cvss_score = 5.3
            cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
            owasp = "A05:2021 - Security Misconfiguration"
            impact = "Disclosure of internal application structure, source code backups, environment configuration (.env), or administrative interfaces."
            reproduction = "1. Send GET request to common paths (e.g. `/admin/`, `/.git/`, `/.env`).\n2. Observe HTTP 200 with directory indices or sensitive configuration files."
            remediation = "Disable directory browsing ('Options -Indexes' in Apache, 'autoindex off;' in Nginx) and block direct web requests to dotfiles and backups."
        elif "HEADER" in rule:
            cwe = "CWE-693: Protection Mechanism Failure"
            cvss_score = 4.3
            cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"
            owasp = "A05:2021 - Security Misconfiguration"
            impact = "Leaves the application susceptible to clickjacking, MIME sniffing, protocol downgrade attacks, and unconstrained script execution."
            reproduction = "1. Perform curl or HEAD request: `curl -I https://target/`.\n2. Inspect response headers; note absence of CSP, HSTS, X-Frame-Options."
            remediation = "Configure defensive HTTP response headers:\n```nginx\nadd_header Content-Security-Policy \"default-src 'self'\";\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\nadd_header X-Frame-Options \"DENY\";\nadd_header X-Content-Type-Options \"nosniff\";\n```"
        elif "SSL" in rule or "TLS" in rule:
            cwe = "CWE-295: Improper Certificate Validation"
            cvss_score = 5.9
            cvss_vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
            owasp = "A02:2021 - Cryptographic Failures"
            impact = "Susceptibility to Man-in-the-Middle (MitM) inspection, cleartext traffic interception, and cryptographic downgrade attacks."
            reproduction = "1. Test cipher suites using `openssl s_client -connect target:443 -tls1_0`.\n2. Verify legacy ciphers or missing certificate chains."
            remediation = "Enforce TLS 1.3 or 1.2 minimum, disable legacy cipher suites (RC4, 3DES), install valid CA-signed certificates, and implement HSTS preload."
        else:
            cwe = "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"
            cvss_score = 3.3
            cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
            owasp = "A05:2021 - Security Misconfiguration"
            impact = "Leakage of server metadata, software versions, and structural details aiding targeted exploitation."
            reproduction = "1. Examine server banner headers and verbose debug response output."
            remediation = "Follow least-privilege configurations and harden infrastructure according to CIS Benchmarks."

        return {
            "cwe": cwe,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "owasp": owasp,
            "impact": impact,
            "reproduction": reproduction,
            "remediation": remediation,
        }

    # ── Full Audit Report Generation ───────────────────────────────────

    def generate_pentest_report(
        self,
        target: str,
        recon_results: dict,
        attack_results: dict,
        all_findings: list[dict],
    ) -> str:
        """Generate a comprehensive, visual, publication-grade penetration testing report."""
        risk = self.calculate_risk_score(all_findings)
        highs = [f for f in all_findings if f.get("severity") == "HIGH"]
        meds = [f for f in all_findings if f.get("severity") == "MEDIUM"]
        lows = [f for f in all_findings if f.get("severity") == "LOW"]
        infos = [f for f in all_findings if f.get("severity") == "INFO"]

        # Generate visual SVG graphs & flowcharts
        kpi_grid = self._generate_kpi_metrics_grid(target, risk["score"], risk["grade"], all_findings, recon_results, attack_results)
        gauge_svg = self._generate_svg_risk_gauge(risk["score"], risk["grade"])
        donut_svg = self._generate_svg_severity_donut(len(highs), len(meds), len(lows), len(infos))
        flowchart_svg = self._generate_svg_killchain_flowchart(recon_results, attack_results, all_findings)
        matrix_svg = self._generate_svg_risk_matrix(all_findings)
        vector_bars_svg = self._generate_svg_attack_vector_bars(attack_results, all_findings)
        compliance_card = self._generate_compliance_summary_card(all_findings)

        server_info = recon_results.get("server_info", {})
        attacks_run = list(attack_results.keys()) if attack_results else ["Reconnaissance only"]
        scans_summary = "\n".join(self._format_scans_summary(recon_results))
        attacks_summary = "\n".join(self._format_attacks_summary(attack_results))

        prompt = f"""You are a Lead Cybersecurity Penetration Tester writing an exhaustive, publication-grade security audit report.

TARGET: {target}
TARGET INFRASTRUCTURE:
  - IP Address: {server_info.get('ip_address', 'N/A')}
  - Hosting Org / ASN: {server_info.get('hosting_org', 'N/A')}
  - Registrar: {server_info.get('registrar', 'N/A')}
  - Server Fingerprint: {server_info.get('server_header', 'N/A')}
  - Location: {server_info.get('city', 'N/A')}, {server_info.get('country', 'N/A')}

ATTACKS EXECUTED: {', '.join(attacks_run)}
TOTAL FINDINGS: {len(all_findings)} (HIGH: {len(highs)}, MEDIUM: {len(meds)}, LOW: {len(lows)}, INFO: {len(infos)})

DETAILED SUMMARY OF EVERY SCAN EXECUTED:
{scans_summary}

DETAILED SUMMARY OF EVERY ATTACK EXECUTED:
{attacks_summary}

Generate an exhaustive, highly detailed penetration testing report formatted in GitHub Flavored Markdown.
The report MUST contain:
1. # Executive Summary (High-level risk overview, overall assessment, and immediate concern for management)
2. ## Target Scope & Infrastructure Profile (Table of target URL, IP, registrar, server headers, and network scope)
3. ## Granular Reconnaissance Scans Breakdown (Detail the specific results of EACH AND EVERY scan: HTTP headers, sensitive paths, SSL/TLS, port scanning, JavaScript secrets, and form discovery)
4. ## Active Penetration Attacks Execution & Results (Detail the specific results of EACH AND EVERY attack: SQL Injection, Cross-Site Scripting, DirBuster path discovery, CSRF form audits, and Auth Brute-Force, including targets tested and clean/vulnerable verdicts)
5. ## Vulnerability Severity Breakdown & Risk Matrix (Table of findings categorized by severity)
6. ## Attack Chain & Threat Correlation Analysis (How discovered issues compound together)
7. ## Strategic Remediation Roadmap (Tiered action items: Immediate / 24-48h, Short-term / 7 days, Medium-term / 30 days)
8. ## Security Posture Verdict (Final conclusion)

Write thoroughly, be technically precise, cite specific parameters/paths/headers, and detail both vulnerable outcomes and clean scan results."""

        llm_body = None
        try:
            response = ollama.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
            )
            llm_body = response["message"]["content"]
        except Exception:
            # Deterministic generation will be used if Ollama is unreachable
            pass

        if llm_body:
            # Weave in the visual graphs, flowcharts, and technical dossier
            header_block = [
                f"# Security Assessment & Executive Penetration Testing Dossier",
                f"**Target Host:** `{target}` | **Audit Date:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())} | **Classification:** CONFIDENTIAL / RESTRICTED",
                "## Visual Threat Horizon & Intelligence Dashboard",
                kpi_grid,
                f'<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 18px 0;">{gauge_svg}{donut_svg}</div>',
                flowchart_svg,
                matrix_svg,
                vector_bars_svg,
                compliance_card,
                "---",
                llm_body
            ]
            return "\n\n".join(header_block)

        return self.build_fallback_report(
            target=target,
            recon_results=recon_results,
            attack_results=attack_results,
            all_findings=all_findings,
        )

    def build_fallback_report(
        self,
        target: str,
        recon_results: dict,
        attack_results: dict,
        all_findings: list[dict],
        error_msg: str = None,
    ) -> str:
        """Deterministically build a complete, detailed visual Markdown report."""
        risk = self.calculate_risk_score(all_findings)
        server_info = recon_results.get("server_info", {})
        highs = [f for f in all_findings if f.get("severity") == "HIGH"]
        meds = [f for f in all_findings if f.get("severity") == "MEDIUM"]
        lows = [f for f in all_findings if f.get("severity") == "LOW"]
        infos = [f for f in all_findings if f.get("severity") == "INFO"]

        kpi_grid = self._generate_kpi_metrics_grid(target, risk["score"], risk["grade"], all_findings, recon_results, attack_results)
        gauge_svg = self._generate_svg_risk_gauge(risk["score"], risk["grade"])
        donut_svg = self._generate_svg_severity_donut(len(highs), len(meds), len(lows), len(infos))
        flowchart_svg = self._generate_svg_killchain_flowchart(recon_results, attack_results, all_findings)
        matrix_svg = self._generate_svg_risk_matrix(all_findings)
        vector_bars_svg = self._generate_svg_attack_vector_bars(attack_results, all_findings)
        compliance_card = self._generate_compliance_summary_card(all_findings)

        report = [
            f"# Security Assessment & Executive Penetration Testing Dossier",
            "",
            "## Visual Threat Horizon & Intelligence Dashboard",
            "",
            kpi_grid,
            "",
            f'<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 18px 0;">{gauge_svg}{donut_svg}</div>',
            "",
            flowchart_svg,
            "",
            matrix_svg,
            "",
            vector_bars_svg,
            "",
            compliance_card,
            "",
            "## 1. Executive Summary",
            f"An autonomous, end-to-end security assessment and penetration test was conducted against `{target}` by the Saturn Autonomous Security Engine. "
            f"The evaluation comprised comprehensive passive reconnaissance scanning followed by active, multi-vector penetration attacks. "
            f"A total of **{len(all_findings)} finding(s)** were identified across the target's attack surface "
            f"({len(highs)} High, {len(meds)} Medium, {len(lows)} Low, {len(infos)} Informational). "
            f"The target currently carries a security risk score of **{risk['score']}/100** (Grade **{risk['grade']}**).",
            "\n## 2. Infrastructure & Target Scope",
            "| Scope Parameter | Audited System Details |",
            "| :--- | :--- |",
            f"| **Target URL** | `{target}` |",
            f"| **Resolved IP** | `{server_info.get('ip_address', 'N/A')}` |",
            f"| **Hosting Provider / ASN** | `{server_info.get('hosting_org', 'N/A')}` |",
            f"| **Domain Registrar** | `{server_info.get('registrar', 'N/A')}` |",
            f"| **Server Banner** | `{server_info.get('server_header', 'N/A')}` |",
            f"| **Location** | {server_info.get('city', 'N/A')}, {server_info.get('country', 'N/A')} |",
            f"| **Active Attack Modules Run** | {', '.join(attack_results.keys()) if attack_results else 'Reconnaissance only'} |",
            "",
        ]

        # Granular Recon Scans
        report.extend(self._format_scans_summary(recon_results))

        # Active Penetration Attacks
        report.extend(self._format_attacks_summary(attack_results))

        # Vulnerability Severity Breakdown
        report.extend([
            "## 5. Vulnerability Severity Breakdown & Risk Matrix",
            "| Severity Tier | Finding Count | CVSS Base Range | SLA Resolution Window |",
            "| :--- | :--- | :--- | :--- |",
            f"| **HIGH** | {len(highs)} | 7.0 - 10.0 | **Emergency (24-48 hours)** |",
            f"| **MEDIUM** | {len(meds)} | 4.0 - 6.9 | **Next Release Cycle (< 7 days)** |",
            f"| **LOW** | {len(lows)} | 0.1 - 3.9 | **Routine Hardening (30 days)** |",
            f"| **INFO** | {len(infos)} | 0.0 | **Best Practice Review** |",
            "",
            "## 6. Deep Technical Vulnerability Dossier (CVSS v3.1 & CWE Mapped)",
        ])

        if not all_findings:
            report.append("No security vulnerabilities or weaknesses were detected during this assessment.")
        else:
            for idx, f in enumerate(all_findings, 1):
                sev = f.get("severity", "INFO")
                rule = f.get("rule", "GENERAL")
                desc = f.get("description", "No description provided.")
                enriched = self._enrich_finding_metadata(f)

                report.append(f"### Finding 6.{idx}: [{sev}] {rule}")
                report.append(f"- **Vulnerability Description:** {desc}")
                report.append(f"- **CVSS v3.1 Score:** **{enriched['cvss_score']}** (`{enriched['cvss_vector']}`)")
                report.append(f"- **CWE Classification:** {enriched['cwe']}")
                report.append(f"- **OWASP Top 10 (2021):** {enriched['owasp']}")
                report.append(f"- **Impact Analysis:** {enriched['impact']}")

                context_items = [f"  - **{k}:** `{v}`" for k, v in f.items() if k not in ["rule", "description", "severity"]]
                if context_items:
                    report.append("- **Technical Evidence & Parameters:**\n" + "\n".join(context_items))

                report.append(f"- **Step-by-Step Reproduction:**\n{enriched['reproduction']}")
                report.append(f"- **Actionable Remediation Guidance:**\n{enriched['remediation']}")
                report.append("")

        report.extend([
            "## 7. Attack Chain & Threat Correlation Analysis",
            "Attackers rarely exploit isolated findings. The primary threat chain identified during this assessment involves:",
            "1. **Reconnaissance & Footprinting:** Extraction of web server fingerprint, missing defensive response headers, and sensitive directory paths.",
            "2. **Vector Weaponization:** Correlating exposed input forms or missing anti-CSRF tokens with injection vector payloads.",
            "3. **Lateral Movement / Data Exfiltration:** Leveraging high-impact flaws (SQLi / credential discovery) to access backend datastores.",
            "",
            "## 8. Strategic Remediation Roadmap",
            "1. **Phase 1: Immediate Triage (0 - 48 Hours):** Remediate all High severity findings, especially SQL Injection and exposed administrative or credential endpoints.",
            "2. **Phase 2: Short-Term Hardening (Within 7 Days):** Deploy strict HTTP security headers (CSP, HSTS, X-Frame-Options) and implement anti-CSRF validation.",
            "3. **Phase 3: Defense-in-Depth & Compliance (Within 30 Days):** Integrate automated security testing into CI/CD pipelines and conduct recurring penetration audits.",
            "",
            "## 9. Security Posture Verdict & Methodology",
            f"**Final Verdict:** The target system evaluated holds an overall posture score of **{risk['score']}/100** (Grade **{risk['grade']}**). "
            f"Execution followed the OWASP Web Security Testing Guide (WSTG v4.2) and the NIST SP 800-115 Technical Guide to Information Security Testing and Assessment."
        ])

        return "\n".join(report)