import requests
import json
import time
import os
from urllib.parse import urlparse
from engine.web_scanner import WebScanner
from engine.ai_reasoner import AIReasoner
from engine.attacks import ATTACK_REGISTRY, ALL_ATTACKS


class AttackAgent:
    """
    Autonomous AI-driven penetration testing agent.

    Runs a multi-phase pipeline:
      1. RECON   — passive reconnaissance via WebScanner
      2. PLAN    — AI analyzes recon, picks first attack module
      3. ATTACK  — execute the chosen module
      4. ANALYZE — AI evaluates results, chains to next attack or stops
      5. REPEAT  — loop until all relevant modules are exhausted
      6. REPORT  — AI generates comprehensive pentest report
    """

    MAX_ITERATIONS = 10

    def __init__(self, target_url: str, model: str = "gemma:latest", event_callback=None):
        if not target_url.startswith("http"):
            target_url = "https://" + target_url
        self.target_url = target_url.rstrip("/")
        self.domain = urlparse(self.target_url).netloc
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "SkillGuard-PenTest/1.0"})

        self.reasoner = AIReasoner(model=model)
        self.web_scanner = WebScanner(self.target_url)
        self.event_callback = event_callback

        # State
        self.recon_results = {}
        self.attack_results = {}
        self.all_findings = []
        self.execution_log = []
        self.context = {}

    # ── helpers ──────────────────────────────────────────────────────────

    def _log(self, phase: str, message: str):
        entry = {
            "phase": phase,
            "message": message,
            "timestamp": time.time(),
        }
        self.execution_log.append(entry)
        print(f"[{phase}] {message}")
        if self.event_callback:
            try:
                self.event_callback("log", entry)
            except Exception:
                pass

    # ── phase 1: recon ──────────────────────────────────────────────────

    def run_recon(self) -> dict:
        """Run passive reconnaissance via the existing WebScanner."""
        if self.event_callback:
            self.event_callback("phase", {"phase": "RECON", "status": "running"})
        self._log("RECON", "Starting passive reconnaissance...")
        self.recon_results = self.web_scanner.scan()
        new_findings = self.recon_results.get("findings", [])
        self.all_findings.extend(new_findings)

        # Build context that attack modules can use
        self.context["forms"] = self.web_scanner._discover_form_fields()
        self.context["recon"] = self.recon_results
        self.context["server_info"] = self.recon_results.get("server_info", {})
        self.context["github_repo"] = self.recon_results.get("github_repo", {})

        finding_count = len(new_findings)
        form_count = len(self.context["forms"])
        self._log(
            "RECON",
            f"Recon complete — {finding_count} findings, {form_count} forms discovered",
        )
        if self.event_callback:
            for f in new_findings:
                self.event_callback("finding", f)
            self.event_callback("recon_complete", {
                "findings": new_findings,
                "server_info": self.context["server_info"],
                "forms_count": form_count,
            })
            self.event_callback("phase", {"phase": "RECON", "status": "completed"})
        return self.recon_results

    # ── phase 2-5: agentic attack loop ──────────────────────────────────

    def _run_attack_module(self, attack_name: str) -> list[dict]:
        """Instantiate and execute a single attack module."""
        if attack_name not in ATTACK_REGISTRY:
            self._log("ATTACK", f"Unknown attack module: {attack_name}")
            return []

        if self.event_callback:
            self.event_callback("phase", {"phase": "ATTACK", "module": attack_name, "status": "running"})
        self._log("ATTACK", f"Launching {attack_name} module...")

        attack_class = ATTACK_REGISTRY[attack_name]
        attack = attack_class(self.target_url, self.domain, self.session)

        start = time.time()
        findings = attack.run(context=self.context)
        elapsed = round(time.time() - start, 1)

        self.attack_results[attack_name] = findings
        self.all_findings.extend(findings)

        # Context chaining: feed discovered paths into context for subsequent attacks
        if attack_name == "dirbuster":
            discovered = self.context.setdefault("discovered_paths", [])
            for f in findings:
                p = f.get("path")
                if p and p not in discovered:
                    discovered.append(p)

        high = sum(1 for f in findings if f.get("severity") == "HIGH")
        self._log(
            "ATTACK",
            f"{attack_name} complete in {elapsed}s — "
            f"{len(findings)} findings ({high} HIGH)",
        )

        if self.event_callback:
            for f in findings:
                self.event_callback("finding", f)
            self.event_callback("module_complete", {
                "module": attack_name,
                "elapsed": elapsed,
                "findings_count": len(findings),
                "high_count": high,
                "findings": findings,
            })
        return findings

    def run_agentic_loop(self) -> dict:
        """AI-driven attack loop: plan → attack → analyze → repeat."""
        if self.event_callback:
            self.event_callback("phase", {"phase": "PLAN", "status": "running"})
        self._log("AGENT", "Starting agentic attack loop...")
        completed_attacks = set()
        iteration = 0

        while iteration < self.MAX_ITERATIONS:
            iteration += 1
            self._log("AGENT", f"--- Iteration {iteration}/{self.MAX_ITERATIONS} ---")

            # Ask the AI planner what to do next
            decision = self.reasoner.plan_next_attack(
                target=self.target_url,
                recon_results=self.recon_results,
                attack_results=self.attack_results,
                completed_attacks=list(completed_attacks),
                available_attacks=[a for a in ALL_ATTACKS if a not in completed_attacks],
                all_findings=self.all_findings,
            )

            self._log(
                "AGENT",
                f"AI decision: {decision.get('next_action')} — "
                f"{decision.get('reasoning', 'no reason given')}",
            )

            if self.event_callback:
                self.event_callback("decision", {
                    "iteration": iteration,
                    "next_action": decision.get("next_action"),
                    "reasoning": decision.get("reasoning", ""),
                    "priority": decision.get("priority", "MEDIUM"),
                    "completed_attacks": list(completed_attacks),
                })

            next_action = decision.get("next_action", "stop")

            if next_action == "stop":
                self._log("AGENT", "AI decided to stop the attack loop.")
                break

            if next_action in completed_attacks:
                self._log("AGENT", f"Skipping {next_action} — already completed")
                continue

            if next_action not in ATTACK_REGISTRY:
                self._log("AGENT", f"Unknown action '{next_action}', skipping")
                continue

            # Execute the chosen attack
            findings = self._run_attack_module(next_action)
            completed_attacks.add(next_action)

            # Feed results back into context for chaining
            self.context["latest_findings"] = findings
            self.context["completed_attacks"] = list(completed_attacks)

        self._log(
            "AGENT",
            f"Agentic loop finished after {iteration} iterations — "
            f"{len(completed_attacks)} modules executed",
        )
        if self.event_callback:
            self.event_callback("phase", {"phase": "PLAN", "status": "completed"})
        return self.attack_results

    # ── phase 6: report ─────────────────────────────────────────────────

    def generate_report(self) -> dict:
        """Generate the final comprehensive pentest report."""
        if self.event_callback:
            self.event_callback("phase", {"phase": "REPORT", "status": "running"})
        self._log("REPORT", "Generating final pentest report via AI...")

        risk = self.reasoner.calculate_risk_score(self.all_findings)

        ai_report = self.reasoner.generate_pentest_report(
            target=self.target_url,
            recon_results=self.recon_results,
            attack_results=self.attack_results,
            all_findings=self.all_findings,
        )

        report_timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        saved_report_path = None
        saved_pdf_path = None

        # Persist full report markdown and PDF to disk
        try:
            reports_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "reports"))
            os.makedirs(reports_dir, exist_ok=True)
            safe_domain = self.domain.replace(":", "_").replace("/", "_")
            timestamp_id = int(time.time())
            filename = f"pentest_{safe_domain}_{timestamp_id}.md"
            saved_report_path = os.path.join(reports_dir, filename)
            with open(saved_report_path, "w", encoding="utf-8") as f:
                f.write(ai_report)

            # Auto-generate visual PDF dossier
            pdf_filename = f"pentest_{safe_domain}_{timestamp_id}.pdf"
            pdf_target_path = os.path.join(reports_dir, pdf_filename)
            try:
                from engine.pdf_generator import SkillGuardPDFGenerator
                pdf_gen = SkillGuardPDFGenerator()
                pdf_gen.build_pdf(
                    target=self.target_url,
                    output_filepath=pdf_target_path,
                    risk_score=risk["score"],
                    risk_grade=risk["grade"],
                    all_findings=self.all_findings,
                    recon_results=self.recon_results,
                    attack_results=self.attack_results,
                    raw_markdown=ai_report,
                )
                saved_pdf_path = pdf_target_path
            except Exception as pe:
                print(f"[REPORT] PDF auto-generation note: {pe}")
        except Exception:
            pass

        report = {
            "target": self.target_url,
            "domain": self.domain,
            "timestamp": report_timestamp,
            "risk_score": risk["score"],
            "risk_grade": risk["grade"],
            "total_findings": len(self.all_findings),
            "findings_by_severity": {
                sev: len([f for f in self.all_findings if f.get("severity") == sev])
                for sev in ["HIGH", "MEDIUM", "LOW", "INFO"]
            },
            "saved_report_path": saved_report_path,
            "saved_pdf_path": saved_pdf_path,
            "recon": self.recon_results,
            "attacks": self.attack_results,
            "all_findings": self.all_findings,
            "full_report_markdown": ai_report,
            "execution_log": self.execution_log,
        }

        self._log("REPORT", f"Report generation complete{' — saved to ' + saved_report_path if saved_report_path else ''}")
        if self.event_callback:
            self.event_callback("report", report)
            self.event_callback("phase", {"phase": "REPORT", "status": "completed"})
        return report

    # ── full pipeline ───────────────────────────────────────────────────

    def run_full_pentest(self) -> dict:
        """Execute the complete autonomous pentest pipeline."""
        self._log("AGENT", f"=== SkillGuard Attack Agent targeting {self.target_url} ===")

        self.run_recon()          # Phase 1
        self.run_agentic_loop()   # Phase 2-5
        report = self.generate_report()  # Phase 6

        self._log("AGENT", "=== Pentest complete ===")
        if self.event_callback:
            self.event_callback("complete", report)
        return report
