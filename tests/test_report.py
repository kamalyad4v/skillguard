import unittest
import os
from unittest.mock import patch
from engine.ai_reasoner import AIReasoner
from engine.attack_agent import AttackAgent


class TestReportGeneration(unittest.TestCase):
    def setUp(self):
        self.reasoner = AIReasoner()
        self.target = "https://example.com"
        self.recon = {
            "server_info": {
                "ip_address": "93.184.216.34",
                "hosting_org": "EDGECAST - MCI Communications Services, Inc.",
                "registrar": "RESERVED-Internet Assigned Numbers Authority",
                "server_header": "ECS (dcb/7F83)",
                "country": "US",
                "city": "Norwell",
            }
        }
        self.attacks = {
            "dirbuster": [{"rule": "DIR_FOUND", "description": "Accessible path: /admin", "severity": "HIGH", "path": "/admin", "status_code": 200}],
            "csrf": [{"rule": "CSRF_NO_TOKEN", "description": "Form missing CSRF token", "severity": "MEDIUM", "url": "https://example.com/login", "method": "POST"}],
        }
        self.findings = self.attacks["dirbuster"] + self.attacks["csrf"]

    def test_build_fallback_report_structure(self):
        report_md = self.reasoner.build_fallback_report(
            target=self.target,
            recon_results=self.recon,
            attack_results=self.attacks,
            all_findings=self.findings,
        )
        self.assertIn("# Security Assessment & Executive Penetration Testing Dossier", report_md)
        self.assertIn("## 1. Executive Summary", report_md)
        self.assertIn("## 2. Infrastructure & Target Scope", report_md)
        self.assertIn("## 3. Passive Reconnaissance Scans Breakdown", report_md)
        self.assertIn("## 4. Active Penetration Attacks Execution & Results", report_md)
        self.assertIn("## 5. Vulnerability Severity Breakdown", report_md)
        self.assertIn("## 6. Deep Technical Vulnerability Dossier", report_md)
        self.assertIn("## 7. Attack Chain & Threat Correlation Analysis", report_md)
        self.assertIn("## 8. Strategic Remediation Roadmap", report_md)
        self.assertIn("93.184.216.34", report_md)
        self.assertIn("/admin", report_md)

    @patch("ollama.chat")
    def test_attack_agent_generate_report_persists_file(self, mock_chat):
        mock_chat.return_value = {
            "message": {"content": "# Security Audit\n\n## Executive Summary\nTarget analyzed."}
        }
        agent = AttackAgent(target_url=self.target)
        agent.recon_results = self.recon
        agent.attack_results = self.attacks
        agent.all_findings = list(self.findings)

        report = agent.generate_report()
        self.assertIn("risk_score", report)
        self.assertIn("risk_grade", report)
        self.assertIn("full_report_markdown", report)
        self.assertIn("saved_report_path", report)
        self.assertTrue(os.path.exists(report["saved_report_path"]))

        # Cleanup created test report
        if os.path.exists(report["saved_report_path"]):
            os.remove(report["saved_report_path"])


if __name__ == "__main__":
    unittest.main()
