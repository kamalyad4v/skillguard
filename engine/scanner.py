import re
from models.skill import SkillManifest


class ASTScanner:
    # (pattern, rule_id, description, severity)
    SUSPICIOUS_PATTERNS = [
        (r"(eval|exec)\s*\(", "AST05", "Unsafe dynamic code execution", "HIGH"),
        (r"unserialize\s*\(", "AST05", "Insecure deserialization", "HIGH"),
        (r"(curl|wget)\s+.*\|\s*(sh|bash)", "AST01", "Pipe-to-shell download pattern", "HIGH"),
        (r"\bnc\s+-e\b|bash -i", "AST01", "Reverse shell pattern", "HIGH"),
        (r"(\.env\b|/etc/passwd|id_rsa|\.ssh/)", "AST03", "Sensitive credential/file access", "HIGH"),
        (r"subprocess\.(run|call|Popen)\s*\(.*shell\s*=\s*True", "AST05", "Shell injection risk via subprocess", "HIGH"),
        (r"os\.system\s*\(", "AST05", "Unsafe OS command execution", "MEDIUM"),
        (r"https?://[^\s\"']+", "AST02", "External network reference in instructions", "LOW"),
        (r"base64\.b64decode|base64_decode", "AST05", "Obfuscated payload via base64 decode", "MEDIUM"),
        (r"pickle\.loads\s*\(", "AST05", "Insecure deserialization via pickle", "HIGH"),
    ]

    def scan_instructions(self, instructions: str) -> list[dict]:
        findings = []
        for pattern, rule_id, description, severity in self.SUSPICIOUS_PATTERNS:
            match = re.search(pattern, instructions, re.IGNORECASE)
            if match:
                findings.append({
                    "rule": rule_id,
                    "description": description,
                    "matched_text": match.group(0),
                    "severity": severity,
                })
        return findings

    def verify_privileges(self, manifest: SkillManifest) -> list[dict]:
        findings = []
        perms = manifest.permissions

        if perms.network_access and not perms.allowed_domains:
            findings.append({
                "rule": "AST03",
                "description": "Network access granted with no domain allowlist",
                "severity": "MEDIUM",
            })

        if perms.file_system_write and perms.network_access:
            findings.append({
                "rule": "AST03",
                "description": "Skill can both write to disk and reach the network — exfiltration risk",
                "severity": "HIGH",
            })

        if not manifest.signature:
            findings.append({
                "rule": "AST08",
                "description": "Skill has no integrity signature",
                "severity": "LOW",
            })

        return findings

    def evaluate(self, manifest: SkillManifest) -> dict:
        instruction_findings = self.scan_instructions(manifest.instructions)
        privilege_findings = self.verify_privileges(manifest)
        all_findings = instruction_findings + privilege_findings

        has_high = any(f["severity"] == "HIGH" for f in all_findings)
        status = "REJECTED" if has_high else ("REVIEW" if all_findings else "APPROVED")

        return {
            "skill_id": manifest.id,
            "skill_name": manifest.name,
            "status": status,
            "risk_count": len(all_findings),
            "findings": all_findings,
        }