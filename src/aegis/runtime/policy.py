"""Deterministic non-AI Policy Engine + Fine-Tuned Semantic ML Classifier + SSRF/SQL/DLP Constraints."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from aegis.ml.classifier import AdversarialGuardrailClassifier
from aegis.models import PolicyAction, RiskTier

INJECTION_SIGNATURES: List[Tuple[str, float, re.Pattern[str]]] = [
    (
        "Instruction Override Directive",
        0.85,
        re.compile(
            r"(ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|prompts)|"
            r"disregard\s+(all\s+)?(system|safety)\s+(rules|guidelines)|"
            r"you\s+are\s+now\s+in\s+developer\s+mode|"
            r"system\s*override\s*:)",
            re.IGNORECASE,
        ),
    ),
    (
        "Markdown / Image Beacon Data Exfiltration",
        0.90,
        re.compile(r"!\[[^\]]*\]\(https?://[^)\s]+\)", re.IGNORECASE),
    ),
    (
        "Hidden Zero-Width Unicode Smuggling",
        0.75,
        re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]{2,}"),
    ),
    (
        "System Prompt / Credential Extraction Probe",
        0.80,
        re.compile(
            r"(print\s+your\s+system\s+prompt|dump\s+all\s+environment\s+variables|"
            r"cat\s+~/.ssh|cat\s+/etc/passwd|\.env\b.*curl\s+http)",
            re.IGNORECASE,
        ),
    ),
    (
        "Shell Chaining / Reverse-Shell Payload",
        0.95,
        re.compile(
            r"(;\s*curl\s+https?://|\|\s*(ba)?sh\b|nc\s+-e\s+/bin/|bash\s+-i\s+>&\s*/dev/tcp/)",
            re.IGNORECASE,
        ),
    ),
]

REDACTION_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("OPENAI_KEY", re.compile(r"(?<![A-Za-z0-9_\-])sk-(?:proj-)?[A-Za-z0-9_]{20,}")),
    ("ANTHROPIC_KEY", re.compile(r"(?<![A-Za-z0-9_\-])sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{24,}\b")),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{16,}\b")),
    ("JWT_BEARER", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("US_SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
]

IRREVERSIBLE_TOOLS: Set[str] = {
    "send_wire_transfer",
    "initiate_payout",
    "transfer_funds",
    "delete_s3_bucket",
    "terminate_production_instance",
    "grant_iam_admin",
    "publish_public_announcement",
    "unseal_vault",
    "decrypt_vault",
    "export_company_dataset",
}

EXTERNAL_EGRESS_TOOLS: Set[str] = {
    "fetch_webhook",
    "http_post",
    "send_external_email",
    "send_email",
    "post_slack_external",
    "upload_artifact",
}

CONFIDENTIAL_READ_TOOLS: Set[str] = {
    "read_customer_pii",
    "query_confidential_db",
    "read_payroll_records",
    "read_financial_ledger",
    "get_vault_record",
}

REVERSIBLE_WRITE_TOOLS: Set[str] = {
    "update_order",
    "db_update",
    "db_insert",
    "db_delete",
    "write_memory",
    "stage_infra_change",
    "update_ticket_status",
}

BLOCKED_METADATA_HOSTS: Set[str] = {
    "169.254.169.254",
    "metadata.google.internal",
    "100.100.100.200",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
}


@dataclass
class PolicyEvaluation:
    risk_tier: RiskTier
    action: PolicyAction
    injection_score: float
    ml_attack_probability: float
    reasons: List[str] = field(default_factory=list)
    redacted_arguments: Dict[str, Any] = field(default_factory=dict)


class PolicyEngine:
    """
    Combines hard deterministic non-AI rules (SSRF, SQL DDL, Egress Allowlist, Owner-Gate Tiers)
    with a Fine-Tuned Semantic ML Guardrail (`AdversarialGuardrailClassifier`).
    """

    def __init__(
        self,
        high_value_amount_threshold: float = 5000.0,
        allowed_egress_domains: Optional[Set[str]] = None,
        ml_classifier: Optional[AdversarialGuardrailClassifier] = None,
        ml_block_threshold: float = 0.65,
    ) -> None:
        self.high_value_amount_threshold = high_value_amount_threshold
        self.allowed_egress_domains = allowed_egress_domains or set()
        self.ml_classifier = ml_classifier or AdversarialGuardrailClassifier()
        self.ml_block_threshold = ml_block_threshold
        if self.ml_classifier.pipeline is None:
            self.ml_classifier.train_base()

    def classify_tool(self, tool_name: str, arguments: Dict[str, Any]) -> RiskTier:
        lower = tool_name.lower()
        if lower in IRREVERSIBLE_TOOLS or any(
            kw in lower for kw in ("wire", "payout", "transfer", "grant_iam", "destroy", "vault", "export_company")
        ):
            return RiskTier.IRREVERSIBLE_CRITICAL
        if lower in EXTERNAL_EGRESS_TOOLS or any(
            kw in lower for kw in ("webhook", "external_email", "http_post", "upload")
        ):
            return RiskTier.EXTERNAL_EGRESS
        if lower in CONFIDENTIAL_READ_TOOLS or any(
            kw in lower for kw in ("pii", "confidential", "payroll", "secret")
        ):
            return RiskTier.CONFIDENTIAL_READ
        if lower in REVERSIBLE_WRITE_TOOLS or any(
            kw in lower for kw in ("update", "insert", "delete", "write", "stage", "mutate")
        ):
            return RiskTier.REVERSIBLE_WRITE
        sql = str(arguments.get("sql") or arguments.get("query") or "")
        if re.search(r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE)\b", sql, re.IGNORECASE):
            return RiskTier.REVERSIBLE_WRITE
        return RiskTier.READ_ONLY

    def redact_sensitive(self, data: Any) -> Tuple[Any, List[str]]:
        redacted_types: Set[str] = set()

        def _scrub(val: Any) -> Any:
            if isinstance(val, str):
                out = val
                for label, rx in REDACTION_PATTERNS:
                    if rx.search(out):
                        redacted_types.add(label)
                        out = rx.sub(f"[REDACTED:{label}]", out)
                return out
            if isinstance(val, dict):
                return {k: _scrub(v) for k, v in val.items()}
            if isinstance(val, list):
                return [_scrub(item) for item in val]
            return val

        cleaned = _scrub(data)
        return cleaned, sorted(redacted_types)

    def scan_injection(self, payload_text: str) -> Tuple[float, List[str]]:
        max_score = 0.0
        matched: List[str] = []
        for name, weight, rx in INJECTION_SIGNATURES:
            if rx.search(payload_text):
                matched.append(name)
                max_score = max(max_score, weight)
        return round(max_score, 2), matched

    def check_ssrf_and_egress(self, arguments: Dict[str, Any]) -> List[str]:
        violations: List[str] = []
        serialized = json.dumps(arguments, default=str)
        urls = re.findall(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s\"')\]>]+", serialized)
        for raw_url in urls:
            parsed = urlparse(raw_url)
            scheme = (parsed.scheme or "").lower()
            host = (parsed.hostname or "").lower()
            if scheme not in {"http", "https"}:
                violations.append(f"Disallowed URI scheme `{scheme}://` in tool argument.")
                continue
            if host in BLOCKED_METADATA_HOSTS:
                violations.append(f"SSRF attempt blocked targeting protected host `{host}`.")
                continue
            try:
                ip = ipaddress.ip_address(host)
                if ip.is_private or ip.is_loopback or ip.is_link_local:
                    violations.append(f"SSRF attempt blocked targeting private/link-local IP `{ip}`.")
                    continue
            except ValueError:
                pass
            if self.allowed_egress_domains and host not in self.allowed_egress_domains:
                violations.append(f"Outbound domain `{host}` is not in enterprise egress allowlist.")
        return violations

    def check_sql_safety(self, arguments: Dict[str, Any]) -> List[str]:
        violations: List[str] = []
        sql = str(arguments.get("sql") or arguments.get("query") or "").strip()
        if not sql:
            return violations
        if re.search(r"\b(DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE|ALTER\s+SYSTEM)\b", sql, re.I):
            violations.append("Catastrophic DDL (`DROP`/`TRUNCATE`/`ALTER SYSTEM`) deterministically blocked.")
        if re.search(r"^\s*(UPDATE|DELETE)\b", sql, re.I) and not re.search(r"\bWHERE\b", sql, re.I):
            violations.append("Unbounded `UPDATE`/`DELETE` without `WHERE` clause deterministically blocked.")
        if re.search(r"\bWHERE\s+(1\s*=\s*1|TRUE)\b", sql, re.I):
            violations.append("Tautological `WHERE 1=1` bulk mutation deterministically blocked.")
        return violations

    def evaluate(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        untrusted_context: Optional[str] = None,
    ) -> PolicyEvaluation:
        reasons: List[str] = []
        redacted_args, redacted_labels = self.redact_sensitive(arguments)
        if redacted_labels:
            reasons.append(f"Redacted sensitive tokens/PII in arguments: {', '.join(redacted_labels)}")

        combined_text = f"tool={tool_name} args={json.dumps(arguments, default=str)}"
        if untrusted_context:
            combined_text += "\n" + untrusted_context

        inj_score, inj_matches = self.scan_injection(combined_text)
        for m in inj_matches:
            reasons.append(f"Deterministic injection signature: {m}")

        # Score ONLY untrusted context or free-text values with Fine-Tuned Semantic ML Classifier
        text_for_ml = untrusted_context or json.dumps(arguments, default=str)
        ml_prob = self.ml_classifier.predict_attack_probability(text_for_ml)
        if ml_prob >= self.ml_block_threshold:
            reasons.append(
                f"Fine-Tuned Adversarial Guardrail Model flagged semantic attack (p={ml_prob:.2f} >= {self.ml_block_threshold})."
            )

        ssrf_issues = self.check_ssrf_and_egress(arguments)
        sql_issues = self.check_sql_safety(arguments)
        reasons.extend(ssrf_issues)
        reasons.extend(sql_issues)

        risk_tier = self.classify_tool(tool_name, arguments)

        if ssrf_issues or sql_issues or inj_score >= 0.75 or ml_prob >= self.ml_block_threshold:
            return PolicyEvaluation(
                risk_tier=risk_tier,
                action=PolicyAction.BLOCK,
                injection_score=inj_score,
                ml_attack_probability=ml_prob,
                reasons=reasons,
                redacted_arguments=redacted_args,
            )

        amount = self._extract_amount(arguments)
        if risk_tier == RiskTier.IRREVERSIBLE_CRITICAL or (
            amount is not None and amount >= self.high_value_amount_threshold
        ):
            reasons.append(
                f"Hard Owner-Verification Constraint: Tool `{tool_name}`"
                + (f" (${amount:,.2f})" if amount is not None else "")
                + " is LOCKED until verified by offline Owner Ed25519 signature + 6-digit TOTP."
            )
            return PolicyEvaluation(
                risk_tier=RiskTier.IRREVERSIBLE_CRITICAL,
                action=PolicyAction.REQUIRE_OWNER_SIGNATURE,
                injection_score=inj_score,
                ml_attack_probability=ml_prob,
                reasons=reasons,
                redacted_arguments=redacted_args,
            )

        return PolicyEvaluation(
            risk_tier=risk_tier,
            action=PolicyAction.ALLOW,
            injection_score=inj_score,
            ml_attack_probability=ml_prob,
            reasons=reasons or ["Passed deterministic + fine-tuned ML guardrail checks."],
            redacted_arguments=redacted_args,
        )

    @staticmethod
    def _extract_amount(arguments: Dict[str, Any]) -> Optional[float]:
        for key in ("amount", "amount_usd", "total", "transfer_amount", "payout_amount"):
            if key in arguments:
                try:
                    return float(arguments[key])
                except (TypeError, ValueError):
                    return None
        return None
