"""Optional Ollama-powered security analyst module."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

import requests

from models.alert_model import Alert
from models.log_model import LogRecord


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class AIAnalysis:
    """Structured AI analysis fields stored with an alert."""

    incident_summary: str
    severity_assessment: str
    investigation_steps: str
    mitre_mapping: str
    recommended_remediation: str


class OllamaSecurityAnalyst:
    """Generate alert analysis with a local Ollama model."""

    def __init__(
        self,
        model: str = "qwen2.5:latest",
        base_url: str = "http://localhost:11434",
        timeout_seconds: int = 60,
        enabled: bool = True,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.enabled = enabled

    def analyze(self, alert: Alert, log_record: LogRecord | None = None) -> AIAnalysis:
        """Return AI analysis for an alert, or a deterministic fallback."""
        if not self.enabled:
            return self._fallback_analysis(alert)

        prompt = self._build_prompt(alert, log_record)
        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                },
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
            payload = response.json()
            raw_text = payload.get("response", "{}")
            parsed = json.loads(raw_text)
            return AIAnalysis(
                incident_summary=str(parsed.get("incident_summary", "")),
                severity_assessment=str(parsed.get("severity_assessment", "")),
                investigation_steps=str(parsed.get("investigation_steps", "")),
                mitre_mapping=str(parsed.get("mitre_mapping", "")),
                recommended_remediation=str(
                    parsed.get("recommended_remediation", ""),
                ),
            )
        except Exception as exc:
            LOGGER.warning("AI analysis unavailable, using fallback: %s", exc)
            return self._fallback_analysis(alert)

    @staticmethod
    def apply_to_alert(alert: Alert, analysis: AIAnalysis) -> Alert:
        """Copy generated analysis fields onto an alert model."""
        alert.ai_summary = analysis.incident_summary
        alert.ai_severity_assessment = analysis.severity_assessment
        alert.ai_investigation_steps = analysis.investigation_steps
        alert.ai_mitre_mapping = analysis.mitre_mapping
        alert.ai_recommended_remediation = analysis.recommended_remediation
        return alert

    def _build_prompt(self, alert: Alert, log_record: LogRecord | None) -> str:
        log_details: dict[str, Any] = {}
        if log_record:
            log_details = {
                "event_id": log_record.event_id,
                "timestamp": str(log_record.timestamp),
                "username": log_record.username,
                "computer_name": log_record.computer_name,
                "message": log_record.message[:4000],
            }

        return (
            "You are a SOC Tier 2 security analyst. Analyze this Windows "
            "security alert and respond only as JSON with keys: "
            "incident_summary, severity_assessment, investigation_steps, "
            "mitre_mapping, recommended_remediation.\n\n"
            f"Alert Type: {alert.title}\n"
            f"Alert Severity: {alert.severity}\n"
            f"Event ID: {alert.event_id}\n"
            f"Description: {alert.description}\n"
            f"Log Details JSON: {json.dumps(log_details)}"
        )

    @staticmethod
    def _fallback_analysis(alert: Alert) -> AIAnalysis:
        """Return useful static guidance when Ollama is unavailable."""
        mitre_by_event = {
            4625: "T1110 - Brute Force",
            4720: "T1136 - Create Account",
            4740: "T1110 - Brute Force / Account Lockout Indicator",
        }
        return AIAnalysis(
            incident_summary=(
                f"{alert.title}: {alert.description} Review the source host, "
                "affected account, and nearby authentication events."
            ),
            severity_assessment=(
                f"Current rule severity is {alert.severity}. Escalate if the "
                "activity involves privileged accounts or repeats across hosts."
            ),
            investigation_steps=(
                "Validate the account owner, review surrounding Event IDs 4624 "
                "and 4625, check endpoint activity, and confirm whether the "
                "activity matches an approved change."
            ),
            mitre_mapping=mitre_by_event.get(
                alert.event_id,
                "T1087 - Account Discovery / Requires analyst validation",
            ),
            recommended_remediation=(
                "Reset affected credentials when suspicious, disable unknown "
                "accounts, block offending sources, and document the incident."
            ),
        )
