"""
BaseEngine — abstract base for all MAILOX scan engines.

Contract:
- Subclasses implement _run(domain) → EngineResult
- run() wraps _run() with timeout and uniform error handling
- Engines NEVER raise — errors are captured in EngineResult.error
- An absence of data is NOT automatically a vulnerability — engines must
  distinguish "not found" from "confirmed misconfiguration"
"""
import asyncio
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

import structlog

from app.schemas.findings import Evidence, EvidenceType, Finding, RiskLevel


@dataclass
class EngineResult:
    engine: str
    domain: str
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration_ms: Optional[float] = None
    ran_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def success(self) -> bool:
        return self.error is None

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def finding_count_by_level(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.risk_level.value] = counts.get(f.risk_level.value, 0) + 1
        return counts


class BaseEngine(ABC):
    name: str = "base"
    default_timeout: float = 30.0

    def __init__(self, timeout: Optional[float] = None) -> None:
        self.timeout = timeout if timeout is not None else self.default_timeout
        self.logger = structlog.get_logger(f"mailox.engines.{self.name}")

    @abstractmethod
    async def _run(self, domain: str) -> EngineResult:
        """
        Core engine logic.
        Must return an EngineResult — never raise.
        Set EngineResult.error for engine-level failures.
        """
        ...

    async def run(self, domain: str) -> EngineResult:
        """
        Public entry point: runs _run() with timeout and top-level error capture.
        Always returns an EngineResult.
        """
        t0 = time.monotonic()
        try:
            result = await asyncio.wait_for(self._run(domain), timeout=self.timeout)
        except asyncio.TimeoutError:
            result = EngineResult(
                engine=self.name,
                domain=domain,
                error=f"Engine timed out after {self.timeout:.1f}s",
            )
            self.logger.warning("engine_timeout", domain=domain, timeout=self.timeout)
        except Exception as exc:
            result = EngineResult(
                engine=self.name,
                domain=domain,
                error=f"Unexpected engine error: {type(exc).__name__}",
            )
            self.logger.error("engine_error", domain=domain, error=type(exc).__name__)

        result.duration_ms = (time.monotonic() - t0) * 1000
        self.logger.info(
            "engine_done",
            domain=domain,
            findings=len(result.findings),
            duration_ms=round(result.duration_ms, 1),
            error=result.error,
        )
        return result

    # ── Finding helpers ───────────────────────────────────────────────────────

    def _make_finding(
        self,
        check_id: str,
        title: str,
        description: str,
        risk_level: RiskLevel,
        confidence: float,
        evidence: list[Evidence],
        remediation: str,
        affected_asset: str,
        business_impact: Optional[str] = None,
        references: Optional[list[str]] = None,
    ) -> Finding:
        return Finding(
            engine=self.name,
            check_id=check_id,
            title=title,
            description=description,
            risk_level=risk_level,
            confidence=confidence,
            evidence=evidence,
            remediation=remediation,
            affected_asset=affected_asset,
            business_impact=business_impact,
            references=references or [],
        )

    def _absence_evidence(self, source: str, details: Optional[dict] = None) -> Evidence:
        return Evidence(
            type=EvidenceType.ABSENCE,
            observed_value=None,
            expected_value="Record present",
            source=source,
            technical_details=details,
        )

    def _dns_evidence(
        self,
        source: str,
        observed: str,
        details: Optional[dict] = None,
    ) -> Evidence:
        return Evidence(
            type=EvidenceType.DNS_RECORD,
            observed_value=observed,
            source=source,
            technical_details=details,
        )

    def _analysis_evidence(
        self,
        source: str,
        observed: Optional[str] = None,
        expected: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> Evidence:
        return Evidence(
            type=EvidenceType.ANALYSIS,
            observed_value=observed,
            expected_value=expected,
            source=source,
            technical_details=details,
        )
