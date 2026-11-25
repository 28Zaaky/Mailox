"""
Reporting Engine.

Generates scan reports in three formats (json, html, csv) and three types
(executive, technical, full).

No external template files — HTML template is embedded as a string.
"""
import csv
import io
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from app.db.models.scan import FindingStatus, RiskLevel, ScanStatus


# ── Data contracts ────────────────────────────────────────────────────────────

@dataclass
class ReportFinding:
    id: str
    engine: str
    check_id: str
    title: str
    description: str
    risk_level: str
    confidence: float
    affected_asset: Optional[str]
    remediation: str
    evidence: Any
    references: list
    status: str
    cvss_score: Optional[float]
    created_at: datetime
    last_seen_at: Optional[datetime]


@dataclass
class ReportScan:
    id: str
    org_id: str
    target_domain: str
    status: str
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    risk_score: Optional[float]
    finding_count: int
    engine_runs: list[dict]


@dataclass
class ScanReport:
    report_type: str
    format: str
    generated_at: datetime
    scan: ReportScan
    findings: list[ReportFinding]
    risk_summary: dict
    chains: list[dict]


# ── Report generator ─────────────────────────────────────────────────────────

class ReportingEngine:

    def generate(
        self,
        scan: ReportScan,
        findings: list[ReportFinding],
        chains: list[dict],
        report_type: str = "full",
        fmt: str = "json",
    ) -> tuple[str | bytes, str]:
        """
        Returns (content, content_type).
        content_type drives HTTP response headers.
        """
        risk_summary = self._build_risk_summary(findings, scan.risk_score)

        report = ScanReport(
            report_type=report_type,
            format=fmt,
            generated_at=datetime.now(timezone.utc),
            scan=scan,
            findings=self._filter_findings(findings, report_type),
            risk_summary=risk_summary,
            chains=chains,
        )

        if fmt == "json":
            return self._render_json(report), "application/json"
        elif fmt == "html":
            return self._render_html(report), "text/html; charset=utf-8"
        elif fmt == "csv":
            return self._render_csv(report), "text/csv; charset=utf-8"
        else:
            raise ValueError(f"Unsupported format: {fmt}")

    # ── Filter by report type ─────────────────────────────────────────────────

    def _filter_findings(
        self, findings: list[ReportFinding], report_type: str
    ) -> list[ReportFinding]:
        if report_type == "executive":
            # Top findings only: CRITICAL + HIGH, up to 20
            top = [f for f in findings if f.risk_level in ("critical", "high")]
            return sorted(top, key=lambda f: (
                {"critical": 0, "high": 1}.get(f.risk_level, 9),
                -f.confidence,
            ))[:20]
        # technical + full: all findings
        return findings

    # ── Risk summary ──────────────────────────────────────────────────────────

    def _build_risk_summary(
        self, findings: list[ReportFinding], risk_score: Optional[float]
    ) -> dict:
        counts: dict[str, int] = {lvl.value: 0 for lvl in RiskLevel}
        status_counts: dict[str, int] = {s.value: 0 for s in FindingStatus}

        for f in findings:
            counts[f.risk_level] = counts.get(f.risk_level, 0) + 1
            status_counts[f.status] = status_counts.get(f.status, 0) + 1

        return {
            "risk_score": risk_score,
            "total_findings": len(findings),
            "by_severity": counts,
            "by_status": status_counts,
            "posture": self._posture_label(risk_score),
        }

    def _posture_label(self, score: Optional[float]) -> str:
        if score is None:
            return "unknown"
        if score >= 75:
            return "critical"
        if score >= 50:
            return "high"
        if score >= 25:
            return "medium"
        if score > 0:
            return "low"
        return "clean"

    # ── JSON ──────────────────────────────────────────────────────────────────

    def _render_json(self, report: ScanReport) -> str:
        def _dt(v: Any) -> Any:
            if isinstance(v, datetime):
                return v.isoformat()
            raise TypeError(f"Not serializable: {type(v)}")

        payload: dict[str, Any] = {
            "report_type": report.report_type,
            "generated_at": report.generated_at.isoformat(),
            "scan": {
                "id": report.scan.id,
                "org_id": report.scan.org_id,
                "target_domain": report.scan.target_domain,
                "status": report.scan.status,
                "created_at": report.scan.created_at.isoformat(),
                "started_at": report.scan.started_at.isoformat() if report.scan.started_at else None,
                "completed_at": report.scan.completed_at.isoformat() if report.scan.completed_at else None,
                "risk_score": report.scan.risk_score,
                "finding_count": report.scan.finding_count,
                "engine_runs": report.scan.engine_runs,
            },
            "risk_summary": report.risk_summary,
            "chains": report.chains,
            "findings": [self._finding_to_dict(f, report.report_type) for f in report.findings],
        }
        return json.dumps(payload, default=_dt, indent=2, ensure_ascii=False)

    def _finding_to_dict(self, f: ReportFinding, report_type: str) -> dict:
        base = {
            "id": f.id,
            "engine": f.engine,
            "check_id": f.check_id,
            "title": f.title,
            "risk_level": f.risk_level,
            "confidence": f.confidence,
            "affected_asset": f.affected_asset,
            "status": f.status,
            "cvss_score": f.cvss_score,
            "created_at": f.created_at.isoformat(),
        }
        if report_type in ("technical", "full"):
            base.update({
                "description": f.description,
                "remediation": f.remediation,
                "evidence": f.evidence,
                "references": f.references,
                "last_seen_at": f.last_seen_at.isoformat() if f.last_seen_at else None,
            })
        return base

    # ── HTML ──────────────────────────────────────────────────────────────────

    def _render_html(self, report: ScanReport) -> str:
        SEV_COLOR  = {"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706", "low": "#2563eb", "info": "#6b7280"}
        SEV_BG     = {"critical": "#fef2f2", "high": "#fff7ed", "medium": "#fffbeb", "low": "#eff6ff", "info": "#f9fafb"}

        summary  = report.risk_summary
        score    = summary.get("risk_score")
        score_str = f"{score:.1f}" if score is not None else "—"
        posture  = summary.get("posture", "unknown")
        bysev    = summary.get("by_severity", {})
        total    = summary.get("total_findings", 0)
        is_full  = report.report_type in ("technical", "full")

        posture_color = {
            "critical": "#dc2626", "high": "#ea580c",
            "medium": "#d97706", "low": "#2563eb",
            "clean": "#16a34a", "unknown": "#6b7280",
        }.get(posture, "#6b7280")

        # ── Severity summary pills ────────────────────────────────────────────
        sev_pills = ""
        for lvl in ("critical", "high", "medium", "low", "info"):
            count = bysev.get(lvl, 0)
            if count == 0:
                continue
            c = SEV_COLOR[lvl]
            bg = SEV_BG[lvl]
            sev_pills += (
                f"<div class='pill' style='border-color:{c}20;background:{bg}'>"
                f"<span class='pill-dot' style='background:{c}'></span>"
                f"<span class='pill-count' style='color:{c}'>{count}</span>"
                f"<span class='pill-label'>{lvl.capitalize()}</span>"
                f"</div>"
            )

        # ── Risk chains ───────────────────────────────────────────────────────
        chains_html = ""
        for c in report.chains:
            chains_html += (
                f"<div class='chain'>"
                f"<div class='chain-title'><code>{_esc(c.get('rule_id',''))}</code> — {_esc(c.get('title',''))}</div>"
                f"<div class='chain-desc'>{_esc(c.get('description',''))}</div>"
                f"</div>"
            )
        chains_section = (
            f"<section><h2>Attack Chains <span class='count'>{len(report.chains)}</span></h2>{chains_html}</section>"
            if report.chains else ""
        )

        # ── Findings rows ─────────────────────────────────────────────────────
        rows = ""
        for i, f in enumerate(report.findings):
            c   = SEV_COLOR.get(f.risk_level, "#6b7280")
            bg  = SEV_BG.get(f.risk_level, "#f9fafb")
            asset = _esc(f.affected_asset or "—")
            cvss  = f"{f.cvss_score:.1f}" if f.cvss_score else "—"

            if is_full:
                refs = "".join(_ref_html(r) for r in (f.references or []))
                evidence_raw = f.evidence if isinstance(f.evidence, str) else (
                    json.dumps(f.evidence, indent=2) if f.evidence else ""
                )
                detail_html = (
                    f"<tr class='detail-row' id='d{i}'><td colspan='5'>"
                    f"<div class='detail-box'>"
                    f"<div class='detail-col'>"
                    f"<div class='detail-label'>Description</div>"
                    f"<div class='detail-text'>{_esc(f.description)}</div>"
                    f"<div class='detail-label' style='margin-top:12px'>Remediation</div>"
                    f"<div class='detail-text'>{_esc(f.remediation)}</div>"
                    f"{'<div class=detail-label style=margin-top:12px>References</div><div class=detail-text>' + refs + '</div>' if refs else ''}"
                    f"</div>"
                    f"{'<div class=detail-col><div class=detail-label>Evidence</div><pre class=evidence>' + _esc(str(evidence_raw)) + '</pre></div>' if evidence_raw else ''}"
                    f"</div></td></tr>"
                )
                toggle = f"onclick=\"var r=document.getElementById('d{i}');r.style.display=r.style.display==='table-row'?'none':'table-row'\""
                rows += (
                    f"<tr class='finding-row' {toggle}>"
                    f"<td><span class='badge' style='color:{c};background:{bg};border-color:{c}30'>{f.risk_level.upper()}</span></td>"
                    f"<td class='mono'>{_esc(f.check_id)}</td>"
                    f"<td><strong>{_esc(f.title)}</strong><br><span class='asset-txt'>{asset}</span></td>"
                    f"<td><span class='status-badge'>{_esc(f.status.replace('_',' '))}</span></td>"
                    f"<td class='mono right'>{cvss}</td>"
                    f"</tr>"
                    f"{detail_html}"
                )
            else:
                rows += (
                    f"<tr>"
                    f"<td><span class='badge' style='color:{c};background:{bg};border-color:{c}30'>{f.risk_level.upper()}</span></td>"
                    f"<td class='mono'>{_esc(f.check_id)}</td>"
                    f"<td><strong>{_esc(f.title)}</strong><br><span class='asset-txt'>{asset}</span></td>"
                    f"<td><span class='status-badge'>{_esc(f.status.replace('_',' '))}</span></td>"
                    f"<td class='mono right'>{cvss}</td>"
                    f"</tr>"
                )

        expand_hint = "<p class='hint'>Click a row to expand details.</p>" if is_full else ""
        generated  = report.generated_at.strftime("%d %B %Y, %H:%M UTC")
        scan_date  = report.scan.created_at.strftime("%d %B %Y")
        rtype_label = _esc({"executive": "Executive Summary", "technical": "Technical Report", "full": "Full Report"}.get(report.report_type, report.report_type.title()))

        return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Report — {_esc(report.scan.target_domain)}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
:root{{--fg:#111827;--fg2:#374151;--fg3:#6b7280;--border:#e5e7eb;--bg:#ffffff;--bg2:#f9fafb;--bg3:#f3f4f6;--accent:#111827;font-size:14px}}
body{{background:var(--bg);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Inter',Helvetica,Arial,sans-serif;line-height:1.6;max-width:960px;margin:0 auto;padding:48px 40px 80px}}
h1{{font-size:1.75rem;font-weight:700;letter-spacing:-0.02em;color:var(--fg);margin-bottom:6px}}
h2{{font-size:.7rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--fg3);margin:40px 0 14px;padding-bottom:8px;border-bottom:1px solid var(--border)}}
h2 .count{{font-weight:400;color:var(--fg3);margin-left:6px}}
section{{margin-bottom:40px}}
.header{{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:40px;padding-bottom:28px;border-bottom:2px solid var(--fg)}}
.brand{{font-size:.75rem;font-weight:700;letter-spacing:.15em;text-transform:uppercase;color:var(--fg3)}}
.meta-row{{font-size:.8rem;color:var(--fg3);margin-top:4px}}
.meta-row strong{{color:var(--fg2)}}
.score-block{{text-align:right}}
.score-num{{font-size:3rem;font-weight:800;line-height:1;letter-spacing:-0.04em;color:var(--accent)}}
.score-sub{{font-size:.75rem;text-transform:uppercase;letter-spacing:.1em;color:var(--fg3);margin-top:4px}}
.posture{{font-weight:700;color:{posture_color}}}
.pills{{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:4px}}
.pill{{display:flex;align-items:center;gap:7px;padding:8px 14px;border-radius:8px;border:1px solid;font-size:.8rem}}
.pill-dot{{width:8px;height:8px;border-radius:50%;flex-shrink:0}}
.pill-count{{font-weight:700;font-size:1rem}}
.pill-label{{color:var(--fg3);font-size:.75rem}}
table{{width:100%;border-collapse:collapse;font-size:.8rem}}
thead th{{text-align:left;padding:9px 12px;background:var(--bg2);color:var(--fg3);font-weight:600;font-size:.7rem;letter-spacing:.06em;text-transform:uppercase;border-top:1px solid var(--border);border-bottom:1px solid var(--border)}}
thead th.right{{text-align:right}}
td{{padding:11px 12px;border-bottom:1px solid var(--border);vertical-align:middle}}
.finding-row{{cursor:pointer;transition:background .1s}}
.finding-row:hover{{background:var(--bg2)}}
.detail-row{{display:none}}
.detail-box{{display:grid;grid-template-columns:1fr 1fr;gap:20px;padding:16px;background:var(--bg2);border-radius:6px;margin:4px 0}}
.detail-col{{min-width:0}}
.detail-label{{font-size:.65rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--fg3);margin-bottom:5px}}
.detail-text{{font-size:.8rem;color:var(--fg2);line-height:1.6;white-space:pre-wrap;word-break:break-word}}
.evidence{{font-family:'Menlo','Consolas','Courier New',monospace;font-size:.72rem;background:#f3f4f6;border:1px solid var(--border);border-radius:4px;padding:10px;overflow-x:auto;white-space:pre;max-height:200px;overflow-y:auto;color:var(--fg2)}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.65rem;font-weight:700;letter-spacing:.06em;border:1px solid}}
.status-badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.7rem;background:var(--bg3);color:var(--fg3);border:1px solid var(--border);text-transform:capitalize}}
.mono{{font-family:'Menlo','Consolas','Courier New',monospace;font-size:.75rem;color:var(--fg2)}}
.right{{text-align:right}}
.asset-txt{{font-family:'Menlo','Consolas',monospace;font-size:.72rem;color:var(--fg3)}}
a{{color:#2563eb;text-decoration:none}}
a:hover{{text-decoration:underline}}
.chain{{border-left:3px solid var(--border);padding:10px 16px;margin-bottom:12px;border-radius:0 6px 6px 0;background:var(--bg2)}}
.chain-title{{font-weight:600;color:var(--fg);font-size:.85rem;margin-bottom:4px}}
.chain-desc{{font-size:.8rem;color:var(--fg3);line-height:1.5}}
.hint{{font-size:.75rem;color:var(--fg3);margin-bottom:12px;font-style:italic}}
.footer{{margin-top:56px;padding-top:20px;border-top:1px solid var(--border);font-size:.72rem;color:var(--fg3);display:flex;justify-content:space-between;align-items:center}}
.print-btn{{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;background:var(--fg);color:#fff;border:none;border-radius:6px;font-size:.75rem;font-weight:600;letter-spacing:.04em;cursor:pointer;text-transform:uppercase}}
@media print{{
  body{{padding:20px;max-width:none}}
  .print-btn{{display:none}}
  .detail-row{{display:table-row!important}}
  .finding-row{{cursor:default}}
  h2{{page-break-after:avoid}}
  tr{{page-break-inside:avoid}}
  .detail-box{{grid-template-columns:1fr}}
  .header{{border-bottom-color:#000}}
}}
</style>
</head>
<body>

<div class="header">
  <div>
    <div class="brand">MAILOX &nbsp;·&nbsp; Khaøtic Security</div>
    <h1>{_esc(report.scan.target_domain)}</h1>
    <div class="meta-row">{rtype_label} &nbsp;·&nbsp; Assessed <strong>{scan_date}</strong> &nbsp;·&nbsp; Generated {generated}</div>
    <div class="meta-row" style="margin-top:2px;font-size:.72rem">Scan <code style="font-size:.7rem">{_esc(str(report.scan.id)[:8])}</code> &nbsp;·&nbsp; <strong style="color:{posture_color}">{posture.upper()}</strong> posture</div>
  </div>
  <div class="score-block">
    <div class="score-num">{score_str}</div>
    <div class="score-sub">Risk score <span class="posture">/ 100</span></div>
    <button class="print-btn" onclick="window.print()" style="margin-top:12px">⎙ Save as PDF</button>
  </div>
</div>

<section>
  <h2>Risk Breakdown</h2>
  <div class="pills">{sev_pills if sev_pills else '<span style="color:var(--fg3);font-size:.85rem">No findings.</span>'}</div>
  <p style="font-size:.78rem;color:var(--fg3);margin-top:10px">{total} total finding{'s' if total != 1 else ''} &nbsp;·&nbsp; {len(report.findings)} included in this report</p>
</section>

{chains_section}

<section>
  <h2>Findings <span class="count">{len(report.findings)}</span></h2>
  {expand_hint}
  <table>
    <thead>
      <tr>
        <th style="width:90px">Severity</th>
        <th style="width:160px">Check ID</th>
        <th>Title / Asset</th>
        <th style="width:120px">Status</th>
        <th style="width:60px" class="right">CVSS</th>
      </tr>
    </thead>
    <tbody>
{rows if rows else "<tr><td colspan='5' style='text-align:center;color:var(--fg3);padding:32px'>No findings in this report.</td></tr>"}
    </tbody>
  </table>
</section>

<div class="footer">
  <span>Confidential — MAILOX Security Assessment &nbsp;·&nbsp; Khaøtic Security</span>
  <button class="print-btn" onclick="window.print()">⎙ Save as PDF</button>
</div>

<script>
if(location.hash==='#print'){{setTimeout(()=>window.print(),400)}}
</script>
</body>
</html>"""

    # ── CSV ───────────────────────────────────────────────────────────────────

    def _render_csv(self, report: ScanReport) -> str:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "id", "engine", "check_id", "title", "risk_level",
            "affected_asset", "status", "confidence", "cvss_score",
            "created_at",
        ])
        for f in report.findings:
            writer.writerow([
                f.id, _csv_safe(f.engine), _csv_safe(f.check_id), _csv_safe(f.title),
                f.risk_level,
                _csv_safe(f.affected_asset or ""),
                f.status,
                f"{f.confidence:.4f}",
                f.cvss_score if f.cvss_score is not None else "",
                f.created_at.isoformat(),
            ])
        return buf.getvalue()


_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value):
    """Neutralise spreadsheet formula injection (CSV/DDE): prefix text cells
    starting with = + - @ TAB CR with an apostrophe. Non-strings untouched."""
    if isinstance(value, str) and value.startswith(_CSV_FORMULA_PREFIXES):
        return "'" + value
    return value


def _ref_html(ref) -> str:
    """Reference link. Only http(s) URLs become links: HTML-escaping does not
    neutralise javascript:/data: schemes inside href."""
    text = _esc(ref)
    if str(ref).strip().lower().startswith(("https://", "http://")):
        return f"<a href='{text}' target='_blank' rel='noopener noreferrer'>{text}</a><br>"
    return f"{text}<br>"


def _esc(s: str) -> str:
    """HTML-escape a string."""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )
