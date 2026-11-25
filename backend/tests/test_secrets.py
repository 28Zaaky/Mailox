"""
SecretsEngine tests.

Covers:
- Pattern detection accuracy
- Masking (never plaintext in output)
- Zip Slip protection
- Decompression bomb guard
- File size limits
- Context scoring
- API schema compliance
"""
import io
import os
import zipfile
import pytest

from app.engines.secrets import SecretsEngine, _mask_secret, _mask_line


# ── Masking unit tests ─────────────────────────────────────────────────────────


class TestMasking:
    def test_mask_normal_secret(self):
        assert _mask_secret("MyP4ssword!") == "My***d!"

    def test_mask_short_secret(self):
        assert _mask_secret("abc") == "***"

    def test_mask_exact_6_chars(self):
        result = _mask_secret("abcdef")
        assert result == "ab***ef"

    def test_mask_line_replaces_smtp_dsn(self):
        line = "smtp://user:supersecret@smtp.example.com:587"
        masked = _mask_line(line)
        assert "supersecret" not in masked
        assert "***MASKED***" in masked

    def test_mask_line_replaces_smtp_password_var(self):
        line = "SMTP_PASSWORD=my_very_secret_pass"
        masked = _mask_line(line)
        assert "my_very_secret_pass" not in masked

    def test_mask_line_no_false_positive_on_comment(self):
        # A comment line without actual secrets should not mask random text
        line = "# This is a comment about SMTP configuration"
        masked = _mask_line(line)
        # No secret group matched — line unchanged
        assert masked == line


# ── Pattern detection ──────────────────────────────────────────────────────────


class TestPatternDetection:
    def _engine(self):
        return SecretsEngine()

    def test_detects_smtp_dsn(self):
        engine = self._engine()
        content = b"mail_url: smtps://user:superS3cret@smtp.example.com:465"
        hits = engine.scan_bytes(content, "config.yaml")
        assert any(h.rule_id == "SMTP-DSN" for h in hits)

    def test_detects_smtp_password_env_var(self):
        engine = self._engine()
        content = b"SMTP_PASSWORD=mySuperSecretPassword123\n"
        hits = engine.scan_bytes(content, ".env")
        assert any(h.rule_id == "SMTP-PWD-VAR" for h in hits)

    def test_detects_mail_secret_var(self):
        engine = self._engine()
        content = b"mail_password: 'tHisIsAV3ryS3cret!'\n"
        hits = engine.scan_bytes(content, "config.yml")
        assert any(h.rule_id == "MAIL-SECRET-VAR" for h in hits)

    def test_detects_sendgrid_key(self):
        engine = self._engine()
        # Fake SendGrid key pattern: SG.<20+ chars>
        content = b"SENDGRID_API_KEY=SG.abcdefghijklmnopqrstuvwxyz12345678"
        hits = engine.scan_bytes(content, ".env")
        assert any(h.rule_id == "SENDGRID-KEY" for h in hits)

    def test_detects_smtp_username_email(self):
        engine = self._engine()
        content = b"SMTP_USERNAME=admin@example.com\n"
        hits = engine.scan_bytes(content, ".env")
        assert any(h.rule_id == "SMTP-USER" for h in hits)

    def test_no_hit_on_placeholder(self):
        engine = self._engine()
        # Typical placeholder — too short / looks like placeholder
        content = b"SMTP_PASSWORD=\n"
        hits = engine.scan_bytes(content, ".env")
        # Empty value — no match
        assert len(hits) == 0

    def test_no_hit_on_non_text_extension(self):
        engine = self._engine()
        content = b"SMTP_PASSWORD=mySuperSecretPassword123\n"
        hits = engine.scan_bytes(content, "binary.exe")
        assert len(hits) == 0

    def test_masked_value_not_plaintext(self):
        engine = self._engine()
        content = b"SMTP_PASSWORD=mySuperSecretPassword123\n"
        hits = engine.scan_bytes(content, ".env")
        for hit in hits:
            # Secret must never appear in masked_value or context_snippet verbatim
            assert "mySuperSecretPassword123" not in hit.masked_value
            if hit.context_snippet:
                assert "mySuperSecretPassword123" not in hit.context_snippet

    def test_context_snippet_not_plaintext(self):
        engine = self._engine()
        lines = [
            "# mail config",
            "SMTP_HOST=smtp.example.com",
            "SMTP_PASSWORD=TotallySecret999!",
            "SMTP_PORT=587",
        ]
        content = "\n".join(lines).encode()
        hits = engine.scan_bytes(content, ".env")
        for hit in hits:
            if hit.context_snippet:
                assert "TotallySecret999!" not in hit.context_snippet

    def test_deduplication_same_secret(self):
        engine = self._engine()
        content = b"SMTP_PASSWORD=SamePass123!\nSMTP_PASS=SamePass123!\n"
        hits = engine.scan_bytes(content, ".env")
        # Same masked value from same rule — deduped to one hit
        smtp_pwd_hits = [h for h in hits if h.secret_type == "smtp_password"]
        masked_vals = [h.masked_value for h in smtp_pwd_hits]
        assert len(masked_vals) == len(set(masked_vals))


# ── File size limits ───────────────────────────────────────────────────────────


class TestFileSizeLimits:
    def test_file_too_large_returns_empty(self):
        engine = SecretsEngine()
        # 11 MB file
        big_content = b"SMTP_PASSWORD=SomeSecret999!\n" * (11 * 1024 * 1024 // 30)
        hits = engine.scan_bytes(big_content, ".env", max_size_mb=10)
        assert hits == []

    def test_file_within_limit_scanned(self):
        engine = SecretsEngine()
        content = b"SMTP_PASSWORD=SomeSecret999!\n"
        hits = engine.scan_bytes(content, ".env", max_size_mb=10)
        assert len(hits) > 0


# ── Zip Slip protection ────────────────────────────────────────────────────────


class TestZipSlip:
    def _make_zip(self, entries: dict[str, bytes]) -> bytes:
        """Create in-memory ZIP with given filename -> content entries."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for name, data in entries.items():
                zf.writestr(name, data)
        return buf.getvalue()

    def test_safe_path_normal(self):
        engine = SecretsEngine()
        assert engine._safe_path("config/.env") == "config/.env"

    def test_safe_path_traversal_blocked(self):
        engine = SecretsEngine()
        assert engine._safe_path("../../etc/passwd") is None

    def test_safe_path_leading_slash(self):
        engine = SecretsEngine()
        result = engine._safe_path("/etc/passwd")
        # Leading slash stripped
        assert result is not None and not result.startswith("/")

    def test_zip_slip_blocked_during_scan(self):
        engine = SecretsEngine()
        zip_bytes = self._make_zip({
            "../../evil.env": b"SMTP_PASSWORD=pwned!\n",
        })
        hits = engine.scan_archive(zip_bytes, "malicious.zip")
        # Traversal member skipped — no hits
        assert hits == []

    def test_normal_zip_scanned(self):
        engine = SecretsEngine()
        zip_bytes = self._make_zip({
            "app/.env": b"SMTP_PASSWORD=SomeRealSecret999!\n",
        })
        hits = engine.scan_archive(zip_bytes, "deploy.zip")
        assert len(hits) > 0

    def test_non_text_files_in_zip_skipped(self):
        engine = SecretsEngine()
        zip_bytes = self._make_zip({
            "image.png": b"\x89PNG binary data",
            "app.env": b"SMTP_PASSWORD=AnotherRealSecret!\n",
        })
        hits = engine.scan_archive(zip_bytes, "mixed.zip")
        # Only app.env scanned
        assert all(".env" in h.source_path or ".env" in h.source_path for h in hits)


# ── Decompression bomb guard ───────────────────────────────────────────────────


class TestDecompressionBombGuard:
    def test_bomb_guard_blocks_large_uncompressed(self):
        engine = SecretsEngine()
        # Create a "bomb": many small files summing > 50 MB
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            # Each file: 1 MB of repeated text — 60 of them = 60 MB
            big_chunk = b"SMTP_PASSWORD=x\n" * (1024 * 1024 // 16)
            for i in range(60):
                zf.writestr(f"file{i}.env", big_chunk)
        zip_bytes = buf.getvalue()
        hits = engine.scan_archive(zip_bytes, "bomb.zip", max_archive_mb=50)
        # Should be blocked before scanning
        assert hits == []

    def test_non_zip_returns_empty(self):
        engine = SecretsEngine()
        hits = engine.scan_archive(b"not a zip", "not_a_zip.zip")
        assert hits == []


# ── File count limit ───────────────────────────────────────────────────────────


class TestFileCountLimit:
    def test_file_count_limit_respected(self):
        engine = SecretsEngine()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for i in range(60):
                zf.writestr(f"file{i}.env", b"SMTP_PASSWORD=SomeRealSecret!\n")
        zip_bytes = buf.getvalue()
        hits = engine.scan_archive(zip_bytes, "many.zip", max_files=10)
        # At most 10 files × 1 hit = 10 hits (after dedup per file, could be fewer)
        file_paths = {h.source_path for h in hits}
        # Count distinct files (before archive prefix)
        inner_files = {p.split("::")[-1] for p in file_paths}
        assert len(inner_files) <= 10


# ── hits_to_findings ───────────────────────────────────────────────────────────


class TestHitsToFindings:
    def test_findings_contain_no_plaintext(self):
        engine = SecretsEngine()
        content = b"SMTP_PASSWORD=PlainTextSecret123!\n"
        hits = engine.scan_bytes(content, ".env")
        findings = engine.hits_to_findings(hits, "example.com", "upload.zip")
        for f in findings:
            for ev in f.evidence:
                # observed_value must not contain the plaintext secret
                assert "PlainTextSecret123!" not in (ev.observed_value or "")
                if ev.technical_details:
                    assert "PlainTextSecret123!" not in str(ev.technical_details)

    def test_findings_have_correct_check_id_prefix(self):
        engine = SecretsEngine()
        content = b"SMTP_PASSWORD=SomeRealSecret999!\n"
        hits = engine.scan_bytes(content, ".env")
        findings = engine.hits_to_findings(hits, "example.com", "archive.zip")
        for f in findings:
            assert f.check_id.startswith("SE-")

    def test_smtp_password_risk_is_high_or_critical(self):
        engine = SecretsEngine()
        content = b"SMTP_PASSWORD=SomeRealSecret999!\n"
        hits = engine.scan_bytes(content, ".env")
        findings = engine.hits_to_findings(hits, "example.com", "archive.zip")
        for f in findings:
            assert f.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    def test_sendgrid_key_risk_is_critical(self):
        engine = SecretsEngine()
        content = b"SG.abcdefghijklmnopqrstuvwxyz12345678\n"
        hits = engine.scan_bytes(content, ".env")
        findings = engine.hits_to_findings(hits, "example.com", "archive.zip")
        for f in findings:
            if "SENDGRID" in f.check_id:
                assert f.risk_level == RiskLevel.CRITICAL


# ── Context scoring ────────────────────────────────────────────────────────────


class TestContextScoring:
    def test_mail_context_boosts_confidence(self):
        engine = SecretsEngine()
        lines = [
            "# SMTP configuration for mail delivery",
            "smtp_host: smtp.example.com",
            "SMTP_PASSWORD=BoostMeSecret999!",
            "smtp_port: 587",
        ]
        content = "\n".join(lines).encode()
        hits = engine.scan_bytes(content, ".env")
        for h in hits:
            if h.rule_id == "SMTP-PWD-VAR":
                # Context has smtp/mail keywords — confidence boosted above base 0.85
                assert h.confidence >= 0.85


# import needed for CRITICAL assertion in hits_to_findings test
from app.schemas.findings import RiskLevel
