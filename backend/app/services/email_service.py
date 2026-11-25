"""Transactional email service.

If SMTP_HOST is not configured, falls back to logging the email body to stdout
so development workflows don't require a real mail server.
"""
from __future__ import annotations

import uuid
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from html import escape
from typing import Optional

import aiosmtplib

from app.core.config import settings
from app.core.logging import get_logger
from app.db.session import AsyncSessionLocal

# structlog: the calls below pass key=value context, which stdlib logging rejects
logger = get_logger("mailox.email")


async def _log_email(
    recipient: str,
    subject: str,
    template: str,
    status: str,
    error_message: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> None:
    """Log email to database for history tracking."""
    try:
        from app.db.models.email_log import EmailLog
        async with AsyncSessionLocal() as db:
            log = EmailLog(
                id=uuid.uuid4(),
                recipient=recipient,
                subject=subject,
                template=template,
                status=status,
                error_message=error_message,
                metadata_=metadata,
            )
            db.add(log)
            await db.commit()
    except Exception as exc:
        logger.error("email_log.save_failed", error=str(exc))


async def send_email(
    to: str,
    subject: str,
    html: str,
    text: Optional[str] = None,
    template: str = "generic",
    metadata: Optional[dict] = None,
) -> None:
    if not settings.SMTP_HOST:
        # The body carries password-reset and invitation links: only log it in
        # DEBUG, never in production logs.
        log_fields = {"to": to, "subject": subject, "template": template}
        if settings.DEBUG:
            log_fields["body"] = text or html
        logger.warning("email.not_sent.no_smtp_config", **log_fields)
        await _log_email(to, subject, template, "failed", "SMTP not configured", metadata)
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_FROM
    msg["To"] = to

    if text:
        msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))

    password = (
        settings.SMTP_PASSWORD.get_secret_value()
        if settings.SMTP_PASSWORD
        else None
    )

    try:
        await aiosmtplib.send(
            msg,
            hostname=settings.SMTP_HOST,
            port=settings.SMTP_PORT,
            username=settings.SMTP_USERNAME,
            password=password,
            use_tls=settings.SMTP_USE_TLS,
        )
        logger.info("email.sent", to=to, subject=subject)
        await _log_email(to, subject, template, "sent", None, metadata)
    except Exception as exc:
        logger.error("email.send_failed", to=to, subject=subject, error=str(exc))
        await _log_email(to, subject, template, "failed", str(exc), metadata)
        raise


async def send_password_reset_email(to: str, token: str) -> None:
    reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token}"

    text = (
        f"You requested a password reset for your MAILOX account.\n\n"
        f"Reset link (valid 15 minutes):\n{reset_url}\n\n"
        f"If you did not request this, ignore this email."
    )
    html = f"""
<html><body style="font-family:sans-serif;color:#222;max-width:480px;margin:0 auto;padding:24px">
  <h2 style="color:#111">Reset your password</h2>
  <p>You requested a password reset for your <strong>MAILOX</strong> account.</p>
  <p style="margin:24px 0">
    <a href="{reset_url}"
       style="background:#E53935;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600">
      Reset password
    </a>
  </p>
  <p style="color:#666;font-size:13px">Link expires in 15 minutes. If you did not request this, ignore this email.</p>
  <hr style="border:none;border-top:1px solid #eee;margin:24px 0">
  <p style="color:#999;font-size:12px">MAILOX — Email Security Assessment Platform</p>
</body></html>
"""

    await send_email(
        to=to,
        subject="Reset your MAILOX password",
        html=html,
        text=text,
        template="password_reset",
    )


def _layout(title: str, body_html: str) -> str:
    return f"""
<html><body style="font-family:sans-serif;color:#222;max-width:520px;margin:0 auto;padding:24px">
  <h2 style="color:#111">{title}</h2>
  {body_html}
  <hr style="border:none;border-top:1px solid #eee;margin:24px 0">
  <p style="color:#999;font-size:12px">MAILOX — Email Security Assessment Platform</p>
</body></html>
"""


async def send_access_invite_email(to: str, name: str, token: str, valid_hours: int) -> None:
    """Sent when a platform admin approves an access request."""
    url = f"{settings.FRONTEND_URL}/register?invite={token}"
    days = max(1, round(valid_hours / 24))
    text = (
        f"Hello {name},\n\n"
        f"Your request for MAILOX access has been approved.\n"
        f"Create your account with this link (single use, valid {days} days):\n{url}\n\n"
        f"The account must be created with this email address: {to}"
    )
    html = _layout("Your MAILOX access is ready", f"""
  <p>Hello {escape(name)},</p>
  <p>Your request for <strong>MAILOX</strong> access has been approved.</p>
  <p style="margin:24px 0">
    <a href="{escape(url)}"
       style="background:#E53935;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600">
      Create my account
    </a>
  </p>
  <p style="color:#666;font-size:13px">This link works once and expires in {days} days.
  The account must be created with <strong>{escape(to)}</strong>.</p>
""")
    await send_email(to=to, subject="Your MAILOX access is ready", html=html, text=text, template="access_invite")


async def send_access_request_notification(
    to: str, request_id: str, name: str, email: str, company: str,
    role: Optional[str], message: Optional[str],
) -> None:
    """Tells the platform admin that someone asked for access."""
    url = f"{settings.FRONTEND_URL}/admin/access"
    lines = [f"Name: {name}", f"Email: {email}", f"Company: {company}"]
    if role:
        lines.append(f"Role: {role}")
    if message:
        lines.append(f"Message: {message}")
    text = "New MAILOX access request\n\n" + "\n".join(lines) + f"\n\nReview: {url}\nID: {request_id}"
    rows = "".join(f"<p style='margin:4px 0'>{escape(line)}</p>" for line in lines)
    html = _layout("New access request", f"""
  {rows}
  <p style="margin:24px 0">
    <a href="{escape(url)}"
       style="background:#111;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:600">
      Review the request
    </a>
  </p>
""")
    await send_email(to=to, subject=f"MAILOX access request: {company}", html=html, text=text, template="access_request_notification")
