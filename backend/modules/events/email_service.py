"""
================================================================================
    EMAIL SERVICE - Transactional Emails for Events
================================================================================

AI_MODULE: EmailService
AI_DESCRIPTION: Servizio email transazionali per eventi
AI_BUSINESS: Conferme iscrizione, reminder, notifiche pagamento
AI_TEACHING: SMTP async, template rendering, retry logic

ALTERNATIVE_VALUTATE:
- SendGrid API: Scelto per free tier 100 email/day
- AWS SES: Scartato, setup complesso
- Resend: Scartato, meno documentazione

PERCHÉ_QUESTA_SOLUZIONE:
- SendGrid free tier sufficiente per MVP
- Fallback SMTP per testing locale (MailHog)
- Template HTML responsive
- Retry logic per reliability

================================================================================
"""

import os
import logging
import asyncio
from enum import Enum
from typing import Optional, Dict, Any, List
from datetime import datetime
from pathlib import Path
import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from jinja2 import Environment, FileSystemLoader, select_autoescape

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

logger = logging.getLogger(__name__)


class EmailType(str, Enum):
    """Email types for transactional emails."""
    SUBSCRIPTION_CONFIRMED = "subscription_confirmed"
    SUBSCRIPTION_PENDING = "subscription_pending"
    PAYMENT_RECEIVED = "payment_received"
    PAYMENT_FAILED = "payment_failed"
    EVENT_REMINDER_7DAYS = "event_reminder_7days"
    EVENT_REMINDER_3DAYS = "event_reminder_3days"
    EVENT_REMINDER_1DAY = "event_reminder_1day"
    REFUND_APPROVED = "refund_approved"
    REFUND_REJECTED = "refund_rejected"
    WAITLIST_SPOT_AVAILABLE = "waitlist_spot_available"
    EVENT_CANCELLED = "event_cancelled"


class EmailConfig:
    """Email configuration from environment."""

    def __init__(self):
        # SendGrid (primary)
        self.sendgrid_api_key = os.getenv("SENDGRID_API_KEY", "")

        # SMTP Fallback (MailHog for local testing)
        self.smtp_host = os.getenv("SMTP_HOST", "localhost")
        self.smtp_port = int(os.getenv("SMTP_PORT", "1025"))
        self.smtp_username = os.getenv("SMTP_USERNAME", "")
        self.smtp_password = os.getenv("SMTP_PASSWORD", "")
        self.smtp_use_tls = os.getenv("SMTP_USE_TLS", "false").lower() == "true"

        # Sender
        self.from_email = os.getenv("EMAIL_FROM", "noreply@events.libra.it")
        self.from_name = os.getenv("EMAIL_FROM_NAME", "Eventi LIBRA")

        # Retry
        self.max_retries = int(os.getenv("EMAIL_MAX_RETRIES", "3"))
        self.retry_delay = float(os.getenv("EMAIL_RETRY_DELAY", "1.0"))

    @property
    def use_sendgrid(self) -> bool:
        """Use SendGrid if API key is configured."""
        return bool(self.sendgrid_api_key)


class EmailService:
    """
    Service for sending transactional emails.

    Supports:
    - SendGrid API (primary, for production)
    - SMTP (fallback, for local testing with MailHog)

    Usage:
        email_service = EmailService()
        await email_service.send_subscription_confirmation(
            to_email="user@example.com",
            user_name="Mario Rossi",
            event_title="Stage Wing Chun",
            event_date="15-17 Marzo 2024",
            ticket_url="https://events.libra.it/tickets/abc123"
        )
    """

    def __init__(self, config: Optional[EmailConfig] = None):
        self.config = config or EmailConfig()
        self._templates = self._load_templates()

    def _load_templates(self) -> Environment:
        """Load Jinja2 email templates."""
        template_dir = Path(__file__).parent / "templates"

        # Create template directory if it doesn't exist
        template_dir.mkdir(exist_ok=True)

        return Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(['html', 'xml']),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def _render_template(self, template_name: str, context: Dict[str, Any]) -> str:
        """Render email template with context."""
        try:
            template = self._templates.get_template(f"{template_name}.html")
            return template.render(**context)
        except Exception as e:
            logger.warning(f"Template {template_name} not found, using fallback: {e}")
            return self._render_fallback_template(template_name, context)

    def _render_fallback_template(self, template_name: str, context: Dict[str, Any]) -> str:
        """Fallback plain text template when HTML template is missing."""
        subject = context.get("subject", "Notifica Eventi")
        return f"""
        <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h1 style="color: #2563eb;">{subject}</h1>
            <hr style="border: 1px solid #e5e7eb;">
            <p>Ciao {context.get('user_name', 'Utente')},</p>
            <p>{context.get('message', 'Hai ricevuto una notifica.')}</p>
            <hr style="border: 1px solid #e5e7eb;">
            <p style="color: #6b7280; font-size: 12px;">
                Questa email è stata inviata automaticamente da Eventi LIBRA.
            </p>
        </body>
        </html>
        """

    async def _send_via_sendgrid(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: Optional[str] = None
    ) -> bool:
        """Send email via SendGrid API."""
        if not HTTPX_AVAILABLE:
            logger.error("httpx not installed, cannot use SendGrid")
            return False

        url = "https://api.sendgrid.com/v3/mail/send"
        headers = {
            "Authorization": f"Bearer {self.config.sendgrid_api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "personalizations": [{"to": [{"email": to_email}]}],
            "from": {
                "email": self.config.from_email,
                "name": self.config.from_name
            },
            "subject": subject,
            "content": [
                {"type": "text/html", "value": html_content}
            ]
        }

        if text_content:
            payload["content"].insert(0, {"type": "text/plain", "value": text_content})

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(url, json=payload, headers=headers, timeout=30)

                if response.status_code in [200, 201, 202]:
                    logger.info(f"Email sent via SendGrid to {to_email}")
                    return True
                else:
                    logger.error(f"SendGrid error: {response.status_code} - {response.text}")
                    return False
        except Exception as e:
            logger.error(f"SendGrid exception: {e}")
            return False

    async def _send_via_smtp(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: Optional[str] = None
    ) -> bool:
        """Send email via SMTP (MailHog for local testing)."""
        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = f"{self.config.from_name} <{self.config.from_email}>"
        message["To"] = to_email

        # Add plain text version
        if text_content:
            message.attach(MIMEText(text_content, "plain"))

        # Add HTML version
        message.attach(MIMEText(html_content, "html"))

        try:
            if self.config.smtp_use_tls:
                await aiosmtplib.send(
                    message,
                    hostname=self.config.smtp_host,
                    port=self.config.smtp_port,
                    username=self.config.smtp_username or None,
                    password=self.config.smtp_password or None,
                    start_tls=True,
                )
            else:
                await aiosmtplib.send(
                    message,
                    hostname=self.config.smtp_host,
                    port=self.config.smtp_port,
                )

            logger.info(f"Email sent via SMTP to {to_email}")
            return True
        except Exception as e:
            logger.error(f"SMTP error: {e}")
            return False

    async def send_email(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: Optional[str] = None
    ) -> bool:
        """
        Send email with retry logic.

        Args:
            to_email: Recipient email
            subject: Email subject
            html_content: HTML body
            text_content: Optional plain text body

        Returns:
            True if sent successfully
        """
        for attempt in range(self.config.max_retries):
            try:
                # Try SendGrid first if configured
                if self.config.use_sendgrid:
                    success = await self._send_via_sendgrid(
                        to_email, subject, html_content, text_content
                    )
                    if success:
                        return True

                # Fallback to SMTP
                success = await self._send_via_smtp(
                    to_email, subject, html_content, text_content
                )
                if success:
                    return True

            except Exception as e:
                logger.warning(f"Email attempt {attempt + 1} failed: {e}")

            if attempt < self.config.max_retries - 1:
                await asyncio.sleep(self.config.retry_delay * (attempt + 1))

        logger.error(f"Failed to send email to {to_email} after {self.config.max_retries} attempts")
        return False

    # ========================================================================
    # HIGH-LEVEL EMAIL METHODS
    # ========================================================================

    async def send_subscription_confirmation(
        self,
        to_email: str,
        user_name: str,
        event_title: str,
        event_date: str,
        event_location: str,
        option_name: str,
        amount_paid: str,
        ticket_url: Optional[str] = None
    ) -> bool:
        """Send subscription confirmation email."""
        context = {
            "subject": f"Iscrizione Confermata - {event_title}",
            "user_name": user_name,
            "event_title": event_title,
            "event_date": event_date,
            "event_location": event_location,
            "option_name": option_name,
            "amount_paid": amount_paid,
            "ticket_url": ticket_url,
            "year": datetime.now().year,
        }

        html_content = self._render_template("subscription_confirmed", context)

        return await self.send_email(
            to_email=to_email,
            subject=context["subject"],
            html_content=html_content
        )

    async def send_payment_confirmation(
        self,
        to_email: str,
        user_name: str,
        event_title: str,
        amount_paid: str,
        payment_date: str,
        receipt_url: Optional[str] = None
    ) -> bool:
        """Send payment receipt email."""
        context = {
            "subject": f"Pagamento Ricevuto - {event_title}",
            "user_name": user_name,
            "event_title": event_title,
            "amount_paid": amount_paid,
            "payment_date": payment_date,
            "receipt_url": receipt_url,
            "year": datetime.now().year,
        }

        html_content = self._render_template("payment_received", context)

        return await self.send_email(
            to_email=to_email,
            subject=context["subject"],
            html_content=html_content
        )

    async def send_event_reminder(
        self,
        to_email: str,
        user_name: str,
        event_title: str,
        event_date: str,
        event_location: str,
        event_address: Optional[str],
        days_until: int
    ) -> bool:
        """Send event reminder (7, 3, or 1 day before)."""
        if days_until == 1:
            subject = f"Domani! {event_title}"
            urgency = "domani"
        elif days_until <= 3:
            subject = f"Tra {days_until} giorni - {event_title}"
            urgency = f"tra {days_until} giorni"
        else:
            subject = f"Promemoria: {event_title} tra {days_until} giorni"
            urgency = f"tra {days_until} giorni"

        context = {
            "subject": subject,
            "user_name": user_name,
            "event_title": event_title,
            "event_date": event_date,
            "event_location": event_location,
            "event_address": event_address,
            "days_until": days_until,
            "urgency": urgency,
            "year": datetime.now().year,
        }

        html_content = self._render_template("event_reminder", context)

        return await self.send_email(
            to_email=to_email,
            subject=subject,
            html_content=html_content
        )

    async def send_refund_notification(
        self,
        to_email: str,
        user_name: str,
        event_title: str,
        refund_amount: str,
        approved: bool,
        reason: Optional[str] = None
    ) -> bool:
        """Send refund status notification."""
        if approved:
            subject = f"Rimborso Approvato - {event_title}"
            status = "approvato"
        else:
            subject = f"Richiesta Rimborso - {event_title}"
            status = "rifiutato"

        context = {
            "subject": subject,
            "user_name": user_name,
            "event_title": event_title,
            "refund_amount": refund_amount,
            "approved": approved,
            "status": status,
            "reason": reason,
            "year": datetime.now().year,
        }

        html_content = self._render_template("refund_notification", context)

        return await self.send_email(
            to_email=to_email,
            subject=subject,
            html_content=html_content
        )

    async def send_waitlist_notification(
        self,
        to_email: str,
        user_name: str,
        event_title: str,
        event_date: str,
        checkout_url: str,
        expires_in_hours: int = 24
    ) -> bool:
        """Send waitlist spot available notification."""
        subject = f"Posto Disponibile! {event_title}"

        context = {
            "subject": subject,
            "user_name": user_name,
            "event_title": event_title,
            "event_date": event_date,
            "checkout_url": checkout_url,
            "expires_in_hours": expires_in_hours,
            "year": datetime.now().year,
        }

        html_content = self._render_template("waitlist_spot_available", context)

        return await self.send_email(
            to_email=to_email,
            subject=subject,
            html_content=html_content
        )

    async def send_event_cancelled(
        self,
        to_email: str,
        user_name: str,
        event_title: str,
        event_date: str,
        cancellation_reason: Optional[str],
        refund_info: str
    ) -> bool:
        """Send event cancellation notification."""
        subject = f"Evento Annullato - {event_title}"

        context = {
            "subject": subject,
            "user_name": user_name,
            "event_title": event_title,
            "event_date": event_date,
            "cancellation_reason": cancellation_reason,
            "refund_info": refund_info,
            "year": datetime.now().year,
        }

        html_content = self._render_template("event_cancelled", context)

        return await self.send_email(
            to_email=to_email,
            subject=subject,
            html_content=html_content
        )

    # ========================================================================
    # UTILITY METHODS
    # ========================================================================

    def map_alert_type_to_email_type(self, alert_type: str) -> Optional[EmailType]:
        """Map alert type to email type."""
        mapping = {
            "event_reminder": EmailType.EVENT_REMINDER_7DAYS,
            "waitlist_spot": EmailType.WAITLIST_SPOT_AVAILABLE,
            "refund_request": EmailType.REFUND_APPROVED,
            "event_cancelled": EmailType.EVENT_CANCELLED,
        }
        return mapping.get(alert_type)


# Singleton instance
_email_service: Optional[EmailService] = None


def get_email_service() -> EmailService:
    """Get or create email service singleton."""
    global _email_service
    if _email_service is None:
        _email_service = EmailService()
    return _email_service
