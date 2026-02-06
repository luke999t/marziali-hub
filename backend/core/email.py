"""
🎓 AI_MODULE: Email Service
🎓 AI_DESCRIPTION: SMTP email sending with template support
🎓 AI_BUSINESS: User communication, verification, password reset
🎓 AI_TEACHING: Email templates + async sending

📄 ALTERNATIVE_VALUTATE:
- SendGrid: $14.95/month for 40k emails
- Mailgun: $35/month for 50k emails
- Brevo (Sendinblue): FREE tier 300 emails/day
- Gmail SMTP: FREE, 500 emails/day limit

💡 PERCHÉ_QUESTA_SOLUZIONE:
- Brevo free tier: Perfetto per MVP
- Gmail SMTP: Fallback gratuito
- Template HTML integrati
- Async support per performance

🔧 DEPENDENCIES:
- aiosmtplib: Async SMTP client
- email: Python standard library

⚠️ LIMITAZIONI_NOTE:
- Free tier: 300 emails/day (Brevo)
- Gmail: 500 emails/day
- Rate limiting necessario

🎯 METRICHE_SUCCESSO:
- Email delivery: >95%
- Send time: <2s
- Template rendering: <100ms
"""

import os
import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, List
from jinja2 import Template


class EmailService:
    """Async email service with SMTP support."""

    def __init__(self):
        self.smtp_host = os.getenv("SMTP_HOST", "smtp-relay.brevo.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER", "")
        self.smtp_password = os.getenv("SMTP_PASSWORD", "")
        self.from_email = os.getenv("FROM_EMAIL", "noreply@artimarziali.com")
        self.from_name = os.getenv("FROM_NAME", "Media Center Arti Marziali")

    async def send_email(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: Optional[str] = None
    ) -> bool:
        """
        Send email via SMTP.

        Args:
            to_email: Recipient email
            subject: Email subject
            html_content: HTML body
            text_content: Plain text fallback (optional)

        Returns:
            True if sent successfully, False otherwise
        """
        try:
            # Create message
            message = MIMEMultipart("alternative")
            message["From"] = f"{self.from_name} <{self.from_email}>"
            message["To"] = to_email
            message["Subject"] = subject

            # Add plain text part if provided
            if text_content:
                text_part = MIMEText(text_content, "plain")
                message.attach(text_part)

            # Add HTML part
            html_part = MIMEText(html_content, "html")
            message.attach(html_part)

            # Send email
            await aiosmtplib.send(
                message,
                hostname=self.smtp_host,
                port=self.smtp_port,
                username=self.smtp_user,
                password=self.smtp_password,
                start_tls=True
            )

            return True

        except Exception as e:
            print(f"❌ Email send failed: {e}")
            return False

    async def send_verification_email(
        self,
        to_email: str,
        username: str,
        verification_token: str
    ) -> bool:
        """
        Send email verification link.

        Args:
            to_email: User email
            username: User username
            verification_token: Verification token

        Returns:
            True if sent successfully
        """
        base_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
        verification_link = f"{base_url}/verify-email?token={verification_token}"

        html_content = self._render_verification_template(username, verification_link)

        return await self.send_email(
            to_email=to_email,
            subject="Verify Your Email - Media Center Arti Marziali",
            html_content=html_content
        )

    async def send_password_reset_email(
        self,
        to_email: str,
        username: str,
        reset_token: str
    ) -> bool:
        """
        Send password reset link.

        Args:
            to_email: User email
            username: User username
            reset_token: Password reset token

        Returns:
            True if sent successfully
        """
        base_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
        reset_link = f"{base_url}/reset-password?token={reset_token}"

        html_content = self._render_password_reset_template(username, reset_link)

        return await self.send_email(
            to_email=to_email,
            subject="Reset Your Password - Media Center Arti Marziali",
            html_content=html_content
        )

    async def send_welcome_email(
        self,
        to_email: str,
        username: str,
        full_name: str
    ) -> bool:
        """
        Send welcome email after successful registration.

        Args:
            to_email: User email
            username: User username
            full_name: User full name

        Returns:
            True if sent successfully
        """
        html_content = self._render_welcome_template(username, full_name)

        return await self.send_email(
            to_email=to_email,
            subject="Welcome to Media Center Arti Marziali! 🥋",
            html_content=html_content
        )

    def _render_verification_template(self, username: str, verification_link: str) -> str:
        """Render email verification template."""
        template = Template("""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: #fff; padding: 30px; border: 1px solid #e0e0e0; }
        .button { display: inline-block; padding: 15px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 20px 0; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🥋 Verify Your Email</h1>
        </div>
        <div class="content">
            <h2>Ciao {{ username }}!</h2>
            <p>Thank you for joining <strong>Media Center Arti Marziali</strong>!</p>
            <p>Please verify your email address by clicking the button below:</p>
            <div style="text-align: center;">
                <a href="{{ verification_link }}" class="button">Verify Email Address</a>
            </div>
            <p>Or copy and paste this link in your browser:</p>
            <p style="word-break: break-all; color: #667eea;">{{ verification_link }}</p>
            <p><strong>This link will expire in 24 hours.</strong></p>
            <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 30px 0;">
            <p style="color: #666; font-size: 14px;">If you didn't create an account, you can safely ignore this email.</p>
        </div>
        <div class="footer">
            <p>&copy; 2025 Media Center Arti Marziali. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
        """)

        return template.render(username=username, verification_link=verification_link)

    def _render_password_reset_template(self, username: str, reset_link: str) -> str:
        """Render password reset template."""
        template = Template("""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: #fff; padding: 30px; border: 1px solid #e0e0e0; }
        .button { display: inline-block; padding: 15px 30px; background: #f5576c; color: white; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 20px 0; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
        .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Reset Your Password</h1>
        </div>
        <div class="content">
            <h2>Ciao {{ username }},</h2>
            <p>We received a request to reset your password for your <strong>Media Center Arti Marziali</strong> account.</p>
            <p>Click the button below to reset your password:</p>
            <div style="text-align: center;">
                <a href="{{ reset_link }}" class="button">Reset Password</a>
            </div>
            <p>Or copy and paste this link in your browser:</p>
            <p style="word-break: break-all; color: #f5576c;">{{ reset_link }}</p>
            <p><strong>This link will expire in 1 hour.</strong></p>
            <div class="warning">
                <p><strong>⚠️ Security Notice:</strong></p>
                <p>If you didn't request a password reset, please ignore this email. Your password will remain unchanged.</p>
            </div>
        </div>
        <div class="footer">
            <p>&copy; 2025 Media Center Arti Marziali. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
        """)

        return template.render(username=username, reset_link=reset_link)

    def _render_welcome_template(self, username: str, full_name: str) -> str:
        """Render welcome email template."""
        template = Template("""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: #fff; padding: 30px; border: 1px solid #e0e0e0; }
        .feature { padding: 15px; margin: 10px 0; background: #f8f9fa; border-radius: 5px; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🥋 Welcome to Media Center!</h1>
        </div>
        <div class="content">
            <h2>Ciao {{ full_name }}!</h2>
            <p>Welcome to <strong>Media Center Arti Marziali</strong>! We're excited to have you join our community of martial arts enthusiasts.</p>

            <h3>What's Next?</h3>
            <div class="feature">
                <strong>📚 Explore Techniques</strong><br>
                Browse our extensive library of martial arts techniques from masters around the world.
            </div>
            <div class="feature">
                <strong>🎓 Learn & Practice</strong><br>
                Follow along with detailed video tutorials and improve your skills.
            </div>
            <div class="feature">
                <strong>💎 Earn Stelline</strong><br>
                Support your favorite maestros with our virtual currency system.
            </div>
            <div class="feature">
                <strong>🌟 Upgrade Anytime</strong><br>
                Unlock premium content with our flexible subscription tiers.
            </div>

            <p style="margin-top: 30px;">Your journey in martial arts excellence starts now!</p>
            <p><strong>Username:</strong> {{ username }}</p>

            <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 30px 0;">
            <p style="color: #666; font-size: 14px;">Need help? Contact us anytime at support@artimarziali.com</p>
        </div>
        <div class="footer">
            <p>&copy; 2025 Media Center Arti Marziali. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
        """)

        return template.render(username=username, full_name=full_name)

    # === VIDEO MODERATION NOTIFICATIONS ===

    async def send_video_approved_email(
        self,
        to_email: str,
        maestro_name: str,
        video_title: str,
        video_id: str,
        notes: Optional[str] = None
    ) -> bool:
        """
        Send notification when video is approved.

        Args:
            to_email: Maestro email
            maestro_name: Maestro name
            video_title: Video title
            video_id: Video ID
            notes: Optional moderator notes

        Returns:
            True if sent successfully
        """
        base_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
        video_link = f"{base_url}/video/{video_id}"

        html_content = self._render_video_approved_template(
            maestro_name, video_title, video_link, notes
        )

        return await self.send_email(
            to_email=to_email,
            subject=f"Video Approvato: {video_title} - Media Center Arti Marziali",
            html_content=html_content
        )

    async def send_video_rejected_email(
        self,
        to_email: str,
        maestro_name: str,
        video_title: str,
        rejection_reason: str
    ) -> bool:
        """
        Send notification when video is rejected.

        Args:
            to_email: Maestro email
            maestro_name: Maestro name
            video_title: Video title
            rejection_reason: Reason for rejection

        Returns:
            True if sent successfully
        """
        html_content = self._render_video_rejected_template(
            maestro_name, video_title, rejection_reason
        )

        return await self.send_email(
            to_email=to_email,
            subject=f"Video Non Approvato: {video_title} - Media Center Arti Marziali",
            html_content=html_content
        )

    async def send_video_changes_requested_email(
        self,
        to_email: str,
        maestro_name: str,
        video_title: str,
        video_id: str,
        required_changes: List[str],
        notes: Optional[str] = None
    ) -> bool:
        """
        Send notification when changes are requested for a video.

        Args:
            to_email: Maestro email
            maestro_name: Maestro name
            video_title: Video title
            video_id: Video ID
            required_changes: List of required changes
            notes: Optional moderator notes

        Returns:
            True if sent successfully
        """
        base_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
        edit_link = f"{base_url}/studio/edit/{video_id}"

        html_content = self._render_video_changes_template(
            maestro_name, video_title, edit_link, required_changes, notes
        )

        return await self.send_email(
            to_email=to_email,
            subject=f"Modifiche Richieste: {video_title} - Media Center Arti Marziali",
            html_content=html_content
        )

    def _render_video_approved_template(
        self,
        maestro_name: str,
        video_title: str,
        video_link: str,
        notes: Optional[str]
    ) -> str:
        """Render video approved email template."""
        template = Template("""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: #fff; padding: 30px; border: 1px solid #e0e0e0; }
        .button { display: inline-block; padding: 15px 30px; background: #11998e; color: white; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 20px 0; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
        .success-box { background: #d4edda; border-left: 4px solid #28a745; padding: 15px; margin: 20px 0; border-radius: 0 5px 5px 0; }
        .notes { background: #f8f9fa; padding: 15px; border-radius: 5px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Video Approvato!</h1>
        </div>
        <div class="content">
            <h2>Complimenti {{ maestro_name }}!</h2>
            <div class="success-box">
                <strong>Il tuo video e stato approvato e pubblicato!</strong>
            </div>
            <p>Il video "<strong>{{ video_title }}</strong>" e ora disponibile sulla piattaforma per tutti gli utenti.</p>
            <div style="text-align: center;">
                <a href="{{ video_link }}" class="button">Visualizza Video</a>
            </div>
            {% if notes %}
            <div class="notes">
                <strong>Note del moderatore:</strong>
                <p>{{ notes }}</p>
            </div>
            {% endif %}
            <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 30px 0;">
            <p style="color: #666; font-size: 14px;">Continua a creare contenuti di qualita per la nostra community!</p>
        </div>
        <div class="footer">
            <p>&copy; 2025 Media Center Arti Marziali. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
        """)
        return template.render(
            maestro_name=maestro_name,
            video_title=video_title,
            video_link=video_link,
            notes=notes
        )

    def _render_video_rejected_template(
        self,
        maestro_name: str,
        video_title: str,
        rejection_reason: str
    ) -> str:
        """Render video rejected email template."""
        template = Template("""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #f5576c 0%, #f093fb 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: #fff; padding: 30px; border: 1px solid #e0e0e0; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
        .rejection-box { background: #f8d7da; border-left: 4px solid #dc3545; padding: 15px; margin: 20px 0; border-radius: 0 5px 5px 0; }
        .reason { background: #fff3cd; padding: 15px; border-radius: 5px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Video Non Approvato</h1>
        </div>
        <div class="content">
            <h2>Ciao {{ maestro_name }},</h2>
            <div class="rejection-box">
                <strong>Il tuo video non e stato approvato</strong>
            </div>
            <p>Purtroppo il video "<strong>{{ video_title }}</strong>" non ha superato la moderazione.</p>
            <div class="reason">
                <strong>Motivo del rifiuto:</strong>
                <p>{{ rejection_reason }}</p>
            </div>
            <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 30px 0;">
            <p><strong>Cosa puoi fare:</strong></p>
            <ul>
                <li>Rivedi il contenuto del video</li>
                <li>Assicurati che rispetti le linee guida della community</li>
                <li>Carica una nuova versione corretta</li>
            </ul>
            <p style="color: #666; font-size: 14px;">Per qualsiasi domanda, contattaci a support@artimarziali.com</p>
        </div>
        <div class="footer">
            <p>&copy; 2025 Media Center Arti Marziali. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
        """)
        return template.render(
            maestro_name=maestro_name,
            video_title=video_title,
            rejection_reason=rejection_reason
        )

    def _render_video_changes_template(
        self,
        maestro_name: str,
        video_title: str,
        edit_link: str,
        required_changes: List[str],
        notes: Optional[str]
    ) -> str:
        """Render video changes requested email template."""
        template = Template("""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: #fff; padding: 30px; border: 1px solid #e0e0e0; }
        .button { display: inline-block; padding: 15px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 20px 0; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
        .changes-box { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 0 5px 5px 0; }
        .change-item { padding: 10px; margin: 5px 0; background: #f8f9fa; border-radius: 5px; }
        .notes { background: #e7f3ff; padding: 15px; border-radius: 5px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Modifiche Richieste</h1>
        </div>
        <div class="content">
            <h2>Ciao {{ maestro_name }},</h2>
            <div class="changes-box">
                <strong>Il tuo video richiede alcune modifiche</strong>
            </div>
            <p>Il video "<strong>{{ video_title }}</strong>" e quasi pronto! Abbiamo bisogno di alcune modifiche prima della pubblicazione.</p>

            <h3>Modifiche richieste:</h3>
            {% for change in required_changes %}
            <div class="change-item">
                {{ loop.index }}. {{ change }}
            </div>
            {% endfor %}

            {% if notes %}
            <div class="notes">
                <strong>Note aggiuntive:</strong>
                <p>{{ notes }}</p>
            </div>
            {% endif %}

            <div style="text-align: center;">
                <a href="{{ edit_link }}" class="button">Modifica Video</a>
            </div>

            <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 30px 0;">
            <p style="color: #666; font-size: 14px;">Una volta apportate le modifiche, il video sara nuovamente sottoposto a revisione.</p>
        </div>
        <div class="footer">
            <p>&copy; 2025 Media Center Arti Marziali. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
        """)
        return template.render(
            maestro_name=maestro_name,
            video_title=video_title,
            edit_link=edit_link,
            required_changes=required_changes,
            notes=notes
        )


# Singleton instance
email_service = EmailService()
