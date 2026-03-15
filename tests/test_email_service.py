"""
Unit tests for email_service.send_email (Gmail SMTP).
"""

from unittest.mock import patch, MagicMock
from email_service import send_email


class TestSendEmail:

    @patch("email_service.smtplib.SMTP")
    def test_successful_send(self, mock_smtp_cls):
        """Email is sent successfully via SMTP."""
        mock_smtp = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        result = send_email("app-password", "sender@gmail.com", "recipient@test.com", "Subject", "Body")

        assert result is True
        mock_smtp.starttls.assert_called_once()
        mock_smtp.login.assert_called_once_with("sender@gmail.com", "app-password")
        mock_smtp.send_message.assert_called_once()

    @patch("email_service.smtplib.SMTP")
    def test_smtp_failure_returns_false(self, mock_smtp_cls):
        """If SMTP raises an exception, send_email returns False."""
        mock_smtp = MagicMock()
        mock_smtp.send_message.side_effect = Exception("Connection refused")
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        result = send_email("app-password", "sender@gmail.com", "recipient@test.com", "Subject", "Body")

        assert result is False

    @patch("email_service.smtplib.SMTP")
    def test_email_message_fields(self, mock_smtp_cls):
        """Verify the EmailMessage has correct From, To, Subject fields."""
        mock_smtp = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        send_email("key", "from@gmail.com", "to@test.com", "Test Subject", "Test Body")

        sent_msg = mock_smtp.send_message.call_args[0][0]
        assert sent_msg["From"] == "from@gmail.com"
        assert sent_msg["To"] == "to@test.com"
        assert sent_msg["Subject"] == "Test Subject"
        assert "Test Body" in sent_msg.get_content()

    @patch("email_service.smtplib.SMTP")
    def test_connects_to_gmail_smtp(self, mock_smtp_cls):
        """Verify connection to smtp.gmail.com on port 587."""
        mock_smtp = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        send_email("key", "from@gmail.com", "to@test.com", "Sub", "Body")

        mock_smtp_cls.assert_called_once_with("smtp.gmail.com", 587)
