"""
Email service using SendGrid API.
"""

import logging

from sendgrid.helpers.mail import Mail, Email, To, Content


def send_email(sendgrid_client, from_email, to, subject, body):
    """
    Send an email using SendGrid API.
    Returns True if successful, False otherwise.
    """
    if sendgrid_client is None:
        logging.error("SendGrid client not initialized. Cannot send email.")
        logging.error("Please configure SENDGRID_FROM_EMAIL and ensure sendgrid-api-key is in Secret Manager.")
        return False

    try:
        message = Mail(
            from_email=Email(from_email),
            to_emails=To(to),
            subject=subject,
            plain_text_content=Content("text/plain", body)
        )

        response = sendgrid_client.send(message)
        logging.info(f"Email sent to {to}! Status code: {response.status_code}")
        return True
    except Exception as e:
        logging.error(f"Failed to send email to {to}: {e}")
        return False
