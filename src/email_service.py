"""
Email service using SendGrid API.
"""

import logging

#from sendgrid.helpers.mail import Mail, Email, To, Content
import smtplib
from email.message import EmailMessage

def send_email(mail_api_key, from_email, to, subject, body):
    """
    Send an email using  GMAIL SMTP.
    Returns True if successful, False otherwise.
    """

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = from_email
    msg['To'] = to
    msg.set_content(body)
    try:
    # Connect to Gmail's SMTP server
        with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
            smtp.starttls()  # Secure the connection
            smtp.login(from_email, mail_api_key)
            smtp.send_message(msg)
        logging.info(f"Email sent to {to}!")
        return True
    except Exception as e:
        logging.error(f"Failed to send email to {to}: {e}")
        return False
