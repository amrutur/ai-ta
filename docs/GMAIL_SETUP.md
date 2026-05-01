# Gmail SMTP Email Setup Guide

This guide explains how to configure Gmail SMTP for sending grade notification emails from the AI Teaching Assistant.

## Overview

The application uses Gmail's SMTP server (`smtp.gmail.com:587`) to send email notifications when instructors notify students of their grades. This requires a Gmail account and an app-specific password.

## Prerequisites

- A Gmail account (personal or Google Workspace)
- 2-Step Verification enabled on the Gmail account

## Step 1: Enable 2-Step Verification

If you haven't already:

1. Go to [Google Account Security](https://myaccount.google.com/security)
2. Under "How you sign in to Google", click **2-Step Verification**
3. Follow the prompts to enable it

## Step 2: Create a Gmail App Password

1. Go to [Google App Passwords](https://myaccount.google.com/apppasswords)
   - If you don't see this option, ensure 2-Step Verification is enabled
2. Enter a name for the app (e.g., "AI Teaching Assistant")
3. Click **Create**
4. **Copy the 16-character app password** (you won't see it again)

## Step 3: Store the App Password in Secret Manager

Store the app password in Google Cloud Secret Manager with the name `EMAIL_KEY`:

```bash
echo -n "your-16-char-app-password" | gcloud secrets create EMAIL_KEY \
  --project=your-project-id \
  --data-file=-
```

If the secret already exists and you need to update it:

```bash
echo -n "your-new-app-password" | gcloud secrets versions add EMAIL_KEY \
  --project=your-project-id \
  --data-file=-
```

## Step 4: Set the FROM_EMAIL Environment Variable

Set `FROM_EMAIL` to the Gmail address that will send notification emails.

### For Local Development:
```bash
export FROM_EMAIL="your-gmail@gmail.com"
```

### For Production (Cloud Run):
```bash
gcloud run services update your-service-name \
  --update-env-vars FROM_EMAIL="your-gmail@gmail.com" \
  --region your-region
```

Or include it in your `env.yaml` / deployment command (see [DEPLOYMENT.md](DEPLOYMENT.md)).

## Step 5: Test Email Sending

1. Restart your application
2. Check logs for confirmation — if `FROM_EMAIL` is not set you will see:
   ```
   WARNING: FROM_EMAIL environment variable not set. Email notifications will not work.
   ```
3. Test by calling the `/notify_student_grades` endpoint as an instructor

## Troubleshooting

### Warning: "FROM_EMAIL environment variable not set"
- **Cause**: `FROM_EMAIL` not set in environment
- **Solution**: Set the `FROM_EMAIL` environment variable (see Step 4)

### Error: "Failed to send email to ..."
- **Cause**: Invalid app password or account issue
- **Solution**:
  1. Verify 2-Step Verification is enabled
  2. Generate a new app password (Step 2)
  3. Update the `EMAIL_KEY` secret in Secret Manager (Step 3)
  4. Restart the application

### Error: "SMTPAuthenticationError"
- **Cause**: Incorrect app password or the Gmail account has security restrictions
- **Solution**:
  1. Make sure you are using an **app password**, not the account password
  2. Re-generate the app password and update Secret Manager

## Verification Checklist

- [ ] 2-Step Verification enabled on Gmail account
- [ ] App password generated
- [ ] App password stored in Secret Manager as `EMAIL_KEY`
- [ ] `FROM_EMAIL` environment variable set to the Gmail address
- [ ] Application deployed/restarted
- [ ] Test email sent successfully via `/notify_student_grades`

## Gmail SMTP Rate Limits

- **Per-day limit**: 500 emails/day (personal Gmail), 2,000 emails/day (Google Workspace)
- **Per-minute**: No official per-minute limit, but the application throttles bulk sends with 10-second delays between emails to avoid triggering Google's spam filters
- For large classes, consider Google Workspace for higher limits

## Security Best Practices

1. **Use a dedicated Gmail account** for sending notifications (not a personal account)
2. **Never commit** the app password to version control — always use Secret Manager
3. **Rotate** the app password periodically
4. **Monitor** the Gmail account's "Sent" folder to verify delivery
