# SendGrid Email Setup Guide

This guide explains how to configure SendGrid for sending email notifications from the AI Teaching Assistant.

## Overview

The application uses SendGrid API to send email notifications when instructors notify students of their grades. SendGrid is a cloud-based email service that doesn't require Google Workspace.

## Prerequisites

- SendGrid account (free tier available: 100 emails/day)
- SendGrid API key already stored in Google Cloud Secret Manager as `sendgrid-api-key`

## Step 1: Verify SendGrid API Key in Secret Manager

Check that the SendGrid API key is stored in Secret Manager:

```bash
gcloud secrets describe sendgrid-api-key --project=ai-ta
```

If the secret doesn't exist, create it:

```bash
# Get your SendGrid API key from https://app.sendgrid.com/settings/api_keys
echo -n "your-sendgrid-api-key" | gcloud secrets create sendgrid-api-key \
  --project=ai-ta \
  --data-file=-
```

## Step 2: Verify Sender Email in SendGrid

SendGrid requires you to verify the email address you'll send from.

### Option A: Single Sender Verification (Easiest)

1. Go to [SendGrid Dashboard](https://app.sendgrid.com/)
2. Navigate to **Settings** > **Sender Authentication**
3. Click **Verify a Single Sender**
4. Fill in the form:
   - **From Name**: AI Teaching Assistant
   - **From Email Address**: noreply@yourdomain.com (or your preferred email)
   - Fill in other required fields
5. Click **Create**
6. Check your email and click the verification link

### Option B: Domain Authentication (Recommended for Production)

1. Go to [SendGrid Dashboard](https://app.sendgrid.com/)
2. Navigate to **Settings** > **Sender Authentication**
3. Click **Authenticate Your Domain**
4. Follow the wizard to add DNS records to your domain
5. Wait for verification (can take up to 48 hours)

## Step 3: Configure Environment Variable

Set the `SENDGRID_FROM_EMAIL` environment variable to match your verified sender:

### For Local Development:
```bash
export SENDGRID_FROM_EMAIL="noreply@yourdomain.com"
```

### For Production (Cloud Run):
```bash
gcloud run services update ai-ta-api \
  --update-env-vars SENDGRID_FROM_EMAIL="noreply@yourdomain.com" \
  --region us-east1
```

## Step 4: Test Email Sending

After deployment, check the logs:

```bash
gcloud run services logs read ai-ta-api --region us-east1 --limit 20
```

Look for:
```
SendGrid email service initialized, sending as: noreply@yourdomain.com
```

Test by calling the `/notify_student_grades` endpoint as an instructor.

## Troubleshooting

### Error: "SendGrid API key not found"
**Cause**: The secret `sendgrid-api-key` doesn't exist in Secret Manager

**Solution**:
```bash
echo -n "your-actual-api-key" | gcloud secrets create sendgrid-api-key \
  --project=ai-ta \
  --data-file=-
```

### Error: "Failed to send email: 403"
**Cause**: Sender email not verified in SendGrid

**Solution**:
1. Go to SendGrid Dashboard > Sender Authentication
2. Verify the email address in `SENDGRID_FROM_EMAIL`

### Error: "Failed to send email: 401"
**Cause**: Invalid SendGrid API key

**Solution**:
1. Generate a new API key in SendGrid Dashboard
2. Update the secret:
```bash
echo -n "new-api-key" | gcloud secrets versions add sendgrid-api-key \
  --data-file=-
```
3. Restart the application

### Warning: "SENDGRID_FROM_EMAIL not configured"
**Cause**: Environment variable not set

**Solution**: Set `SENDGRID_FROM_EMAIL` environment variable (see Step 3)

### Error: "Failed to send email: 400 Bad Request"
**Cause**: Invalid email format

**Solution**: Check that recipient email address is valid

## SendGrid Free Tier Limits

- **100 emails per day** (free tier)
- Paid plans start at $15/month for 40,000 emails
- API rate limit: 600 requests per minute

If you need more emails, upgrade your SendGrid plan at [SendGrid Pricing](https://sendgrid.com/pricing/).

## Verification Checklist

- [ ] SendGrid API key stored in Secret Manager as `sendgrid-api-key`
- [ ] Sender email verified in SendGrid dashboard
- [ ] `SENDGRID_FROM_EMAIL` environment variable set
- [ ] Application deployed/restarted
- [ ] Logs show "SendGrid email service initialized"
- [ ] Test email sent successfully

## Getting Your SendGrid API Key

If you need to create a new SendGrid API key:

1. Go to [SendGrid API Keys](https://app.sendgrid.com/settings/api_keys)
2. Click **Create API Key**
3. Name: "AI Teaching Assistant"
4. Permissions: **Full Access** or **Mail Send** only
5. Click **Create & View**
6. **IMPORTANT**: Copy the key immediately (you won't see it again!)
7. Store it in Secret Manager:
```bash
echo -n "SG.your-api-key" | gcloud secrets create sendgrid-api-key \
  --project=ai-ta \
  --data-file=-
```

## Monitoring Email Delivery

To monitor email delivery:

1. Go to [SendGrid Activity Feed](https://app.sendgrid.com/email_activity)
2. View sent emails, delivery status, and any errors
3. Check for bounces or spam reports

## Security Best Practices

1. **API Key**: Never commit API keys to git - always use Secret Manager
2. **Permissions**: Use "Mail Send" permission only (not "Full Access")
3. **Rotation**: Rotate API keys periodically (every 90 days recommended)
4. **Monitoring**: Regularly check SendGrid activity for unusual patterns

## Alternative: Gmail SMTP (Not Recommended)

If you prefer Gmail, you can use Gmail SMTP (requires app-specific password), but SendGrid is recommended for production use as it provides better deliverability, monitoring, and doesn't require Google Workspace.

## Support

- SendGrid Documentation: https://docs.sendgrid.com/
- SendGrid Support: https://support.sendgrid.com/
- API Status: https://status.sendgrid.com/
