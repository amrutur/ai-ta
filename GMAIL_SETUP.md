# Gmail Service Account Setup Guide

This guide explains how to configure the service account to send emails using Gmail API with domain-wide delegation.

## Prerequisites

**IMPORTANT**: This setup requires **Google Workspace** (formerly G Suite). It will NOT work with regular/personal Gmail accounts.

If you don't have Google Workspace, see the "Alternative: Use SendGrid" section at the bottom.

## Overview

The application uses a service account (`ai-ta-firestore@ai-ta.iam.gserviceaccount.com`) with domain-wide delegation to send emails on behalf of a user in your Google Workspace domain.

## Step 1: Enable Gmail API

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Select your project: `ai-ta`
3. Navigate to **APIs & Services** > **Library**
4. Search for "Gmail API"
5. Click **Enable**

## Step 2: Configure Domain-Wide Delegation

### A. Get Service Account Client ID

1. Go to **IAM & Admin** > **Service Accounts**
2. Find your service account: `ai-ta-firestore@ai-ta.iam.gserviceaccount.com`
3. Click on the service account
4. Copy the **Client ID** (it's a long number, e.g., `101156988112383641306`)
   - You can also find it under "OAuth 2.0 Client ID"

### B. Enable Domain-Wide Delegation in Google Workspace Admin Console

**Note**: You need Google Workspace Admin privileges for this step.

1. Go to [Google Workspace Admin Console](https://admin.google.com/)
2. Navigate to **Security** > **Access and data control** > **API Controls**
3. Click **Manage Domain-Wide Delegation**
4. Click **Add new**
5. Enter the following:
   - **Client ID**: Paste the Client ID from Step 2A (the long number)
   - **OAuth Scopes**: Enter the following scope:
     ```
     https://www.googleapis.com/auth/gmail.send
     ```
6. Click **Authorize**

## Step 3: Configure Environment Variable

Set the `GMAIL_SENDER_EMAIL` environment variable to the email address you want to send from. This must be a valid email address in your Google Workspace domain.

### For Local Development:
```bash
export GMAIL_SENDER_EMAIL="noreply@yourdomain.com"
# or whatever email address you want to send from
```

### For Production (Cloud Run):
```bash
gcloud run services update ai-ta-api \
  --update-env-vars GMAIL_SENDER_EMAIL="noreply@yourdomain.com" \
  --region us-east1
```

Or add it in the Cloud Console:
1. Go to Cloud Run > ai-ta-api
2. Click **Edit & Deploy New Revision**
3. Add environment variable:
   - Name: `GMAIL_SENDER_EMAIL`
   - Value: `noreply@yourdomain.com` (or your preferred sender email)

## Step 4: Test Email Sending

After completing the setup:

1. Restart your application
2. Check logs for confirmation:
   ```
   Gmail service initialized with service account, sending as: noreply@yourdomain.com
   ```
3. Test the `/notify_student_grades` endpoint

## Troubleshooting

### Error: "Email service not initialized"
- **Cause**: `GMAIL_SENDER_EMAIL` environment variable not set
- **Solution**: Set the environment variable as shown in Step 3

### Error: "Client is unauthorized to retrieve access tokens"
- **Cause**: Domain-wide delegation not properly configured
- **Solution**:
  1. Verify you completed Step 2B in Google Workspace Admin Console
  2. Make sure you used the correct Client ID
  3. Double-check the scope: `https://www.googleapis.com/auth/gmail.send`
  4. Wait a few minutes for changes to propagate

### Error: "Failed to send email: 403"
- **Cause**: The sender email address doesn't exist in your domain or lacks permissions
- **Solution**:
  1. Verify the email address in `GMAIL_SENDER_EMAIL` exists in your Google Workspace
  2. Ensure the user account is active (not suspended)

### Error: "Failed to send email: 400"
- **Cause**: Invalid email format or recipient
- **Solution**: Check that the recipient email address is valid

### Logs show "GMAIL_SENDER_EMAIL not configured"
- **Cause**: Environment variable not set
- **Solution**: Set `GMAIL_SENDER_EMAIL` environment variable

## Verification Checklist

- [ ] Gmail API is enabled in Google Cloud Console
- [ ] Service account Client ID has been copied
- [ ] Domain-wide delegation configured in Google Workspace Admin Console
- [ ] Scope `https://www.googleapis.com/auth/gmail.send` is authorized
- [ ] `GMAIL_SENDER_EMAIL` environment variable is set
- [ ] Sender email address exists in your Google Workspace domain
- [ ] Application has been restarted
- [ ] Logs confirm Gmail service initialized successfully

## Security Best Practices

1. **Use a dedicated email address** for sending notifications (e.g., `noreply@yourdomain.com`)
2. **Limit scope** - Only grant `gmail.send`, not full Gmail access
3. **Monitor usage** - Regularly review sent emails in Gmail
4. **Rate limiting** - Be aware of Gmail API quotas (default: 1 billion quota units/day)

## Alternative: Use SendGrid (if you don't have Google Workspace)

If you don't have Google Workspace, you can use SendGrid instead:

### 1. Sign up for SendGrid
- Go to [SendGrid](https://sendgrid.com/)
- Create a free account (100 emails/day free tier)

### 2. Get API Key
- In SendGrid dashboard, go to Settings > API Keys
- Create a new API key with "Mail Send" permissions
- Copy the API key

### 3. Store API Key in Secret Manager
```bash
echo -n "your-sendgrid-api-key" | gcloud secrets create sendgrid-api-key --data-file=-
```

### 4. Modify Code
You would need to modify the email sending code to use SendGrid's Python library instead of Gmail API. This requires code changes which can be done if needed.

## Gmail API Quotas

- **Per-user rate limit**: 250 quota units per user per second
- **Daily quota**: 1 billion quota units per day
- Each email send costs approximately 100 quota units
- This means you can send approximately 10 million emails per day

For more details, see [Gmail API Usage Limits](https://developers.google.com/gmail/api/reference/quota)

## References

- [Domain-Wide Delegation Setup](https://developers.google.com/identity/protocols/oauth2/service-account#delegatingauthority)
- [Gmail API Documentation](https://developers.google.com/gmail/api)
- [Service Account Authentication](https://cloud.google.com/iam/docs/service-accounts)
