# Deployment Guide: Google Cloud Run

This guide walks you through deploying the AI Teaching Assistant API to Google Cloud Run.

## Prerequisites

1. **Google Cloud SDK (gcloud CLI)** installed
   ```bash
   # Check if installed
   gcloud --version

   # If not installed, visit: https://cloud.google.com/sdk/docs/install
   ```

2. **Docker** installed
   ```bash
   docker --version
   ```

3. **Authenticated with Google Cloud**
   ```bash
   gcloud auth login
   gcloud config set project ai-ta
   ```

4. **Enable required APIs**
   ```bash
   gcloud services enable \
     cloudbuild.googleapis.com \
     run.googleapis.com \
     artifactregistry.googleapis.com \
     secretmanager.googleapis.com
   ```

## Step 1: Set Up Environment Variables

Create a file to store your production environment variable values (DO NOT commit this file):

```bash
# .env (DO NOT COMMIT)
ADMIN_EMAILS=admin@example.com
GOOGLE_CLOUD_PROJECT=your_project_name
SERVICE_ACCOUNT_EMAIL=email_id@project_id.iam.gserviceaccount.com
FIRESTORE_CLIENT_ID=<id>
FIRESTORE_DATABASE_ID=<database_name>
PRODUCTION=1
```

Firestore database is used in the backend and so a email service account
is needed to access this.

Use the following to create a .yaml file for use with gcloud deployment cli
```bash
sed 's/=/: "/' .env | sed 's/$/"/' > env.yaml
```

## Step 2: Ensure Secrets are in Secret Manager

Make sure all required secrets are stored in Google Cloud Secret Manager:

- `OAUTH_CLIENT_ID_KEY_NAME`
- `OAUTH_CLIENT_SECRET_KEY_NAME`
- `SIGNING_SECRET_KEY_NAME`
- `FIRESTORE_PRIVATE_KEY_ID_KEY_NAME`
- `FIRESTORE_PRIVATE_KEY_KEY_NAME`
- `GEMINI_API_KEY_NAME`

You can create/update secrets using:
```bash
echo -n "your-secret-value" | gcloud secrets create SECRET_NAME --data-file=-
```

## Step 3: Build and Push Docker Image

### Option A: Using Google Cloud Build (Recommended)

This builds the image in the cloud without needing local Docker.

```bash
# Set your project ID
export PROJECT_ID=<your-project-id>
export SERVICE_NAME=<your-service-name>

# Build and push using Cloud Build
gcloud builds submit --tag gcr.io/$PROJECT_ID/$SERVICE_NAME

# Or use Artifact Registry (newer, recommended)
gcloud builds submit --tag us-docker.pkg.dev/$PROJECT_ID/cloud-run-source-deploy/$SERVICE_NAME
```

### Option B: Build Locally and Push

```bash
# Set your project ID
export PROJECT_ID=<your-project-id>
export SERVICE_NAME=<your-service-name>

# Build the Docker image
docker build -t gcr.io/$PROJECT_ID/$SERVICE_NAME .

# Configure Docker to use gcloud credentials
gcloud auth configure-docker

# Push the image
docker push gcr.io/$PROJECT_ID/$SERVICE_NAME
```

## Step 4: Deploy to Cloud Run

```bash
# Set variables
export PROJECT_ID=<your-project-id>
export SERVICE_NAME=<your-service-name>
export REGION=asia-south1

# Deploy to Cloud Run
gcloud run deploy $SERVICE_NAME \
  --image gcr.io/$PROJECT_ID/$SERVICE_NAME \
  --platform managed \
  --region $REGION \
  --allow-unauthenticated \
  --set-env-vars "GOOGLE_CLOUD_PROJECT=$PROJECT_ID" \
  --set-env-vars "PRODUCTION=1" \
  --set-env-vars "FIRESTORE_DATABASE_ID=your-database-id" \
  --set-env-vars "ADMIN_EMAILS=admin@example.com" \
  --set-env-vars "SENDGRID_FROM_EMAIL=noreply@yourdomain.com" \
  --set-env-vars "OAUTH_CLIENT_ID_KEY_NAME=oauth-client-id" \
  --set-env-vars "OAUTH_CLIENT_SECRET_KEY_NAME=oauth-client-secret" \
  --set-env-vars "SIGNING_SECRET_KEY_NAME=signing-secret" \
  --set-env-vars "FIRESTORE_PRIVATE_KEY_ID_KEY_NAME=firestore-key-id" \
  --set-env-vars "FIRESTORE_PRIVATE_KEY_KEY_NAME=firestore-key" \
  --set-env-vars "GEMINI_API_KEY_NAME=gemini-api-key" \
  --memory 2Gi \
  --cpu 2 \
  --timeout 300 \
  --max-instances 10 \
  --min-instances 0
```

or if you have the env.yaml file then use 
```bash
gcloud run deploy $SERVICE_NAME \
  --image gcr.io/$PROJECT_ID/$SERVICE_NAME \
  --platform managed \
  --region $REGION \
  --allow-unauthenticated \
  --env-vars-file env.yaml \
  --memory 2Gi \
  --cpu 2 \
  --timeout 300 \
  --max-instances 10 \
  --min-instances 0
```

## Step 5: Update OAuth Redirect URI

After deployment, Cloud Run will give you a URL like:
```
https://<your-service-name>-622756405105.asia-south1.run.app
```
(Or check with: `gcloud run services describe <your-service-name> --region asia-south1 --format 'value(status.url)'`)

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Navigate to **APIs & Services** > **Credentials**
3. Edit your OAuth 2.0 Client ID
4. Add to **Authorized redirect URIs**:
   ```
   https://your-cloud-run-url.a.run.app/callback
   ```
5. Click **Save**

## Step 6: Configure SendGrid for Email Notifications (Optional but Recommended)

To enable email notifications for graded assignments, you need to set up SendGrid.

The SendGrid API key should already be stored in Secret Manager as `sendgrid-api-key`.

Quick steps:
1. Verify the secret exists: `gcloud secrets describe sendgrid-api-key --project=$PROJECT_ID`
2. Set `SENDGRID_FROM_EMAIL` environment variable (already done in Step 4)
3. Verify the sender email in SendGrid dashboard

If you skip this step, the application will work but email notifications won't be sent.

See [SENDGRID_SETUP.md](SENDGRID_SETUP.md) for complete setup instructions.

## Step 7: Test Your Deployment

```bash
# Get the service URL
gcloud run services describe $SERVICE_NAME --region $REGION --format 'value(status.url)'

# Test the login endpoint
curl https://your-cloud-run-url.a.run.app/login
```

## Updating the Deployment

When you make code changes:

```bash
# 1. Commit your changes to git
git add .
git commit -m "Your changes"
git push

# 2. Rebuild and redeploy
gcloud builds submit --tag gcr.io/$PROJECT_ID/$SERVICE_NAME

gcloud run deploy $SERVICE_NAME \
  --image gcr.io/$PROJECT_ID/$SERVICE_NAME \
  --region $REGION \
  --platform managed
```

## Environment Variables Reference

| Variable | Description | Example |
|----------|-------------|---------|
| `GOOGLE_CLOUD_PROJECT` | Google Cloud project ID | `ai-ta` |
| `PRODUCTION` | Set to 1 for production | `1` |
| `FIRESTORE_DATABASE_ID` | Firestore database ID | `(default)` |
| `ADMIN_EMAILS` | Comma-separated platform admin emails | `admin@example.com` |
| `SENDGRID_FROM_EMAIL` | Email address to send from (must be verified in SendGrid) | `noreply@yourdomain.com` |
| `OAUTH_REDIRECT_URI` | Optional custom redirect URI | Only for dev with ngrok |
| Secret key environment variables (point to Secret Manager secrets) ||
| `OAUTH_CLIENT_ID_KEY_NAME` | Name of secret containing OAuth client ID | `oauth-client-id` |
| `OAUTH_CLIENT_SECRET_KEY_NAME` | Name of secret containing OAuth client secret | `oauth-client-secret` |
| `SIGNING_SECRET_KEY_NAME` | Name of secret for session signing | `signing-secret` |
| `FIRESTORE_PRIVATE_KEY_ID_KEY_NAME` | Name of secret for Firestore key ID | `firestore-key-id` |
| `FIRESTORE_PRIVATE_KEY_KEY_NAME` | Name of secret for Firestore private key | `firestore-key` |
| `GEMINI_API_KEY_NAME` | Name of secret for Gemini API key | `gemini-api-key` |

## Troubleshooting

### View logs
```bash
gcloud run services logs read $SERVICE_NAME --region $REGION --limit 50
```

### Check service status
```bash
gcloud run services describe $SERVICE_NAME --region $REGION
```

### Test locally with Docker
```bash
docker run -p 8080:8080 \
  -e GOOGLE_CLOUD_PROJECT=ai-ta \
  -e PRODUCTION=0 \
  gcr.io/$PROJECT_ID/$SERVICE_NAME
```

## Security Checklist

- [ ] All secrets stored in Secret Manager (not in environment variables)
- [ ] OAuth redirect URIs properly configured
- [ ] Instructor emails configured correctly
- [ ] Service account permissions reviewed
- [ ] Cloud Run service configured with appropriate memory/CPU limits
- [ ] Firestore security rules configured
- [ ] API rate limiting considered

## Cost Optimization

- Adjust `--min-instances` to 0 to scale to zero when not in use
- Set appropriate `--max-instances` based on expected load
- Monitor usage in Google Cloud Console > Cloud Run > Metrics
