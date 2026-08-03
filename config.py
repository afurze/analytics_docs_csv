import os


GITBOOK_API_BASE = "https://api.gitbook.com/v1"
PUBLIC_DOCS_BASE = "https://cortex-docs.paloaltonetworks.com"
ALERTS_INDEX_PATH = "/analytics-alerts/alerts"

GITBOOK_SPACE_ID = os.getenv('GITBOOK_SPACE_ID', '')
GITBOOK_API_TOKEN = os.getenv('GITBOOK_API_KEY', '')

GOOGLE_SERVICE_ACCOUNT_FILE = os.getenv('GOOGLE_SERVICE_ACCOUNT_FILE', 'credentials.json')
GOOGLE_SHEET_ID = os.getenv('GOOGLE_SHEET_ID', '')

GCP_SECRET_NAME = os.getenv('GCP_SECRET_NAME', 'gitbook-api-token')
GCP_PROJECT_ID = os.getenv('GCP_PROJECT_ID', 'afurze')


def get_gitbook_token():
    """Resolve the GitBook API token with priority: env var > GCP Secret Manager > None."""
    if GITBOOK_API_TOKEN:
        return GITBOOK_API_TOKEN

    try:
        from google.cloud import secretmanager
        client = secretmanager.SecretManagerServiceClient()
        name = f"projects/{GCP_PROJECT_ID}/secrets/{GCP_SECRET_NAME}/versions/latest"
        response = client.access_secret_version(request={"name": name})
        token = response.payload.data.decode("UTF-8")
        if token:
            print("Loaded GitBook API token from GCP Secret Manager")
            return token
    except Exception as e:
        print(f"Could not load token from Secret Manager: {e}")

    return None
