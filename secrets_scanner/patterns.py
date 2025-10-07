import re

# Central list of secret detection patterns
PATTERNS = {
    "AWS Access Key ID": re.compile(r"\b(AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16,}\b"),
    "AWS Secret Access Key": re.compile(r"(?i)(aws_?secret_?access_?key|secret_?access_?key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),

    "GitHub Personal Access Token": re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,255}\b"),
    "GitHub Fine-Grained PAT": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,255}\b"),

    "Slack Token": re.compile(r"\bxox[bpaeors]-[A-Za-z0-9-]{10,}\b"),
    "Slack Webhook": re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+"),

    "Stripe Secret Key": re.compile(r"\b(sk|rk)_(live|test)_[A-Za-z0-9]{20,}\b"),
    "Stripe Publishable Key": re.compile(r"\bpk_(live|test)_[A-Za-z0-9]{20,}\b"),

    "Twilio Account SID": re.compile(r"\bAC[0-9a-fA-F]{32}\b"),
    "Twilio API Key SID": re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
    "Twilio Auth Token": re.compile(r"(?i)\b(twilio_)?auth(_)?token['\"]?\s*[:=]\s*['\"]?([0-9a-f]{32})['\"]?"),

    "SendGrid API Key": re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{30,}\b"),

    "Discord Bot/User Token": re.compile(r"\b[A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,}\b"),
    "Discord Webhook": re.compile(r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d{5,30}/[A-Za-z0-9_-]{30,}"),

    "Telegram Bot Token": re.compile(r"\b\d{7,12}:[A-Za-z0-9_-]{35,}\b"),

    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z\-_\\]{32,40}\b"),
    "Google OAuth Token": re.compile(r"\bya29\.[0-9A-Za-z\-_]{20,}\b"),
    "GCP Service Account": re.compile(r"\b[A-Za-z0-9\-\_]+@[A-Za-z0-9\-\_]+\.iam\.gserviceaccount\.com\b"),

    "OpenAI API Key": re.compile(r"\bsk-(proj-)?[A-Za-z0-9]{20,200}\b"),

    "GitLab Personal Access Token": re.compile(r"\bglpat-[0-9A-Za-z\-_]{20,}\b"),

    "npm Token": re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b"),
    "PyPI Token": re.compile(r"\bpypi-[A-Za-z0-9\-_]{40,}\b"),

    "Atlassian API Token (Basic Auth)": re.compile(r"https?://[^/\s:@]+:[^/\s:@]+@[^/\s]+"),

    "Azure Storage Connection String": re.compile(r"DefaultEndpointsProtocol=(?:http|https);AccountName=[A-Za-z0-9\-]+;AccountKey=([A-Za-z0-9+/=]{40,});EndpointSuffix=core\.windows\.net"),
    "Azure SAS Token": re.compile(r"[\?&]sv=\d{4}-\d{2}-\d{2}[^ \n]*?&sig=[A-Za-z0-9%+/=]{16,}"),

    "JWT Token": re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),

    "Private Key (PEM)": re.compile(r"-----BEGIN (?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----"),
    "OpenSSH Private Key": re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----"),
    "PGP Private Key": re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]+?-----END PGP PRIVATE KEY BLOCK-----"),

    "Password Assignment": re.compile(r"(?i)\b(pass(word)?|pwd)\s*[:=]\s*['\"][^'\"\n]{8,}['\"]"),
    "API Key Assignment": re.compile(r"(?i)\b(api[_\-]?key|token|secret|client_secret)\s*[:=]\s*['\"][^'\"\n]{16,}['\"]"),

    "Bitbucket App Password": re.compile(r"https://[^/\s:@]+:[^/\s:@]+@bitbucket\.org"),
    "Databricks PAT": re.compile(r"\bdapi[A-Za-z0-9]{32}\b"),
    "Firebase FCM Server Key": re.compile(r"AAAA[A-Za-z0-9_-]{7,}:[A-Za-z0-9_-]{140,}"),
    "Shopify Token": re.compile(r"\bshp(at|pa|ss)_[0-9a-f]{32}\b"),
    "Notion Integration Token": re.compile(r"\bsecret_[A-Za-z0-9]{32,}\b"),
    "Linear API Key": re.compile(r"\blin_api_[A-Za-z0-9]{40,}\b"),
    "Mapbox Access Token": re.compile(r"\b[ps]k\.[A-Za-z0-9\-_.]{30,}\b"),
    "Dropbox Access Token": re.compile(r"\bsl\.[A-Za-z0-9_-]{120,}\b"),
    "DigitalOcean Personal Access Token": re.compile(r"\bdop_v1_[a-f0-9]{64}\b"),
    "Square Access Token": re.compile(r"\bEAAA[A-Za-z0-9]{60}\b"),
    "Airtable Personal Access Token": re.compile(r"\bpat[A-Za-z0-9]{14}\b"),
    "Airtable Legacy API Key": re.compile(r"\bkey[A-Za-z0-9]{14}\b"),
    "Facebook Access Token": re.compile(r"\bEAA[A-Za-z0-9]{30,}\b"),
}

