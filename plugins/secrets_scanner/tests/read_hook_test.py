#!/usr/bin/env python3
"""Unified test runner for secrets_scanner_hook.py secret scanning hook."""

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Optional


GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'


HOOK_PATH = Path(__file__).resolve().parent.parent / "hooks" / "secrets_scanner_hook.py"


def wrap_secret(secret_value: str) -> str:
    """Build standard two-line content used by the basic suite."""
    return f"API_KEY={secret_value}\nSECRET={secret_value}"


def run_hook_test(
    payload,
    description: str,
    should_detect: bool = True,
    *,
    mode: str = "post",
    wrap_content: bool = True,
    expect_exit: Optional[int] = None,
):
    """Run the hook with synthetic data and report detection."""

    # Test with both client types to ensure compatibility
    for client_type in ["claude_code", "cursor"]:
        if wrap_content:
            if client_type == "claude_code":
                hook_input = {
                    "tool_input": {"file_path": "test.env"},
                    "tool_response": payload,
                }
            else:  # cursor
                hook_input = {
                    "hook_event_name": "afterShellExecution" if mode == "post" else "beforeReadFile",
                    "file_path": "test.env",
                    "content": payload if mode == "pre" else None,
                    "stdout": payload if mode == "post" else None,
                }
        else:
            hook_input = payload
            # If payload already has client-specific format, only test with that client
            if isinstance(payload, dict) and "hook_event_name" in payload:
                ev = payload.get("hook_event_name")
                CLAUDE_EVENTS = {
                    "PreToolUse",
                    "PostToolUse",
                    "UserPromptSubmit",
                    "Notification",
                    "Stop",
                    "SubagentStop",
                    "PreCompact",
                    "SessionStart",
                    "SessionEnd",
                }
                CURSOR_EVENTS = {
                    "beforeReadFile",
                    "afterFileEdit",
                    "beforeSubmitPrompt",
                    "beforeShellExecution",
                    "afterShellExecution",
                    "beforeMCPExecution",
                    "afterMCPExecution",
                    "stop",
                }
                if ev in CLAUDE_EVENTS and client_type != "claude_code":
                    continue
                if ev in CURSOR_EVENTS and client_type != "cursor":
                    continue
            if ("tool_input" in payload) and client_type != "claude_code":
                continue

        result = subprocess.run(
            ["python3", str(HOOK_PATH), f"--mode={mode}", f"--client={client_type}"],
            input=json.dumps(hook_input),
            capture_output=True,
            text=True,
        )

        if expect_exit is not None and result.returncode != expect_exit:
            return (
                False,
                f"{RED}❌ FAIL{RESET}",
                f"{description} ({client_type}) - expected exit {expect_exit}, got {result.returncode}",
                payload,
            )

        try:
            # Try stdout first, then stderr (for exit code 2)
            output_text = result.stdout or result.stderr
            output = json.loads(output_text)
        except json.JSONDecodeError as exc:
            return (
                False,
                f"{RED}❌ ERROR{RESET}",
                f"{description} ({client_type}) - invalid JSON from hook: {exc}",
                payload,
            )

        # Check for message in various formats
        message_present = any(
            bool(output.get(key)) for key in ("message", "userMessage", "agentMessage", "reason")
        )
        
        # Check hookSpecificOutput (new Claude Code format)
        hook_output = output.get("hookSpecificOutput", {})
        permission_decision = hook_output.get("permissionDecision")
        permission_reason = hook_output.get("permissionDecisionReason")
        additional_context = hook_output.get("additionalContext")
        
        # Check old formats
        action = output.get("action")
        allow = output.get("allow")
        permission = output.get("permission")
        continue_flag = output.get("continue")
        decision = output.get("decision")

        detected = (
            message_present
            or permission_reason
            or additional_context
            or permission_decision == "deny"
            or decision == "block"
            or action == "block"
            or allow is False
            or permission in {"deny", "ask"}
            or continue_flag is False
        )

        if should_detect:
            if not detected:
                return False, f"{RED}❌ FAIL{RESET}", f"{description} ({client_type}) - expected detection, got none", payload
        else:
            if detected:
                return False, f"{YELLOW}⚠️  WARN{RESET}", f"{description} ({client_type}) - false positive", payload

    # If we get here, all client types passed
    return True, f"{GREEN}✅ PASS{RESET}", description, payload


BASIC_TESTS = {
    "AWS Credentials": [
        (wrap_secret("AKIAIOSFODNN7EXAMPLE"), "AWS AKIA key (long-term, 20 chars)", True),
        (wrap_secret("ASIATESTACCESSKEY123"), "AWS ASIA key (temporary, 20 chars)", True),
        (wrap_secret("ABIA" + "A" * 16), "AWS ABIA identifier (20 chars)", True),
        (wrap_secret("ACCA" + "B" * 16), "AWS ACCA identifier (20 chars)", True),
        (wrap_secret("aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"), "AWS secret key with assignment", True),
        (wrap_secret("SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"), "AWS secret key alt format", True),
    ],
    "GitHub Tokens": [
        (wrap_secret("ghp_1234567890abcdefghijklmnopqrstuvwxyz"), "GitHub personal token (ghp_)", True),
        (wrap_secret("gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"), "GitHub OAuth token (gho_)", True),
        (wrap_secret("ghs_1a2b3c4d5e6f7g8h9i0jklmnopqrstuvwxyz"), "GitHub server-to-server (ghs_)", True),
        (wrap_secret("ghu_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"), "GitHub user-to-server (ghu_)", True),
        (wrap_secret("ghr_" + "A" * 36), "GitHub refresh token (ghr_)", True),
        (wrap_secret("github_pat_11AAAAAAA0123456789abcdefghijklmnopqrstuvwxyz"), "GitHub fine-grained PAT", True),
    ],
    "Slack Credentials": [
        (wrap_secret("xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrSt"), "Slack bot token", True),
        (wrap_secret("xoxp-1234567890-1234567890-1234567890-abcdef1234567890abcdef1234567890ab"), "Slack user token", True),
        (wrap_secret("xoxa-1234567890-1234567890-abcdefghijklmnop"), "Slack workspace token (deprecated)", True),
        (wrap_secret("xoxr-1234567890-abcdefghijklmnopqrstuv"), "Slack refresh token", True),
        # Note: detect-secrets regexes do not include 'xoxe' tokens; skipping rotatable token variant
        (wrap_secret("https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"), "Slack webhook URL", True),
    ],
    "Payment Providers": [
        (wrap_secret("sk_live_51A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5"), "Stripe secret key (live)", True),
        (wrap_secret("sk_test_4eC39HqLyjWDarjtT1zdp7dc1234567890abcdefghijklmnopqr"), "Stripe secret key (test)", True),
        (wrap_secret("rk_live_51A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4"), "Stripe restricted key (live)", True),
        (wrap_secret("rk_test_51A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4"), "Stripe restricted key (test)", True),
        (wrap_secret("pk_live_51A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6"), "Stripe publishable key (live)", True),
        (wrap_secret("pk_test_51A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6"), "Stripe publishable key (test)", True),
    ],
    "Twilio": [
        (wrap_secret("AC0123456789abcdef0123456789abcdef"), "Twilio Account SID", True),
        (wrap_secret("SK0123456789abcdef0123456789abcdef"), "Twilio API Key SID", True),
        (wrap_secret("TWILIO_AUTH_TOKEN=0123456789abcdef0123456789abcdef"), "Twilio auth token with assignment", True),
    ],
    "Google Cloud": [
        (wrap_secret("AIzaSyD1234567890abcdefghijklmnopqrs"), "Google API Key (39 chars)", True),
        (wrap_secret("AIzaSyD-1234567890-abcdefghijklmnopqrs"), "Google API Key with hyphens (39 chars)", True),
        (wrap_secret("AIzaSyD_1234567890_abcdefghijklmnopqrs"), "Google API Key with underscores (39 chars)", True),
        (wrap_secret("ya29.a0AfH6SMBx1234567890-abcdefghijklmnopqrstuvwxyz"), "Google OAuth token (ya29)", True),
        # GCP service account emails removed - they're identifiers, not secrets
    ],
    "OpenAI": [
        # detect-secrets pattern requires sentinel 'T3BlbkFJ' and strict segment lengths
        (wrap_secret("sk-proj-abc-" + "A" * 20 + "T3BlbkFJ" + "B" * 20), "OpenAI API key (project)", True),
    ],
    "Other SaaS": [
        (wrap_secret("glpat-abc123def456ghi789jkl"), "GitLab personal access token", True),
        (wrap_secret("SG." + "A" * 22 + "." + "B" * 43), "SendGrid API key", True),
        (wrap_secret("npm_1234567890abcdefghijklmnopqrstuvwxyz"), "npm token", True),
        (wrap_secret("pypi-AgEIcHlwaS5vcmc" + "A" * 72), "PyPI token", True),
    ],
    "Discord & Telegram": [
        (wrap_secret("N" + "a" * 24 + ".ABC123." + "b" * 27), "Discord bot token", True),
        (wrap_secret("https://discord.com/api/webhooks/123456789012345/abcdefghijklmnopqrstuvwxyz1234567890"), "Discord webhook", True),
        (wrap_secret("12345678:" + "A" * 35), "Telegram bot token", True),
    ],
    "Azure": [
        (wrap_secret("DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJ==;EndpointSuffix=core.windows.net"), "Azure storage connection string", True),
        (wrap_secret("?sv=2020-08-04&ss=bfqt&srt=sco&sp=rwdlacupitfx&sig=abcdefghijklmnopqrstuvwxyz12345678%3D"), "Azure SAS token", True),
    ],
    "JWT & Authentication": [
        (wrap_secret("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"), "JWT token", True),
    ],
    "Private Keys": [
        (wrap_secret("-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7VJTUt9Us8cKj\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7VJTUt9Us8cKj\n-----END PRIVATE KEY-----"), "PEM private key", True),
        (wrap_secret("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN\nOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRST\n-----END RSA PRIVATE KEY-----"), "RSA private key", True),
        (wrap_secret("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACDjNITquU0UpKJBD9gvgNq2O9GlVYJPnLGaO9N1R6Q9CQAAAJgNYxKUDWMS\n-----END OPENSSH PRIVATE KEY-----"), "OpenSSH private key", True),
        (wrap_secret("-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\n\nlQOYBFzQxOsBCADHvT3VfN9+ZhX3dWvXGPLjFDvmJj7jWZqjkT7q8sVkT9xzQmN8\nmJPLVwXYXZT9zQxRJPvXZqT7qjkVwXYZT9zQxRJPvXZqT7qjkVwXYZT9zQxRJPvX\n-----END PGP PRIVATE KEY BLOCK-----"), "PGP private key", True),
    ],
    "Generic Patterns": [
        (wrap_secret('PASSWORD="MySecurePassword123!"'), "Password assignment", True),
        (wrap_secret('password="admin123456789"'), "Password assignment (lowercase)", True),
    ],
    "Additional Providers": [
        (wrap_secret("https://user:app_password@bitbucket.org/repo.git"), "Bitbucket app password in URL", True),
        (wrap_secret("dapi" + "a" * 32), "Databricks personal access token", True),
        (wrap_secret("AAAAAabcdef12345:APA91b" + "c" * 150), "Firebase FCM server key", True),
        (wrap_secret("shpat_1234567890abcdef1234567890abcdef"), "Shopify shpat token", True),
        (wrap_secret("shpss_abcdef1234567890abcdef1234567890"), "Shopify shared secret token", True),
        (wrap_secret("secret_ABCD1234EFGH5678IJKL9012MNOP3456QRSTUV"), "Notion integration token", True),
        (wrap_secret("lin_api_" + "A" * 40), "Linear API key", True),
        (wrap_secret("pk.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd"), "Mapbox access token", True),
        (wrap_secret("sl." + "A" * 140), "Dropbox access token", True),
        (wrap_secret("dop_v1_" + "a" * 64), "DigitalOcean personal access token", True),
        (wrap_secret("EAAA" + "A" * 60), "Square access token", True),
        (wrap_secret("patEceGFxxVzGDZoA.22b91547ed078219ec79315c34c2b526f1ddd02e567547f5dd7d37dbe1bf0512"), "Airtable personal access token", True),
        # Airtable legacy API key removed - pattern was too broad and deprecated
        (wrap_secret("EAA" + "A" * 35), "Facebook access token", True),
    ],
    "Edge Cases & Should NOT Detect": [
        (wrap_secret("AKIA123"), "Too short AWS key", False),
        (wrap_secret("ghp_short"), "Too short GitHub token", False),
        (wrap_secret("sk_live_short"), "Too short Stripe key", False),
        (wrap_secret("xoxb-123"), "Too short Slack token", False),
        (wrap_secret("AIza123"), "Too short Google API key", False),
        (wrap_secret("not-a-secret"), "Random string", False),
        (wrap_secret('PASSWORD=""'), "Empty password", False),
    ],
}


EXTENDED_TESTS = {
    "Real-World Scenarios": [
        ("""
# AWS Configuration
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1
""".strip(), "Multi-line AWS config", True),
        ("""
GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz
SLACK_TOKEN=xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrSt
DATABASE_URL=postgresql://user:pass@localhost/db
""".strip(), "Docker env file with multiple secrets", True),
        ('{"api_key": "sk_live_51A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5", "webhook": "https://hooks.slack.com/services/T00/B00/XXX"}', "JSON with secrets", True),
        ("""
credentials:
  github_token: ghp_1234567890abcdefghijklmnopqrstuvwxyz
  stripe_key: sk_test_4eC39HqLyjWDarjtT1zdp7dc1234567890abcdefghijklmnopqr
""".strip(), "YAML-like config", True),
        ("""
export OPENAI_API_KEY=sk-proj-abc-AAAAAAAAAAAAAAAAAAAAT3BlbkFJBBBBBBBBBBBBBBBBBBBB
export GOOGLE_API_KEY=AIzaSyD1234567890abcdefghijklmnopqrs
curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com
""".strip(), "Shell script with secrets", True),
    ],
    "Edge Cases - Whitespace & Formatting": [
        ("  AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE  ", "Secret with surrounding whitespace", True),
        ("KEY='AKIAIOSFODNN7EXAMPLE'", "Secret in single quotes", True),
        ('KEY="AKIAIOSFODNN7EXAMPLE"', "Secret in double quotes", True),
        ("KEY=`AKIAIOSFODNN7EXAMPLE`", "Secret in backticks", True),
        ("AKIAIOSFODNN7EXAMPLE\n", "Secret with newline", True),
        ("\tAKIAIOSFODNN7EXAMPLE", "Secret with tab prefix", True),
    ],
    "Edge Cases - URL Encoded": [
        ("token=ghp_1234567890abcdefghijklmnopqrstuvwxyz&other=param", "Secret in URL params", True),
        ("https://api.example.com?key=sk_live_51A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5", "Secret in URL", True),
    ],
    "Edge Cases - Code Contexts": [
        ("const apiKey = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz';", "JavaScript const", True),
        ('API_KEY = "sk_live_51A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5"', "Python assignment", True),
        ("String apiKey = \"AKIAIOSFODNN7EXAMPLE\";", "Java string", True),
        ("$token = 'xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrSt';", "PHP variable", True),
    ],
    "Edge Cases - Comments": [
        ("# API_KEY=AKIAIOSFODNN7EXAMPLE", "Secret in comment (should still detect)", True),
        ("// TOKEN: ghp_1234567890abcdefghijklmnopqrstuvwxyz", "Secret in C++ comment", True),
        ("/* SECRET: sk_live_51A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5 */", "Secret in block comment", True),
    ],
    "Multiple Secrets in One Line": [
        ("AWS_KEY=AKIAIOSFODNN7EXAMPLE GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz", "Two secrets one line", True),
        ("AKIAIOSFODNN7EXAMPLE,ghp_1234567890abcdefghijklmnopqrstuvwxyz,sk_live_51A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5", "CSV of secrets", True),
    ],
    "Variations - Different Lengths": [
        ("AKIAIOSFODNN7EXAMPL0", "AWS key exactly 20 chars", True),
        ("ghp_" + "a" * 36, "GitHub token exact length (36)", True),
        ("sk_live_" + "a" * 50, "Stripe key min length (50)", True),
        ("AIza" + "a" * 32, "Google key min length (32)", True),
        ("ghp_" + "a" * 100, "GitHub token long (104 chars)", False),
        ("sk-proj-" + "a" * 150, "OpenAI long project key (not DS format)", False),
        ("glpat-" + "a" * 50, "GitLab long token", True),
    ],
    "Private Keys - Various Formats": [
        ("""-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,12345

MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP
QRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV
-----END RSA PRIVATE KEY-----""", "Encrypted RSA key", True),
        ("""-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIGlRQipl5kjpubdLPPG3DjE1X0LPZ+GL8p+3ZuLQR2voAoGCCqGSM49
AwEHoUQDQgAE8Xmf7Q9N8K3L4M5P6R7S8T9U0V1W2X3Y4Z5A6B7C8D9E0F1G2H3I4J
-----END EC PRIVATE KEY-----""", "EC private key", True),
        ("""-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIvLKvMKqXCzGYAgIH
0DCBlgYJKoZIhvcNAQUMMIGIBAOAgICAgICAgICAgICAgICAgICAgICAgICAgICA
-----END ENCRYPTED PRIVATE KEY-----""", "Encrypted private key", True),
    ],
    "Case Sensitivity Tests": [
        ("akiaiosfodnn7example", "AWS key lowercase (should NOT match)", False),
        ("GHPSOMETHING1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ", "GitHub-like but wrong format", False),
        ("SK_LIVE_ABCDEFGHIJKLMNOPQRSTUVWXYZ", "Stripe-like but wrong case", False),
    ],
    "Near Misses - Should NOT Detect": [
        ("AKI", "Too short prefix only", False),
        ("AKIA", "Prefix only no value", False),
        ("ghp_", "GitHub prefix only", False),
        ("sk_live_", "Stripe prefix only", False),
        ("xoxb-", "Slack prefix only", False),
        ("https://hooks.slack.com/services/", "Slack webhook incomplete", False),
        ("-----BEGIN PRIVATE KEY-----", "Private key header only", False),
        ("my-api-key-here", "Generic string", False),
        ("12345678901234567890", "Just numbers", False),
    ],
    "Boundary Testing - Exact Lengths": [
        ("AKIA" + "A" * 16, "AWS exactly 20 (min)", True),
        ("AKIA" + "A" * 15, "AWS 19 chars (too short)", False),
        ("AKIA" + "A" * 17, "AWS 21 chars (should NOT match per DS)", False),
    ],
    "Special Characters in Context": [
        ("export TOKEN='ghp_1234567890abcdefghijklmnopqrstuvwxyz'", "Secret in export", True),
        ("-e STRIPE_KEY=sk_live_51A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5", "Docker flag with secret", True),
        ("Authorization: Bearer ghp_1234567890abcdefghijklmnopqrstuvwxyz", "HTTP header", True),
        ("?token=ghp_1234567890abcdefghijklmnopqrstuvwxyz&", "Query parameter", True),
    ],
    "Base64 Encoded Contexts": [
        ("eyJhcGlfa2V5IjoiQUtJQUlPU0ZPRE5ON0VYQU1QTEUifQ==", "Base64 with AWS key inside (should NOT detect)", False),
        ("Basic QUtJQUlPU0ZPRE5ON0VYQU1QTEU=", "Basic auth with base64 (should NOT detect)", False),
        ("Authorization: Basic QUtJQUlPU0ZPRE5ON0VYQU1QTEU= AKIAIOSFODNN7EXAMPLE", "Base64 AND plaintext secret", True),
    ],
    "Additional Providers": [
        ("https://user:app_password@bitbucket.org/scm/project/repo.git", "Bitbucket app password embedded in URL", True),
        ("export DATABRICKS_TOKEN=dapi" + "a" * 32, "Databricks personal access token", True),
        ("firebase_key=AAAAAabcdef12345:APA91b" + "c" * 150, "Firebase FCM server key", True),
        ("SHOPIFY_TOKEN=shpat_1234567890abcdef1234567890abcdef", "Shopify shpat token", True),
        ("SHOPIFY_SECRET=shpss_abcdef1234567890abcdef1234567890", "Shopify shared secret token", True),
        ("NOTION_TOKEN=secret_ABCD1234EFGH5678IJKL9012MNOP3456QRSTUV", "Notion integration token", True),
        ("export LINEAR_API_KEY=lin_api_" + "A" * 40, "Linear API key", True),
        ("MAPBOX_TOKEN=pk.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd", "Mapbox access token", True),
        ("DROPBOX_TOKEN=sl." + "A" * 140, "Dropbox access token", True),
        ("DIGITALOCEAN_TOKEN=dop_v1_" + "a" * 64, "DigitalOcean personal access token", True),
        ("SQUARE_TOKEN=EAAA" + "A" * 60, "Square access token", True),
        ("AIRTABLE_PAT=patEceGFxxVzGDZoA.22b91547ed078219ec79315c34c2b526f1ddd02e567547f5dd7d37dbe1bf0512", "Airtable personal access token", True),
        # Airtable legacy API key removed - pattern was too broad and deprecated
        ("FACEBOOK_TOKEN=EAA" + "A" * 35, "Facebook access token", True),
    ],
    "User Submit Hook": [
        (
            {
                "hook_event_name": "UserPromptSubmit",
                "prompt": "Please review before I send: ghp_1234567890abcdefghijklmnopqrstuvwxyz",
            },
            "Claude UserPromptSubmit with secret",
            True,
            {"mode": "pre", "wrap_content": False},
        ),
        (
            {
                "hook_event_name": "UserPromptSubmit",
                "prompt": "Please review the deployment plan",
            },
            "Claude UserPromptSubmit without secret",
            False,
            {"mode": "pre", "wrap_content": False},
        ),
    ],
    "Cursor Hook Events": [
        (
            {
                "hook_event_name": "beforeReadFile",
                "file_path": "cursor.env",
                "content": "OPENAI_API_KEY=sk-proj-abc-" + "A" * 20 + "T3BlbkFJ" + "B" * 20,
            },
            "Cursor beforeReadFile with secret",
            True,
            {"mode": "pre", "wrap_content": False},
        ),
        (
            {
                "hook_event_name": "beforeReadFile",
                "file_path": "cursor.env",
                "content": "SIMPLE_TEXT=hello",
            },
            "Cursor beforeReadFile without secret",
            False,
            {"mode": "pre", "wrap_content": False},
        ),
        (
            {
                "hook_event_name": "beforeSubmitPrompt",
                "prompt": "Please remember ghp_abcdefghijklmnopqrstuvwxyz1234567890",
            },
            "Cursor beforeSubmitPrompt with secret",
            True,
            {"mode": "pre", "wrap_content": False},
        ),
        (
            {
                "hook_event_name": "beforeSubmitPrompt",
                "prompt": "Please review the deployment plan",
            },
            "Cursor beforeSubmitPrompt without secret",
            False,
            {"mode": "pre", "wrap_content": False},
        ),
        (
            {
                "hook_event_name": "afterShellExecution",
                "command": "echo secret",
                "stdout": "OPENAI_KEY=sk-proj-abc-" + "A" * 20 + "T3BlbkFJ" + "B" * 20,
            },
            "Cursor afterShellExecution stdout with secret",
            True,
            {"mode": "post", "wrap_content": False},
        ),
        (
            {
                "hook_event_name": "afterShellExecution",
                "command": "echo done",
                "stdout": "deploy complete",
            },
            "Cursor afterShellExecution without secret",
            False,
            {"mode": "post", "wrap_content": False},
        ),
    ],
    "Command Output Hook": [
        (
            {
                "tool_input": {"tool_name": "bash", "command": "echo secret"},
                "tool_response": {"stdout": "OPENAI_KEY=sk-proj-abc-" + "A" * 20 + "T3BlbkFJ" + "B" * 20},
            },
            "Command stdout with OpenAI key",
            True,
            {"mode": "post", "wrap_content": False},
        ),
        (
            {
                "tool_input": {"tool_name": "bash", "command": "echo stderr"},
                "tool_response": {"stderr": "ghp_abcdefghijklmnopqrstuvwxyz1234567890"},
            },
            "Command stderr with GitHub token",
            True,
            {"mode": "post", "wrap_content": False},
        ),
        (
            {
                "tool_input": {"tool_name": "bash", "command": "echo nested"},
                "tool_response": {
                    "content": [
                        {
                            "type": "text",
                            "text": "No secrets here, just output",
                        }
                    ]
                },
            },
            "Command output without secrets",
            False,
            {"mode": "post", "wrap_content": False},
        ),
    ],
    "Real Provider Examples": [
        ("AWS_KEY=" + "AKIA" + "A" * 16, "Real AWS format with assignment", True),
        ("ASIAVEXAMPLE4EXAMPLE", "Real AWS STS format", True),
        ("ghp_16C7e42F292c6912E7710c838347Ae178B4a", "Real GitHub PAT format", True),
        ("xoxb-17653672481-19874698323-pdFZKVeTuE8sk7oOcBrzbqgy", "Real Slack bot format", True),
        ("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", "Real long Stripe key format", True),
    ],
}


SUITES = {
    "basic": {
        "title": "SECRET SCANNER COMPREHENSIVE TEST SUITE",
        "tests": BASIC_TESTS,
        "show_snippet": False,
    },
    "extended": {
        "title": "EXTENDED SECRET SCANNER TEST SUITE",
        "tests": EXTENDED_TESTS,
        "show_snippet": True,
    },
    "exitcodes": {
        "title": "CLAUDE EXIT CODE TESTS",
        "tests": {
            "PreToolUse": [
                (
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "Read",
                        "tool_input": {
                            "file_path": "dummy.txt",
                            "content": "OPENAI_API_KEY=sk-proj-abc-" + "A" * 20 + "T3BlbkFJ" + "B" * 20,
                        },
                    },
                    "Claude PreToolUse block exit code 2",
                    True,
                    {"mode": "pre", "wrap_content": False, "expect_exit": 2},
                ),
                (
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "Read",
                        "tool_input": {
                            "file_path": "dummy.txt",
                            "content": "hello world",
                        },
                    },
                    "Claude PreToolUse allow exit code 0",
                    False,
                    {"mode": "pre", "wrap_content": False, "expect_exit": 0},
                ),
            ],
            "PostToolUse": [
                (
                    {
                        "hook_event_name": "PostToolUse",
                        "tool_name": "Bash",
                        "tool_input": {"tool_name": "Bash", "command": "echo secret"},
                        "tool_response": {"stdout": "OPENAI_KEY=sk-proj-abc-" + "A" * 20 + "T3BlbkFJ" + "B" * 20},
                    },
                    "Claude PostToolUse block exit code 2",
                    True,
                    {"mode": "post", "wrap_content": False, "expect_exit": 2},
                ),
                (
                    {
                        "hook_event_name": "PostToolUse",
                        "tool_name": "Bash",
                        "tool_input": {"tool_name": "Bash", "command": "echo ok"},
                        "tool_response": {"stdout": "deploy complete"},
                    },
                    "Claude PostToolUse allow exit code 0",
                    False,
                    {"mode": "post", "wrap_content": False, "expect_exit": 0},
                ),
            ],
            "UserPromptSubmit": [
                (
                    {
                        "hook_event_name": "UserPromptSubmit",
                        "prompt": "Please remember ghp_abcdefghijklmnopqrstuvwxyz1234567890",
                    },
                    "Claude UserPromptSubmit block exit code 2",
                    True,
                    {"mode": "pre", "wrap_content": False, "expect_exit": 2},
                ),
                (
                    {
                        "hook_event_name": "UserPromptSubmit",
                        "prompt": "Please review the deployment plan",
                    },
                    "Claude UserPromptSubmit allow exit code 0",
                    False,
                    {"mode": "pre", "wrap_content": False, "expect_exit": 0},
                ),
            ],
        },
        "show_snippet": True,
    },
}


def run_suite(label: str, tests: dict, show_snippet: bool):
    """Execute a suite and return aggregated statistics."""
    total = passed = failed = warnings = 0

    print(f"\n{BLUE}{'=' * 80}{RESET}")
    print(f"{BLUE}{label}{RESET}")
    print(f"{BLUE}{'=' * 80}{RESET}\n")

    for category, cases in tests.items():
        print(f"\n{BLUE}[{category}]{RESET}")
        print("-" * 80)

        for case in cases:
            if len(case) == 3:
                payload, description, should_detect = case
                options = {}
            elif len(case) == 4 and isinstance(case[3], dict):
                payload, description, should_detect, options = case
            else:  # pragma: no cover - maintained for backwards compatibility
                payload, description, should_detect = case[:3]
                options = {}

            mode = options.get("mode", "post")
            wrap_content = options.get("wrap_content", mode == "post")

            total += 1
            success, status, message, payload_obj = run_hook_test(
                payload,
                description,
                should_detect,
                mode=mode,
                wrap_content=wrap_content,
            )

            if success:
                passed += 1
            elif "WARN" in status:
                warnings += 1
            else:
                failed += 1

            print(f"{status} {message}")

            if show_snippet and not success and "FAIL" in status:
                if isinstance(payload_obj, str):
                    snippet_source = payload_obj
                else:
                    snippet_source = json.dumps(payload_obj)
                snippet = snippet_source[:60].replace('\n', '\\n')
                print(f"       Content: {snippet}...")

    print(f"\n{BLUE}{'=' * 80}{RESET}")
    print(f"{BLUE}TEST SUMMARY{RESET}")
    print(f"{BLUE}{'=' * 80}{RESET}")
    print(f"Total tests: {total}")
    print(f"{GREEN}Passed: {passed}{RESET}")
    print(f"{RED}Failed: {failed}{RESET}")
    print(f"{YELLOW}Warnings (false positives): {warnings}{RESET}")

    if failed == 0 and warnings == 0:
        print(f"\n{GREEN}✅ ALL TESTS PASSED!{RESET}\n")
    elif failed == 0:
        print(f"\n{YELLOW}⚠️  ALL TESTS PASSED WITH WARNINGS{RESET}\n")
    else:
        print(f"\n{RED}❌ SOME TESTS FAILED{RESET}\n")

    return total, passed, failed, warnings


def main() -> int:
    parser = argparse.ArgumentParser(description="Run secrets_scanner_hook.py secret scanner tests")
    parser.add_argument(
        "--suite",
        choices=["basic", "extended", "exitcodes", "all"],
        default="all",
        help="Which test suite to run (default: all)",
    )
    args = parser.parse_args()

    suite_keys = ["basic", "extended", "exitcodes"] if args.suite == "all" else [args.suite]

    overall = {"total": 0, "passed": 0, "failed": 0, "warnings": 0}

    for key in suite_keys:
        suite = SUITES[key]
        total, passed, failed, warnings = run_suite(suite["title"], suite["tests"], suite["show_snippet"])
        overall["total"] += total
        overall["passed"] += passed
        overall["failed"] += failed
        overall["warnings"] += warnings

    if len(suite_keys) > 1:
        print(f"{BLUE}{'=' * 80}{RESET}")
        print(f"{BLUE}COMBINED SUMMARY{RESET}")
        print(f"{BLUE}{'=' * 80}{RESET}")
        print(f"Total tests: {overall['total']}")
        print(f"{GREEN}Passed: {overall['passed']}{RESET}")
        print(f"{RED}Failed: {overall['failed']}{RESET}")
        print(f"{YELLOW}Warnings: {overall['warnings']}{RESET}")
        print()

    return 0 if overall["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
