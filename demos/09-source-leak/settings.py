"""Django settings recovered from a leaked source archive.

These values were hardcoded for 'convenience' and never moved to env vars.
"""
DEBUG = True
ALLOWED_HOSTS = ["*"]

# Signing key that protects every session cookie and password reset token.
SECRET_KEY = "django-insecure-9zq3vk2m7pwb4x8r6t1y0eu5oa2id7c3n9hg6q"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "prod",
        "USER": "webapp",
        "PASSWORD": "Pr0dDbP@ss!2024",
        "HOST": "db.internal",
    }
}

EMAIL_HOST_PASSWORD = "SmtpRelay#Secret88"

# third-party integrations
SENTRY_AUTH_TOKEN = "f1d2e3c4b5a69788a9b0c1d2e3f4a5b6c7d8e9f0"
