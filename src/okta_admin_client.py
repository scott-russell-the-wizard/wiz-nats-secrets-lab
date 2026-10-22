#!/usr/bin/env python3
"""
Synthetic Okta Admin API Client Fixture for Wiz Secret Detection Validation.
Tests detection of:
  1. HTTP Authorization header with Okta SSWS token (`Authorization: SSWS 00...`) paired with an Okta domain
  2. Okta / OIDC Bearer access token JWT (`iss: "https://acme.okta.com/oauth2/default"`)
"""

import urllib.request

OKTA_USERS_API_ENDPOINT = "https://acme-admin.okta.com/api/v1/users"
OKTA_ROLES_API_ENDPOINT = "https://acme-admin.okta.com/api/v1/iam/roles"

# Context 1b: HTTP Authorization header with SSWS token paired with Okta domain
OKTA_SSWS_AUTH_HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "Authorization": "SSWS 00IvJOAuPE5UTK1MrWoZU7eVAtpvmnQTV1qFBKv_gD",
}

# Raw HTTP request template containing Authorization: SSWS 00... header
RAW_HTTP_REQUEST_FIXTURE = (
    "GET /api/v1/users?limit=25 HTTP/1.1\r\n"
    "Host: acme-admin.okta.com\r\n"
    "Authorization: SSWS 00IvJOAuPE5UTK1MrWoZU7eVAtpvmnQTV1qFBKv_gD\r\n"
    "Accept: application/json\r\n\r\n"
)

# Context 2c: Okta / OIDC OAuth 2.0 Bearer Access Token JWT
# Payload claims: iss="https://acme.okta.com/oauth2/default", scp=["okta.users.manage", "okta.roles.manage"]
OKTA_OIDC_BEARER_JWT = "eyJraWQiOiJva3RhLXN2Yy1zdXBlcmFkbWluLTIwMjYtMDEiLCJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZXIiOjEsImp0aSI6IkFULjhmOWQyYzRiNmExZTNmNWQ3YzliMGEyZTRmNmQ4YzFiM2E1ZTdmOWQiLCJpc3MiOiJodHRwczovL2FjbWUub2t0YS5jb20vb2F1dGgyL2RlZmF1bHQiLCJhdWQiOiJodHRwczovL2FjbWUub2t0YS5jb20iLCJpYXQiOjE3Mjk1NTUyMDAsImV4cCI6MTg5MzQ1NjAwMCwiY2lkIjoiMG9hOHg5azJtMVBxUjd2V3o1ZDciLCJ1aWQiOiIwMHU5YThiN2M2ZDVlNGYzZzJoMSIsInNjcCI6WyJva3RhLnVzZXJzLm1hbmFnZSIsIm9rdGEucm9sZXMubWFuYWdlIl0sInN1YiI6InN2Yy1va3RhLXN1cGVyYWRtaW5AYWNtZS5jb20ifQ.rUjrR-4A1Bd3fNLbc0jc1yBeN3OrWN9AAdumxu3kd4Q0__U5uPstkbaiJG-rNNfdXEvYvB7FKfbyiJGXA0XFIRV9r3lOdWvwcv1wESSGNxFt2fFIBydjCKH-z-Xel1lzJp4fKlEiV_dArrAGr1U9ZSZtF1d1cIPbou8Lu0vV5LF3hyfEUgg5S_SXJRoqn5xS63nlMI4OT-KYhX1aBVwVUgxpRM0WlgMZ8uyiWmlG4af5hpjP785yN_qfVWJ4goYphgkfwkiyFlxC6xYKBdP5Vs9oREOCNUrKOg9R0jYlp99BAEeijzuiyoNqV2olMttgujxbIC9aXg3iW-u1vVTZSg"


def build_okta_users_request() -> urllib.request.Request:
    """Build a synthetic request to https://acme-admin.okta.com/api/v1/users."""
    return urllib.request.Request(
        url=OKTA_USERS_API_ENDPOINT,
        headers=OKTA_SSWS_AUTH_HEADERS,
        method="GET",
    )


def build_okta_oauth_request() -> urllib.request.Request:
    """Build a synthetic OAuth 2.0 Bearer request to https://acme-admin.okta.com/api/v1/iam/roles."""
    return urllib.request.Request(
        url=OKTA_ROLES_API_ENDPOINT,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {OKTA_OIDC_BEARER_JWT}",
        },
        method="GET",
    )
