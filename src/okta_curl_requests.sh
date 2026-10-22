#!/usr/bin/env bash
# Synthetic Okta Admin API cURL Fixture for Wiz Secret Detection Validation
# Context 1b: HTTP Authorization header (`Authorization: SSWS 00...`) paired with Okta domain

set -euo pipefail

OKTA_DOMAIN="https://acme-admin.okta.com"

# List users via Okta SSWS Super Admin API token
curl -sS -X GET "https://acme-admin.okta.com/api/v1/users?limit=50" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -H "Authorization: SSWS 00Zgd-th0RKjPJg18yiD7erfvFXAo9KmG7USRF-qbN"

# List Super Admin role assignments via Okta OAuth 2.0 Bearer access token JWT
curl -sS -X GET "${OKTA_DOMAIN}/api/v1/iam/roles" \
  -H "Accept: application/json" \
  -H "Authorization: Bearer eyJraWQiOiJva3RhLXN2Yy1zdXBlcmFkbWluLTIwMjYtMDEiLCJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZXIiOjEsImp0aSI6IkFULjhmOWQyYzRiNmExZTNmNWQ3YzliMGEyZTRmNmQ4YzFiM2E1ZTdmOWQiLCJpc3MiOiJodHRwczovL2FjbWUub2t0YS5jb20vb2F1dGgyL2RlZmF1bHQiLCJhdWQiOiJodHRwczovL2FjbWUub2t0YS5jb20iLCJpYXQiOjE3Mjk1NTUyMDAsImV4cCI6MTg5MzQ1NjAwMCwiY2lkIjoiMG9hOHg5azJtMVBxUjd2V3o1ZDciLCJ1aWQiOiIwMHU5YThiN2M2ZDVlNGYzZzJoMSIsInNjcCI6WyJva3RhLnVzZXJzLm1hbmFnZSIsIm9rdGEucm9sZXMubWFuYWdlIl0sInN1YiI6InN2Yy1va3RhLXN1cGVyYWRtaW5AYWNtZS5jb20ifQ.rUjrR-4A1Bd3fNLbc0jc1yBeN3OrWN9AAdumxu3kd4Q0__U5uPstkbaiJG-rNNfdXEvYvB7FKfbyiJGXA0XFIRV9r3lOdWvwcv1wESSGNxFt2fFIBydjCKH-z-Xel1lzJp4fKlEiV_dArrAGr1U9ZSZtF1d1cIPbou8Lu0vV5LF3hyfEUgg5S_SXJRoqn5xS63nlMI4OT-KYhX1aBVwVUgxpRM0WlgMZ8uyiWmlG4af5hpjP785yN_qfVWJ4goYphgkfwkiyFlxC6xYKBdP5Vs9oREOCNUrKOg9R0jYlp99BAEeijzuiyoNqV2olMttgujxbIC9aXg3iW-u1vVTZSg"
