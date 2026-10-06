#!/usr/bin/env python3
"""
Verify Wiz Custom Secret Detection Rules, CI/CD Scan Policy, and CI/CD Scan Results via Wiz GraphQL API.
Usage: python3 scripts/verify_wiz_api.py [--help]
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


def load_env(env_path: str) -> None:
    if not os.path.exists(env_path):
        return
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


def get_token(client_id: str, client_secret: str, auth_url: str) -> str:
    data = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "audience": "wiz-api",
    }).encode("utf-8")
    req = urllib.request.Request(
        auth_url,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))["access_token"]


def gql(api_url: str, token: str, query: str, variables: dict | None = None) -> dict:
    payload = json.dumps({"query": query, "variables": variables or {}}).encode("utf-8")
    req = urllib.request.Request(
        api_url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inspect Custom Secret Detection Rules, CI/CD Policies, and latest CI/CD Scans in Wiz."
    )
    parser.add_argument(
        "--env-file",
        default=".env",
        help="Path to .env file containing WIZ_CLIENT_ID and WIZ_CLIENT_SECRET (default: .env)",
    )
    args = parser.parse_args()

    load_env(args.env_file)
    client_id = os.environ.get("WIZ_CLIENT_ID")
    client_secret = os.environ.get("WIZ_CLIENT_SECRET")
    api_url = os.environ.get("WIZ_API_URL", "https://api.us100.app.wiz.io/graphql")
    auth_url = os.environ.get("WIZ_AUTH_URL", "https://auth.app.wiz.io/oauth/token")

    if not client_id or not client_secret:
        print("ERROR: WIZ_CLIENT_ID and WIZ_CLIENT_SECRET must be set.", file=sys.stderr)
        sys.exit(1)

    token = get_token(client_id, client_secret, auth_url)

    query = """
    query VerifyNatsSecretSuite {
      secretsSettings {
        customRules { enabled }
        codeValidation { enabled }
      }
      secretDetectionRules(first: 20, filterBy: { createdBy: [USER], search: "sr-nats" }) {
        nodes {
          id
          name
          enabled
          type
          severity
          targetPlatforms
          customLogic {
            valueRegex
            excludePaths
            excludeValuePatterns
          }
        }
      }
      cicdScanPolicies(first: 20, filterBy: { search: "sr-nats-custom-secrets-policy" }) {
        nodes {
          id
          name
          description
          params {
            __typename
            ... on CICDScanPolicyParamsSecrets {
              countThreshold
              pathAllowList
              secretFindingSeverityThreshold
            }
          }
        }
      }
      cicdScans(first: 5) {
        nodes {
          id
          createdAt
          status {
            verdict
            state
          }
          policies {
            id
            name
          }
          resultJSON
        }
      }
    }
    """
    result = gql(api_url, token, query)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
