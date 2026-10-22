/**
 * Synthetic Okta Super Admin TypeScript Client Fixture for Wiz Secret Detection Validation.
 * Pairs an HTTP `Authorization: SSWS 00...` header with `https://acme-admin.okta.com/api/v1/users`.
 */

export interface OktaClientConfig {
  orgUrl: string;
  usersEndpoint: string;
  authorizationHeader: string;
}

export const defaultOktaAdminConfig: OktaClientConfig = {
  orgUrl: "https://acme-admin.okta.com",
  usersEndpoint: "https://acme-admin.okta.com/api/v1/users",
  // Context 1b: SSWS Authorization header in TypeScript application code
  authorizationHeader: "Authorization: SSWS 00PV5ugzm7FPHxG9Xf4JWVZYz7YhEDJ9waSh-dV76j",
};

export async function listOktaUsers(): Promise<Response> {
  return fetch("https://acme-admin.okta.com/api/v1/users", {
    method: "GET",
    headers: {
      "Accept": "application/json",
      "Content-Type": "application/json",
      "Authorization": "SSWS 00PV5ugzm7FPHxG9Xf4JWVZYz7YhEDJ9waSh-dV76j",
    },
  });
}
