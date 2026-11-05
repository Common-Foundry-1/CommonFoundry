# auth.md — Common Foundry

## Service and access model

The website at https://commonfoundry.ai is public. The read-only API described
in https://commonfoundry.ai/openapi.json is hosted at
https://explorer.commonfoundry.ai. Its documented GET endpoints require no
registration, login, API key, cookie, or Authorization header.

The public MCP service at https://commonfoundry.ai/mcp also requires no
credentials. Its POST transport carries only read-only tools and resources;
see https://commonfoundry.ai/docs/mcp/ for connection instructions and limits.

## Discover the public API

1. Read the catalog at https://commonfoundry.ai/.well-known/api-catalog.
2. Follow its `service-desc` link for the OpenAPI description and `service-doc`
   link for usage instructions.
3. Request the documented public endpoints directly. No account setup is needed.

```http
GET /api/supply HTTP/1.1
Host: explorer.commonfoundry.ai
Accept: application/json
```

## Registration, login, and scopes

This public website does not provide agent registration, OAuth token issuance,
or delegated account scopes. No authorization-server or protected-resource
metadata endpoint is advertised. This file describes current access; it does
not claim implementation of the auth.md agent registration protocol.

Wallet creation, unlocking, transaction signing, and GPU rental spending use
their respective wallet or renter applications and require the user's control
and authorization. Reading public chain data does not grant those permissions.
See https://commonfoundry.ai/learn/ and https://commonfoundry.ai/rent/.

## Credentials and errors

Do not submit wallet keys, passphrases, recovery files, or third-party tokens to
the public data endpoints. They do not need credentials.

If a request returns 429, honor `Retry-After` when present and reduce request
frequency. On 5xx or a network error, back off and retry later. Do not guess
login or registration URLs when a public endpoint is temporarily unavailable.

Updated November 5, 2026.
