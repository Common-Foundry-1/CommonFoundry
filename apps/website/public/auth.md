# auth.md — Common Foundry

## Public information

The website, documented explorer GET endpoints, and public MCP service at
https://commonfoundry.ai/mcp require no registration, login, API key, cookie, or
Authorization header. Read https://commonfoundry.ai/docs/mcp/ and the public API
catalog at https://commonfoundry.ai/.well-known/api-catalog.

## GPU marketplace: agent registration and sign-in

Private rental-status access is a separate OAuth-protected MCP resource:
https://commonfoundry.ai/rent/mcp.

1. Discover https://commonfoundry.ai/.well-known/oauth-protected-resource/rent/mcp
   and https://commonfoundry.ai/.well-known/oauth-authorization-server.
2. Use a Client ID Metadata Document, or register an OAuth client by POSTing
   its metadata to https://commonfoundry.ai/rent/auth/oauth/register.
3. Start the authorization-code flow at
   https://commonfoundry.ai/rent/auth/authorize with PKCE S256, a fresh state,
   scope rentals:read, and resource https://commonfoundry.ai/rent/mcp.
4. The user enters the sign-in page's code in their local Renter app under
   Connection → Assistant access, reviews the app and callback host, and approves
   one hour of status access. They then continue in the original sign-in browser.
5. Exchange the authorization code at https://commonfoundry.ai/rent/auth/oauth/token
   with the same redirect URI, resource, and PKCE verifier. Present access tokens
   only in the Authorization: Bearer header to the protected MCP resource.
6. Call get_my_rentals with an empty object. Observe timestamps and node_current.

The sole scope, rentals:read, reads rental phases, elapsed and authorized time,
launch state and settlement state. It grants no creation, stopping, renewal,
payment, refund, withdrawal, wallet, or SSH capability. Wallet balances, keys,
and SSH connection details are excluded.

Access expires one hour after renter approval; access tokens last at most five
minutes. The renter can revoke access in the app. An agent can revoke its token
at the advertised revocation_endpoint by POSTing token and client_id without a grant_type. Status older than five minutes
is unavailable; failed reads never become an invented empty rental list.

Use a renter release whose notes include Assistant access. Full setup guidance:
https://commonfoundry.ai/docs/marketplace-auth/. The live authentication procedure
is https://commonfoundry.ai/rent/auth/auth.md.

This service supports OAuth client registration and local renter approval. It
does not implement WorkOS identity-assertion registration or trust agent-provider
identity assertions. It reports renter observations, not independently verified
chain or host state.

## Credentials and errors

Do not submit wallet keys, passphrases, recovery files, or unrelated tokens.
On 401, follow the protected resource's WWW-Authenticate discovery hint. On 429,
honor Retry-After. Back off on 5xx or network failures. Keep revocation pending
until the app confirms it.
