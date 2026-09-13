# Keycloak 26.7.3 Standard Token Exchange v2 runtime constraints

Date: 2026-09-13. Scope: ticket 11's single installed Keycloak profile.

## Primary-source findings

Keycloak documents Standard Token Exchange as an implementation of RFC 8693 for
exchanging a Keycloak access token for another Keycloak access token. The
requester must be a confidential client, Standard Token Exchange must be
allowed on that client, and the requester must occur in the subject token's
`aud` claim. The `audience` parameter filters the audiences and client scopes
already available to the requester; it is not a generic permission escalation
mechanism. Public clients are not supported for this flow. The standard-v2
server switch is enabled by default, while each requester client uses the
`standard.token.exchange.enabled` client attribute.

Sources: Keycloak's [Standard Token Exchange
guide](https://www.keycloak.org/securing-apps/token-exchange#_standard-token-exchange),
the versioned [26.7.3 guide
source](https://github.com/keycloak/keycloak/blob/26.7.3/docs/guides/securing-apps/token-exchange.adoc),
and the versioned [OIDC client attribute
source](https://github.com/keycloak/keycloak/blob/26.7.3/server-spi-private/src/main/java/org/keycloak/protocol/oidc/OIDCConfigAttributes.java)
(the authoritative attribute name is also present in
`OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_ENABLED` in the 26.7.3 source
tree). RFC 8693 defines the required token-exchange grant, subject token/type,
requested token type and response `issued_token_type`: [RFC 8693
§2](https://www.rfc-editor.org/rfc/rfc8693.html#section-2).

## Applied closed profile

The implementation therefore fixes issuer, same-origin token/JWKS endpoints,
confidential requester identity, expected subject, one target audience and an
exact scope set in a human-installed profile. The agent selects only the opaque
profile ID. It cannot supply an endpoint, audience, scope, subject, requester,
auxiliary credential or token type.

The custodian sends the RFC 8693 form over TLS 1.3 without redirects. Success
requires an RS256/JWKS-verified Keycloak JWT with the installed issuer,
subject, singleton audience, requester `azp`, unexpired `exp`, and exact scope
set. Refresh and ID tokens are rejected. The emitted access token must differ
from both stored inputs; reflection of either input anywhere in the provider
response or verified claims is an integrity failure.

Keycloak does not promise that revoking the original access token revokes an
already issued access token. The local authority gate only prevents a new POST
when suspension/revocation linearizes first; the consumer remains responsible
for token B after delivery.
