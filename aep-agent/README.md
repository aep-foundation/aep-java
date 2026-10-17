# AEP Agent

`aep-agent` owns Service inspection, enrollment, status, Grant and Revoke operations, credential
storage boundaries, protected-resource authentication, polling, and cancellation for Agents.

OAuth Bearer, API-key, and Basic Grant responses are parsed, stored, and presented without custom
credential handlers. Register an `AgentCredentialHandler` only for a custom Grant Type.

See the root [installation guide](../README.md#installation) for dependency coordinates.

## Configure an Agent

Supply an HTTP transport and an identity provider. The transport boundary is asynchronous and can
adapt the HTTP client already used by the application. The identity provider returns a
Service-scoped Agent identity whose signer receives the complete client-assertion claims.
The signer must use an algorithm advertised by the Service. Configure transports to return
redirect responses without following them automatically, so the SDK can enforce origin checks
before credentials or assertions are sent elsewhere.

```java
AepAgent agent = AepAgent.builder()
    .inspectTransport(httpTransport)
    .commandTransport(httpTransport)
    .identityProvider((serviceOrigin, serviceDid) ->
        identityStore.getOrCreate(serviceOrigin, serviceDid))
    .credentialStore(credentialStore)
    .build();

AepServiceSession service = agent.service(URI.create("https://service.example"));
```

Production identity providers should scope identities by Service, protect signing keys, and return
the same identity for repeated calls. Production credential stores should encrypt credentials at
rest and make replacement, expiry, and revocation atomic.

Implement `AgentCredentialStore.find(serviceDid, grantType, now)` to select a credential whose
`expiresAt` is later than the supplied Agent time. An expired credential must not hide another
usable credential of the same type. A custom credential with no expiry can remain selectable.
This local selection does not authorize access: the Service validates the credential using its own
clock. Changing the Agent's clock cannot extend a credential's lifetime at the Service.

Custom Inspect caches must preserve `AgentInspectCache.Entry.cacheHeaders` alongside the document
and validators, so a `304 Not Modified` response retains the cached freshness policy.

### Upgrading application storage from 0.1.1

Recompile custom adapters against the complete, matching set of AEP modules selected by the BOM.
`AgentCredentialStore.find(serviceDid, grantType)` must become
`find(serviceDid, grantType, Instant now)`. The compiler requires this update. Select an unexpired
credential using the supplied time, rather than returning an expired record when another usable
credential exists. Do not reuse an adapter binary compiled against the old interface.

Credential records, Service enrollment records, and completed command-idempotency responses do not
require a hash conversion. Keep them: deleting credentials forces reauthentication, and deleting
completed responses can repeat operations. The `find` interface change concerns selection, not a
change to the stored credential representation.

If your application persists Inspect-cache entries, update its serializer to preserve `cacheHeaders`
and invalidate only entries written without that metadata. The five-argument `Entry` constructor
still compiles and supplies an empty header map, but cannot reconstruct response headers that were
not stored. A cache miss lets the Agent fetch the document and its headers again. Keep Inspect-cache
data separate from identity, credential, enrollment, and command-idempotency storage; those records
must not be cleared as part of cache invalidation.

## Use a hosted identity Platform

`PlatformIdentityProvider` implements the Agent identity boundary against an AEP Platform. It
discovers the Platform anonymously, recovers an active identity for the Service DID or provisions
one, and delegates client-assertion signing without exposing private key material:

```java
PlatformIdentityProvider identities = PlatformIdentityProvider
    .builder(URI.create("https://platform.example"))
    .transport(httpTransport)
    .authenticationHeaders(() -> platformAccessToken()
        .thenApply(token -> Map.of("Authorization", List.of("Bearer " + token))))
    .build();

AepAgent agent = AepAgent.builder()
    .inspectTransport(httpTransport)
    .commandTransport(httpTransport)
    .identityProvider(identities)
    .build();
```

Authentication headers are resolved for every private Platform request so an application can
refresh an expiring access token. They are never sent to Platform Discovery. The provider honors
Discovery freshness and validators, recovers identities through the advertised list endpoint, and
uses a distinct idempotency key for provisioning and each Sign stage.

A Platform can return a pending Sign response when Owner approval or custody work is required. By
default, the signing stage fails with `PlatformSignPendingException`, which exposes the pending
context and retry interval. Configure `pendingSignResolver` to wait or obtain approval and return
the opaque Platform context for the next Sign stage. Configure `platformContext` when the Platform
requires initial authorization or custody input. Neither context is copied into assertion claims.

## Enroll and request a credential

Inspect before presenting claims so the application can obtain the Service's advertised required,
preferred, and optional claim names:

```java
AgentInspection inspection = service.inspect().join();

ClaimValues claims = ClaimValues.builder()
    .contactEmail("agent@example.com")
    .personFirstName("Avery")
    .personLastName("Agent")
    .build();

EnrollResponse enrolled = service.enroll(claims).join();
if (enrolled.status() == AgentStatus.PENDING) {
    service.waitForActive(Duration.ofSeconds(2), Duration.ofMinutes(2)).join();
}

AgentGrantResult grant = service.grant("api-key", List.of("catalog:read")).join();
```

`enroll` rejects locally when required advertised claims are missing. `waitForActive` is intended
for a Service that returns a pending enrollment; an immediately active enrollment can proceed
directly to Grant.

Polling timeout and cancellation stop the returned wait and prevent further polls. They do not
guarantee cancellation of an HTTP request already running in an application-supplied transport;
configure request timeouts on that transport as well.

Built-in credential handlers parse and store OAuth Bearer, API-key, and Basic responses. A custom
Grant Type remains available through `AgentCredentialHandler`.

## Authenticate and revoke

Authentication selects the first advertised method that the Agent can satisfy. The returned
headers are scoped to the requested Service origin and resource:

```java
URI resource = URI.create("https://service.example/catalog");
AgentAuthentication authentication = service.authenticate(resource).join();

authentication.headers().forEach((name, values) ->
    values.forEach(value -> request.header(name, value)));

service.revoke(RevokeRequest.credential("api-key", credentialId)).join();
```

Do not forward the returned headers to another origin. The Agent refuses cross-origin credential
presentation, command redirects, cross-origin Inspect redirects, oversized responses, and invalid
Service DID bindings.

The application sends protected-resource requests and handles their redirects; `authenticate`
only returns headers. For a same-origin redirect, discard the previous authentication headers and
call `authenticate` for the target URL. When JWT authentication is selected, this creates a fresh
assertion bound to that URL. For a cross-origin
redirect, remove all Service authentication headers, including any API-key header, and restart
anonymously. These forwarding decisions belong to the application's HTTP client, not this SDK.

See the runnable [Agent and Service example](../examples/README.md#agent-and-service) for a complete
JDK `HttpClient` transport and lifecycle flow.
