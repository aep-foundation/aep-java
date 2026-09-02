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
StatusResponse active = service.waitForActive(
    Duration.ofSeconds(2), Duration.ofMinutes(2)).join();

AgentGrantResult grant = service.grant("api-key", List.of("catalog:read")).join();
```

`enroll` rejects locally when required advertised claims are missing. `waitForActive` is intended
for a Service that returns a pending enrollment; an immediately active enrollment can proceed
directly to Grant.

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

See the runnable [Agent and Service example](../examples/README.md#agent-and-service) for a complete
JDK `HttpClient` transport and lifecycle flow.
