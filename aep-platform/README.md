# AEP Platform

`aep-platform` owns hosted Agent identity provisioning, delegated signing, lifecycle management,
identity listing, DID document hosting, authorization, and persistence boundaries.

Applications supply authorization, Service DID resolution, durable identity and idempotency
stores, and production key custody. The HTTP integration must authenticate Platform callers,
construct `PlatformRequestContext`, rate-limit state-changing endpoints, and pass the
`Idempotency-Key` header to the context. Production `PlatformKeyStore` implementations must audit
delegated signing without exposing private key material.

The built-in stores are concurrency-safe development defaults. They retain state only in memory
and are not production persistence. Custom identity identifier suppliers must produce opaque,
non-correlatable values that do not encode Agent, Owner, tenant, account, or Service information.

See the root [installation guide](../README.md#installation) for dependency coordinates.

## Configure a Platform

Construct the discovery document, then provide application boundaries for caller authorization,
key custody, and Service DID resolution:

```java
AepPlatform platform = AepPlatform.builder(
        discoveryDocument,
        "platform.example",
        platformAuthorizer,
        platformKeyStore,
        serviceDidResolver)
    .identityStore(identityStore)
    .idempotencyStore(idempotencyStore)
    .replayStore(replayStore)
    .build();
```

The `didHost` argument is the host used to create managed `did:web` Agent identities. The
discovery document's endpoint paths and DID URL template must describe the HTTP API exposed by the
application; `aep-platform` itself is transport independent.

## Provision and sign

Every private operation receives an authenticated `PlatformRequestContext`. Provisioning is
idempotent for a caller and Service pair. Signing creates an AEP client assertion bound to the
requested Service and operation:

```java
PlatformRequestContext provisionContext =
    new PlatformRequestContext(principal, idempotencyKey);
PlatformAgentIdentity identity = platform.provision(
        new PlatformProvisionRequest(serviceDid), provisionContext)
    .toCompletableFuture()
    .join()
    .body();

PlatformSignRequest request = new PlatformSignRequest(
    jwtId, "300", AssertionOperation.ENROLL, platformContext, null, serviceDid);
PlatformSignResponses.Response response = platform.sign(
        identity.agentIdentityId(), request, signContext)
    .toCompletableFuture()
    .join()
    .body();
```

An application may return a pending signing response through `PlatformSignHandler` when signing
requires an approval. Hosted verification is optional and must match the discovery document. The
Platform applies lifecycle state to signing and DID document availability.

See the runnable [Platform example](../examples/README.md#platform) for ephemeral key custody,
identity provisioning, signing, and independent signature verification.
