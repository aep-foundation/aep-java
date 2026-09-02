# AEP Service

`aep-service` owns command dispatch, enrollment policy, claims, credential issuance and revocation,
request authentication, replay protection, and persistence boundaries for Services.

See the root [installation guide](../README.md#installation) for dependency coordinates.

## Configure a Service

Build the Inspect document with `aep-core`, then supply the application-owned assertion verifier
and policy boundaries:

```java
InspectDocument document = InspectDocument.builder()
    .version(Aep.VERSION)
    .bindings(new InspectDocument.Bindings(List.of("http")))
    .claims(new InspectDocument.Claims(List.of("contact.email"), List.of(), List.of()))
    .commands(new InspectDocument.Commands(
        List.of("enroll", "inspect", "status"), List.of(), Map.of()))
    .core(new InspectDocument.Core(Aep.REQUIRED_SIGNING_ALGORITHMS))
    .http(new InspectDocument.Http("/aep", null))
    .identity(new InspectDocument.Identity(List.of("did:web")))
    .service(new InspectDocument.Service("did:web:service.example"))
    .build();

AepService service = AepService.builder(document, assertionVerifier)
    .enrollmentPolicy((request, now) -> CompletableFuture.completedFuture(
        EnrollmentDecision.active()))
    .enrollmentStore(enrollmentStore)
    .replayStore(replayStore)
    .idempotencyStore(idempotencyStore)
    .build();
```

Use `ClientAssertionVerifier.withKeyResolver(...)` when the application resolves Agent verification
keys itself. The wrapper performs the signed JWT, audience, operation, resource, time-window, and
key-identifier verification after the resolver returns the public key. A custom verifier is suitable
for a managed signing Platform only when it provides the same verification guarantees.

The default stores are process-local and intended for development. Production Services should
provide durable `EnrollmentStore` and `IdempotencyStore` implementations and a replay store whose
consume operation is atomic across every Service instance.

## Dispatch commands

Framework adapters parse the HTTP body into `aep-core` contracts and pass the client assertion and
idempotency key separately:

```java
ServiceResponse<EnrollResponse> response = service.enroll(
        enrollRequest,
        CommandOptions.idempotent(clientAssertion, idempotencyKey))
    .toCompletableFuture()
    .join();
```

`ServiceResponse` contains the HTTP status, media type, response body or Problem Details, and
response headers. The HTTP adapter module maps that framework-neutral result onto a server
framework.

## Add a credential profile

Use a shared credential store with one stored definition for every built-in Grant Type advertised by
the Inspect document:

```java
ServiceCredentialStore credentialStore = ServiceCredentialStore.inMemory();
InspectDocument.GrantTypeConfig apiKeyConfig =
    document.commands().grantTypesConfig().get(Aep.GRANT_TYPE_API_KEY);
StoredCredentialGrantType apiKey = StoredCredentialGrantTypes.apiKey(
    apiKeyConfig,
    (request, context) -> CompletableFuture.completedFuture(issueApiKey(context)),
    credentialStore);

AepService service = AepService.builder(document, assertionVerifier)
    .storedCredentialGrantType(apiKey)
    .build();
```

The included in-memory store retains one-way secret verifiers and is intended for development.
Production stores implement `ServiceCredentialStore` with durable, atomic identifier uniqueness,
authentication, expiry, and revocation. Custom Grant Types continue to use `GrantTypeDefinition`
and `CredentialAuthenticator` directly.
