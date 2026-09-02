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

## Add a Grant Type

Register one handler for every Grant Type advertised by the Inspect document. A successful handler
returns the stable Service-wide credential identifier together with the concrete response object:

```java
GrantTypeDefinition apiKey = new GrantTypeDefinition(
    "api-key",
    grantTypeHandler);

AepService service = AepService.builder(document, assertionVerifier)
    .grantType(apiKey)
    .credentialAuthenticator("api-key", credentialAuthenticator)
    .build();
```

Concrete API-key, Basic, and OAuth Bearer credential profiles are separate integrations. Custom
handlers must implement issuance, presentation, expiry, and revocation according to their Grant
Type specification.
