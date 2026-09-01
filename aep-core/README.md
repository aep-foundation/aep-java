# AEP Core

`aep-core` owns transport-independent protocol contracts, bounded native validation, identity and
assertion primitives, errors, limits, and shared Agent-to-Platform wire models.

## Add the dependency

Import the [AEP BOM](../README.md#installation), then add Core and exactly one JSON adapter:

```xml
<dependency>
  <groupId>foundation.aep</groupId>
  <artifactId>aep-core</artifactId>
</dependency>
<dependency>
  <groupId>foundation.aep</groupId>
  <artifactId>aep-json-jackson2</artifactId>
</dependency>
```

Use `aep-json-jackson3` instead when the application runs Jackson 3.

## Parse and validate protocol JSON

`AepJson` decodes a wire document and applies the bounded AEP validation associated with that
document. It accepts additive fields where the protocol permits them and rejects invalid known
fields.

```java
import foundation.aep.core.AepJson;
import foundation.aep.core.InspectDocument;

InspectDocument document = AepJson.parseInspectDocument(responseBody);
String serviceDid = document.service().did();
```

The same entry point handles claim values, Enroll, Status, Grant, Revoke, Problem Details,
client-assertion claims, protected-resource authorization, and the OpenAPI AEP extension. Invalid
input throws `AepValidationException` with structured `ValidationIssue` values.

Dispatch a built-in Grant response using the Grant Type selected for the request:

```java
GrantResponses.BuiltIn credential = AepJson.parseBuiltInGrantResponse(grantType, responseBody);
```

`AepJson.write` applies AEP's canonical omission rules for lifecycle metadata.

Use `AepValidation` when the application already has a typed value:

```java
List<ValidationIssue> issues = AepValidation.enrollRequest(request);
```

## Compose HTTP paths and authorization

`AepHttp` composes command paths from `http.endpoint_base` and renders or parses the standard and
dedicated authorization carriers:

```java
URI grantUri = AepHttp.commandUri(serviceOrigin, AepCommand.GRANT, document.http().endpointBase());

Map<String, String> headers = AepHttp.renderAuthorization(
    new ProtectedResourceAuthorization(
        AuthorizationCarrier.DEDICATED,
        AuthorizationScheme.AEP,
        clientAssertion));
```

`AepHttpTransport` is the asynchronous transport boundary shared by the role modules. Core does
not select an HTTP client or framework.

## Work with identity and claims

- `DidWeb.documentUri` resolves a `did:web` identifier to its DID document URI.
- `DidWeb.bindsOrigin` checks the Service-origin binding required by AEP.
- `ClientAssertions` signs and verifies ES256 and EdDSA client assertions.
- `ClaimSupport` evaluates advertised claim requirements and identifies missing required values.

The normative contract is maintained in
[`aep-specs`](https://github.com/aep-foundation/aep-specs). Core performs focused native checks; it
does not embed a general JSON Schema engine.
