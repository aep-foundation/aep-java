# AEP Java Examples

This reactor module contains runnable Agent, Service, Platform, claims, and credential examples.
It is built and executed during repository verification but is not published to Maven Central.

Run every example from the repository root:

```sh
./mvnw -pl examples -am verify
```

Run one example while iterating:

```sh
./mvnw -pl examples -am compile exec:java \
  -Dexec.mainClass=foundation.aep.examples.AgentServiceExample

./mvnw -pl examples -am compile exec:java \
  -Dexec.mainClass=foundation.aep.examples.PlatformExample
```

## Agent and Service

[`AgentServiceExample.java`](./src/main/java/foundation/aep/examples/AgentServiceExample.java)
starts an AEP Service on a random loopback port and drives it with an AEP Agent. It demonstrates:

1. an Inspect document with a configurable `/aep/` endpoint base;
2. a real ES256 Agent assertion and Service-side public-key resolution;
3. required name, email, and postal-address claims;
4. enrollment and active status;
5. an API-key Grant stored by both roles;
6. authentication to a protected application resource; and
7. per-credential revocation and rejection of the revoked credential.

[`JdkAepTransport.java`](./src/main/java/foundation/aep/examples/JdkAepTransport.java) adapts the JDK
`HttpClient` to the Agent's `AepHttpTransport` boundary. The Service uses the published
`aep-httpserver` adapter rather than an example-only HTTP dispatcher.

Expected output identifies each completed step without printing the API key or signed assertion:

```text
Inspected did:web:127.0.0.1%3A...
Enrollment status: active
Issued API-key credential: ...
Protected profile: 200 AEP-authenticated profile
Revoked credential: ...
```

Loopback HTTP is explicitly enabled for this local program. A deployed Agent and Service should
use HTTPS, durable stores, protected key custody, and an application-owned enrollment policy.

## Platform

[`PlatformExample.java`](./src/main/java/foundation/aep/examples/PlatformExample.java) constructs a
transport-independent AEP Platform with in-memory identity state and application-owned ES256 keys.
It provisions one Service-scoped Agent identity, signs an Enroll assertion, and verifies the result
with the identity's public key.

Expected output:

```text
Provisioned Agent DID: did:web:platform.example:agents:...
Signed assertion operation: enroll
```

The example authorizer and Service DID resolver accept every request so the lifecycle is easy to
run. A production Platform must authenticate callers, enforce tenant authorization, resolve
Service DIDs, persist identities and idempotency records, and protect private keys.

## Dependency setup

The repository examples use reactor dependencies. External Maven and Gradle applications should
import `foundation.aep:aep-bom`, explicitly add the required role modules, and select exactly one
JSON provider. The root [installation guide](../README.md#installation) contains complete Maven and
Gradle snippets and explains Jackson 2, Jackson 3, and Spring compatibility.
