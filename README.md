# Agent Enrollment Protocol for Java

[![CI](https://github.com/aep-foundation/aep-java/actions/workflows/ci.yml/badge.svg)](https://github.com/aep-foundation/aep-java/actions/workflows/ci.yml)
[![Java](https://img.shields.io/badge/Java-17%2B-ED8B00?logo=openjdk&logoColor=white)](https://openjdk.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

Official Java software development kit for the
[Agent Enrollment Protocol](https://www.aep.foundation/), the open protocol for Agent enrollment,
Service-issued credentials, and authenticated Agent access.

## Modules

| Goal                                               | Module                                               |
| -------------------------------------------------- | ---------------------------------------------------- |
| Align compatible AEP dependency versions          | [`aep-bom`](./aep-bom/README.md)                     |
| Use protocol contracts and validation directly    | [`aep-core`](./aep-core/README.md)                   |
| Inspect, enroll with, and authenticate to Services | [`aep-agent`](./aep-agent/README.md)                 |
| Integrate enrollment into a Service                | [`aep-service`](./aep-service/README.md)             |
| Expose a Service with the JDK HTTP server          | [`aep-httpserver`](./aep-httpserver/README.md)       |
| Expose a Service with Jakarta Servlet              | [`aep-servlet`](./aep-servlet/README.md)             |
| Expose a Service with Spring Web MVC               | [`aep-spring-webmvc`](./aep-spring-webmvc/README.md) |
| Host managed Agent identities                      | [`aep-platform`](./aep-platform/README.md)           |
| Integrate with Jackson 2                           | [`aep-json-jackson2`](./aep-json-jackson2/README.md) |
| Integrate with Jackson 3                           | [`aep-json-jackson3`](./aep-json-jackson3/README.md) |

All artifacts use Maven group `foundation.aep`, require Java 17 or newer, and share one release
version. Role modules depend on Core. Shared Platform wire contracts belong to Core, while Agent
and Platform remain sibling modules. Framework integrations, persistence, and key custody stay
outside Core.

## Installation

Import `aep-bom` once to keep every AEP module on a compatible version:

```xml
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>foundation.aep</groupId>
      <artifactId>aep-bom</artifactId>
      <version>0.1.0</version>
      <type>pom</type>
      <scope>import</scope>
    </dependency>
  </dependencies>
</dependencyManagement>

<dependencies>
  <dependency>
    <groupId>foundation.aep</groupId>
    <artifactId>aep-agent</artifactId>
  </dependency>
  <dependency>
    <groupId>foundation.aep</groupId>
    <artifactId>aep-json-jackson2</artifactId>
  </dependency>
</dependencies>
```

Gradle can import the same BOM as a platform:

```kotlin
implementation(platform("foundation.aep:aep-bom:0.1.0"))
implementation("foundation.aep:aep-agent")
implementation("foundation.aep:aep-json-jackson2")
```

The BOM is optional. Applications that do not use dependency management can put the same version
on each AEP dependency directly:

```xml
<dependency>
  <groupId>foundation.aep</groupId>
  <artifactId>aep-agent</artifactId>
  <version>0.1.0</version>
</dependency>
```

The BOM aligns AEP module versions; it does not add dependencies to an application. Select exactly
one JSON provider explicitly:

- `aep-json-jackson2` for an application using Jackson 2
- `aep-json-jackson3` for an application using Jackson 3

`AepJson` fails during initialization when it finds zero providers or more than one provider. The
framework adapter does not choose a JSON provider for the application.

`aep-spring-webmvc` supports Spring Framework 6 and 7 from one artifact. It exchanges raw bytes
with Spring and delegates AEP serialization to the selected `AepJson` provider, keeping the
framework generation and Jackson generation as explicit application choices.

## Development

The Maven Wrapper provides the complete repository gate:

```sh
./mvnw verify
./scripts/verify-consumer.sh
```

Format Java sources with:

```sh
./mvnw spotless:apply
```

See [DEVELOPMENT.md](./DEVELOPMENT.md) for repository conventions and
[`aep-specs`](https://github.com/aep-foundation/aep-specs) for the normative drafts, schemas,
registries, examples, and test vectors.

## Security

See [SECURITY.md](./SECURITY.md) for vulnerability reporting.

## License

MIT.
