# Development

## Requirements

- Java 17 or newer.
- Gradle 9.5.1 for the Gradle BOM consumer check.
- No system Maven installation; use the checked-in Maven Wrapper.

## Verification

Run the complete repository gate before merging:

```sh
./mvnw verify
./scripts/verify-consumer.sh
./scripts/verify-gradle-consumer.sh
```

The Maven gate compiles all modules, runs tests, enforces dependency convergence and formatting,
and runs Checkstyle, PMD, copy-paste detection, SpotBugs, and JaCoCo reporting. The consumer check
installs the reactor into an isolated temporary repository and proves that a project can import
`aep-bom`, omit versions from its AEP module dependencies, and execute the public JSON API with
either Jackson 2 or Jackson 3. The Gradle check proves the same combinations through Gradle's
platform support.

Format Java sources with:

```sh
./mvnw spotless:apply
```

Run the bidirectional Java and Node.js interoperability flow with adjacent repository checkouts:

```sh
AEP_NODE_DIR=../aep-node make interoperability
```

The flow runs the Java Agent against the Node.js Service and Platform, then the Node.js Agent
against the Java Service and Platform. Its report is written under `.interop/reports/`.

## Module boundaries

`aep-core` owns transport-independent wire contracts, validation, identity and assertion
primitives, and shared Agent-to-Platform HTTP models. `aep-agent`, `aep-service`, and `aep-platform`
are sibling role modules. The role modules do not depend on one another. The Jackson providers
depend only on Core and their matching Jackson major version.

Production validation is bounded native Java behavior. Shared conformance adapters and reports are
development and continuous-integration tooling; they are not runtime dependencies.

The normative protocol is maintained in `aep-foundation/aep-specs`. Confirm draft, schema,
registry, and vector behavior there before implementing or changing it in Java. Use AEP Node and
the other official SDKs as implementation evidence after confirming the specification contract.

## Versions

All public modules use one lockstep semantic version. `aep-bom` exposes those compatible module
versions to Maven and Gradle consumers without requiring them to inherit the reactor parent.
Examples and conformance tooling remain repository-only modules.

## Releases

The manual `Release` workflow publishes these artifacts to Maven Central:

- `aep-java` parent POM and `aep-bom`;
- `aep-core`, `aep-json-jackson2`, and `aep-json-jackson3`;
- `aep-agent`, `aep-service`, and `aep-platform`;
- `aep-httpserver`, `aep-servlet`, and `aep-spring-webmvc`.

The `examples` and `aep-conformance` modules are excluded from publication. A release requires a
stable semantic version on `main` and these repository Actions secrets:

- `CENTRAL_USERNAME`
- `CENTRAL_PASSWORD`
- `MAVEN_GPG_PRIVATE_KEY`
- `MAVEN_GPG_PASSPHRASE`

Before publishing, the workflow runs the repository gates, Spring Framework 7 verification, shared
conformance, Node.js interoperability, Maven and Gradle BOM consumers, and release artifact
inspection. It publishes and attests the signed artifacts, waits for Maven Central, verifies fresh
Maven and Gradle consumers against Central, creates the matching `vX.Y.Z` tag, and publishes the
GitHub release with its conformance and interoperability reports.

Inspect the release profile locally without uploading anything:

```sh
./scripts/verify-release-artifacts.sh
```
