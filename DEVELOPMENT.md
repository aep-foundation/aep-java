# Development

## Requirements

- Java 17 or newer.
- No system Maven installation; use the checked-in Maven Wrapper.

## Verification

Run the complete repository gate before merging:

```sh
./mvnw verify
./scripts/verify-consumer.sh
```

The Maven gate compiles all modules, runs tests, enforces dependency convergence and formatting,
and runs Checkstyle, PMD, copy-paste detection, SpotBugs, and JaCoCo reporting. The consumer check
installs the reactor into an isolated temporary repository and proves that a project can import
`aep-bom`, omit versions from its AEP module dependencies, and execute the public JSON API with
either Jackson 2 or Jackson 3.

Format Java sources with:

```sh
./mvnw spotless:apply
```

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
