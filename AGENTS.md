# AGENTS.md

## Repository

This repository contains the official Java modules for AEP:

- `aep-bom`: compatible versions for the public modules.
- `aep-core`: transport-independent contracts and validation.
- `aep-json-jackson2` and `aep-json-jackson3`: optional JSON providers.
- `aep-agent`: Agent enrollment, credentials, and protected-resource authentication.
- `aep-service`: Service enrollment, credential issuance, and request authentication.
- `aep-platform`: hosted Agent identity management and delegated signing.

The normative protocol is maintained in `aep-foundation/aep-specs`. Check that source before
implementing or changing wire behavior. AEP Node is a reference implementation, not specification
authority.

## Verification

Run `./mvnw verify` and `./scripts/verify-consumer.sh` before merging. Public APIs must be backed by
tests and authoritative protocol behavior.

## Conventions

- Support Java 17 and newer; continuous integration covers Java 17, 21, and 25.
- Use the Java standard library when it is sufficient and justify every additional dependency.
- Return typed failures rather than logging from library code.
- Keep shared Platform wire contracts in Core; Agent and Platform are sibling role modules.
- Keep persistence, key custody, authorization, and framework behavior behind explicit interfaces.
- Keep public APIs small, immutable where practical, and backed by tests.
- Use records for small immutable values and builders for complex documents and configuration.
- Do not expose long positional constructors or `Optional` in serialized models.
- Describe current behavior; do not leave speculative or historical comments.
- Do not introduce framework dependencies into `aep-core`.
- Keep conformance tooling outside production runtime dependencies.
