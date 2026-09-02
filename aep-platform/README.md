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
