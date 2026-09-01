# AEP JSON for Jackson 2

`aep-json-jackson2` connects `AepJson` to Jackson 2 while leaving the application's existing
Jackson configuration independent.

Add this module alongside a role module or `aep-core`:

```xml
<dependency>
  <groupId>foundation.aep</groupId>
  <artifactId>aep-json-jackson2</artifactId>
</dependency>
```

The provider is discovered automatically. Do not include `aep-json-jackson3` in the same runtime;
`AepJson` requires exactly one provider. See the [Core guide](../aep-core/README.md) for parsing and
validation examples and the root [installation guide](../README.md#installation) for BOM usage.
