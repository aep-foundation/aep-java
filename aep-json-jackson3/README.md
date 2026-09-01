# AEP JSON for Jackson 3

`aep-json-jackson3` connects `AepJson` to Jackson 3 while leaving the application's existing
Jackson configuration independent.

Add this module alongside a role module or `aep-core`:

```xml
<dependency>
  <groupId>foundation.aep</groupId>
  <artifactId>aep-json-jackson3</artifactId>
</dependency>
```

The provider is discovered automatically. Do not include `aep-json-jackson2` in the same runtime;
`AepJson` requires exactly one provider. See the [Core guide](../aep-core/README.md) for parsing and
validation examples and the root [installation guide](../README.md#installation) for BOM usage.
