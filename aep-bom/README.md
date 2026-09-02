# AEP Bill of Materials

`aep-bom` manages compatible versions for the public AEP Java modules. It contains no runtime code
and does not add any dependency to an application. Importing it ensures that explicitly selected
AEP modules use one release version.

Every application that uses AEP JSON must explicitly depend on exactly one of
`aep-json-jackson2` or `aep-json-jackson3`. The BOM supplies that module's version after the
application selects it; the BOM does not select a Jackson generation or add Jackson itself.

See the root [installation guide](../README.md#installation) for Maven and Gradle usage and the
supported direct-version alternative.
