# AEP Agent

`aep-agent` owns Service inspection, enrollment, status, Grant and Revoke operations, credential
storage boundaries, protected-resource authentication, polling, and cancellation for Agents.

OAuth Bearer, API-key, and Basic Grant responses are parsed, stored, and presented without custom
credential handlers. Register an `AgentCredentialHandler` only for a custom Grant Type.

See the root [installation guide](../README.md#installation) for dependency coordinates.
