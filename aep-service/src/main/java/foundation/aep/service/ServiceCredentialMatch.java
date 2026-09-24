package foundation.aep.service;

import java.time.Instant;
import java.util.List;

public record ServiceCredentialMatch(
        String agentDid, String credentialId, Instant expiresAt, String grantType, List<String> scopes) {
    public ServiceCredentialMatch {
        // A credential store is a caller-supplied extension point. The handler guards against a
        // malformed match, but it reads expiresAt before it can report one, so a null here surfaced
        // as a NullPointerException instead of the intended rejection.
        java.util.Objects.requireNonNull(agentDid, "agentDid");
        java.util.Objects.requireNonNull(credentialId, "credentialId");
        java.util.Objects.requireNonNull(expiresAt, "expiresAt");
        java.util.Objects.requireNonNull(grantType, "grantType");
        scopes = scopes == null ? List.of() : List.copyOf(scopes);
    }
}
