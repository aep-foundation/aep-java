package foundation.aep.service;

import java.time.Instant;
import java.util.List;

public record ServiceCredentialMatch(
        String agentDid, String credentialId, Instant expiresAt, String grantType, List<String> scopes) {
    public ServiceCredentialMatch {
        scopes = scopes == null ? List.of() : List.copyOf(scopes);
    }
}
