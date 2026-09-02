package foundation.aep.service;

import java.util.List;

public record AuthenticatedPrincipal(
        String agentDid,
        String authenticationMethod,
        String credentialId,
        String grantType,
        List<String> scopes,
        Kind kind) {
    public AuthenticatedPrincipal {
        scopes = scopes == null ? List.of() : List.copyOf(scopes);
    }

    public enum Kind {
        AEP_JWT,
        SESSION_CREDENTIAL
    }
}
