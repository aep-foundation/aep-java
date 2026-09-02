package foundation.aep.service;

import foundation.aep.core.InspectDocument;
import java.util.Objects;

public record StoredCredentialGrantType(
        String grantType,
        InspectDocument.GrantTypeConfig config,
        GrantTypeDefinition definition,
        CredentialAuthenticator authenticator) {
    public StoredCredentialGrantType {
        Objects.requireNonNull(grantType, "grantType");
        Objects.requireNonNull(definition, "definition");
        Objects.requireNonNull(authenticator, "authenticator");
        if (!grantType.equals(definition.grantType())) {
            throw new IllegalArgumentException("Stored credential Grant Type metadata must match its definition.");
        }
    }
}
