package foundation.aep.service;

import java.util.Objects;

public record GrantTypeDefinition(String grantType, GrantTypeHandler handler) {
    public GrantTypeDefinition {
        if (grantType == null || grantType.isBlank()) {
            throw new IllegalArgumentException("Grant Type must not be blank.");
        }
        handler = Objects.requireNonNull(handler, "handler");
    }
}
