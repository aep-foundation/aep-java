package foundation.aep.core;

import com.fasterxml.jackson.annotation.JsonProperty;

public record ClientAssertionClaims(
        @JsonProperty("iss") String issuer,
        @JsonProperty("sub") String subject,
        @JsonProperty("aud") String audience,
        @JsonProperty("op") AssertionOperation operation,
        @JsonProperty("iat") long issuedAt,
        @JsonProperty("exp") long expiresAt,
        @JsonProperty("jti") String jwtId,
        String resource) {}
