package foundation.aep.core;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum AuthorizationScheme {
    AEP("AEP"),
    BEARER("Bearer"),
    BASIC("Basic");

    private final String encodedValue;

    AuthorizationScheme(String value) {
        this.encodedValue = value;
    }

    @JsonCreator
    public static AuthorizationScheme fromValue(String value) {
        for (AuthorizationScheme scheme : values()) {
            if (scheme.encodedValue.equals(value)) {
                return scheme;
            }
        }
        throw new IllegalArgumentException("Unknown AEP authorization scheme: " + value);
    }

    @JsonValue
    public String value() {
        return encodedValue;
    }
}
