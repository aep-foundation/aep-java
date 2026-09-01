package foundation.aep.core;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum AuthorizationCarrier {
    STANDARD("Authorization"),
    DEDICATED("AEP-Authorization");

    private final String encodedValue;

    AuthorizationCarrier(String value) {
        this.encodedValue = value;
    }

    @JsonCreator
    public static AuthorizationCarrier fromValue(String value) {
        for (AuthorizationCarrier carrier : values()) {
            if (carrier.encodedValue.equals(value)) {
                return carrier;
            }
        }
        throw new IllegalArgumentException("Unknown AEP authorization carrier: " + value);
    }

    @JsonValue
    public String value() {
        return encodedValue;
    }
}
