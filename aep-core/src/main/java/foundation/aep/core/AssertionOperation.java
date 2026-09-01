package foundation.aep.core;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum AssertionOperation {
    AUTHENTICATE("authenticate"),
    ENROLL("enroll"),
    GRANT("grant"),
    REVOKE("revoke"),
    STATUS("status");

    private final String encodedValue;

    AssertionOperation(String value) {
        this.encodedValue = value;
    }

    @JsonCreator
    public static AssertionOperation fromValue(String value) {
        for (AssertionOperation operation : values()) {
            if (operation.encodedValue.equals(value)) {
                return operation;
            }
        }
        throw new IllegalArgumentException("Unknown AEP assertion operation: " + value);
    }

    @JsonValue
    public String value() {
        return encodedValue;
    }
}
