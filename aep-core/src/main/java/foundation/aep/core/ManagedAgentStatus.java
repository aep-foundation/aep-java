package foundation.aep.core;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum ManagedAgentStatus {
    ACTIVE("active"),
    REVOKED("revoked"),
    SUSPENDED("suspended"),
    TERMINATED("terminated");

    private final String encodedValue;

    ManagedAgentStatus(String value) {
        encodedValue = value;
    }

    @JsonCreator
    public static ManagedAgentStatus fromValue(String value) {
        for (ManagedAgentStatus status : values()) {
            if (status.encodedValue.equals(value)) return status;
        }
        throw new IllegalArgumentException("Unknown managed Agent status: " + value);
    }

    @JsonValue
    public String value() {
        return encodedValue;
    }
}
