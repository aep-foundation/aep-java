package foundation.aep.core;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum AgentStatus {
    ACTIVE("active"),
    PENDING("pending"),
    REJECTED("rejected"),
    SUSPENDED("suspended"),
    TERMINATED("terminated"),
    UNAVAILABLE("unavailable");

    private final String encodedValue;

    AgentStatus(String value) {
        this.encodedValue = value;
    }

    @JsonCreator
    public static AgentStatus fromValue(String value) {
        for (AgentStatus status : values()) {
            if (status.encodedValue.equals(value)) {
                return status;
            }
        }
        throw new IllegalArgumentException("Unknown AEP Agent status: " + value);
    }

    @JsonValue
    public String value() {
        return encodedValue;
    }
}
