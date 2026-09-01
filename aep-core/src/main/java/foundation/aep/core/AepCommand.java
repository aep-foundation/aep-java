package foundation.aep.core;

public enum AepCommand {
    INSPECT("inspect"),
    ENROLL("enroll"),
    GRANT("grant"),
    REVOKE("revoke"),
    STATUS("status");

    private final String encodedValue;

    AepCommand(String value) {
        this.encodedValue = value;
    }

    public String value() {
        return encodedValue;
    }
}
