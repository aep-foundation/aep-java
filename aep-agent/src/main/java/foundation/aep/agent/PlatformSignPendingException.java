package foundation.aep.agent;

import java.util.Objects;

public final class PlatformSignPendingException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final transient PlatformPendingSign pendingSign;

    public PlatformSignPendingException(PlatformPendingSign value) {
        super("AEP Platform signing is pending.");
        pendingSign = Objects.requireNonNull(value, "pending");
    }

    public PlatformPendingSign pending() {
        return pendingSign;
    }
}
