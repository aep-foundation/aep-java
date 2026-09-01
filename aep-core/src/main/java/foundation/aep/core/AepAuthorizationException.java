package foundation.aep.core;

public final class AepAuthorizationException extends IllegalArgumentException {
    private static final long serialVersionUID = 1L;

    private final String errorCode;

    public AepAuthorizationException(String code, String message) {
        super(message);
        this.errorCode = code;
    }

    public String code() {
        return errorCode;
    }
}
