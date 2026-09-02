package foundation.aep.agent;

public final class AepAgentException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final String errorCode;
    private final int responseStatus;

    public AepAgentException(String code, String message) {
        this(code, message, 0, null);
    }

    public AepAgentException(String code, String message, Throwable cause) {
        this(code, message, 0, cause);
    }

    public AepAgentException(String code, String message, int status) {
        this(code, message, status, null);
    }

    private AepAgentException(String code, String message, int status, Throwable cause) {
        super(message, cause);
        errorCode = code;
        responseStatus = status;
    }

    public String code() {
        return errorCode;
    }

    public int status() {
        return responseStatus;
    }
}
