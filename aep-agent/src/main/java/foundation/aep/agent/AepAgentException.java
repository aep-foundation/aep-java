package foundation.aep.agent;

import foundation.aep.core.ProblemDetails;

public final class AepAgentException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final String errorCode;
    private final int responseStatus;
    private final transient ProblemDetails responseProblem;

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
        this(code, message, status, cause, null);
    }

    AepAgentException(ProblemDetails problem, int status) {
        this(problem.code(), problem.detail() == null ? problem.title() : problem.detail(), status, null, problem);
    }

    private AepAgentException(String code, String message, int status, Throwable cause, ProblemDetails problem) {
        super(message, cause);
        errorCode = code;
        responseStatus = status;
        responseProblem = problem;
    }

    public String code() {
        return errorCode;
    }

    public int status() {
        return responseStatus;
    }

    public ProblemDetails problem() {
        return responseProblem;
    }
}
