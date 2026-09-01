package foundation.aep.core;

import java.util.List;

public final class AepValidationException extends IllegalArgumentException {
    private static final long serialVersionUID = 1L;

    private final String invalidDocumentType;
    private final List<ValidationIssue> validationIssues;

    public AepValidationException(String documentType, List<ValidationIssue> issues) {
        this(documentType, issues, null);
    }

    public AepValidationException(String documentType, List<ValidationIssue> issues, Throwable cause) {
        super("Invalid AEP " + documentType, cause);
        this.invalidDocumentType = documentType;
        this.validationIssues = List.copyOf(issues);
    }

    public String documentType() {
        return invalidDocumentType;
    }

    public List<ValidationIssue> issues() {
        return validationIssues;
    }
}
