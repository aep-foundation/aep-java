package foundation.aep.core;

import java.io.Serializable;

public record ValidationIssue(String path, String message) implements Serializable {
    private static final long serialVersionUID = 1L;
}
