package foundation.aep.service;

import foundation.aep.core.AgentStatus;
import java.util.List;

public record EnrollmentDecision(
        AgentStatus status,
        Boolean ownerActionRequired,
        List<String> verificationPending,
        List<String> requirementsPending,
        boolean updateExisting) {
    public EnrollmentDecision(
            AgentStatus status,
            Boolean ownerActionRequired,
            List<String> verificationPending,
            List<String> requirementsPending) {
        this(status, ownerActionRequired, verificationPending, requirementsPending, true);
    }

    public EnrollmentDecision {
        status = status == null ? AgentStatus.ACTIVE : status;
        if (verificationPending != null) {
            verificationPending = List.copyOf(verificationPending);
        }
        if (requirementsPending != null) {
            requirementsPending = List.copyOf(requirementsPending);
        }
        if (status != AgentStatus.ACTIVE && status != AgentStatus.PENDING && status != AgentStatus.REJECTED) {
            throw new IllegalArgumentException("Initial enrollment status must be active, pending, or rejected.");
        }
    }

    public static EnrollmentDecision active() {
        return new EnrollmentDecision(AgentStatus.ACTIVE, null, null, null);
    }

    public List<String> verificationPending() {
        return verificationPending == null ? null : List.copyOf(verificationPending);
    }

    public List<String> requirementsPending() {
        return requirementsPending == null ? null : List.copyOf(requirementsPending);
    }
}
