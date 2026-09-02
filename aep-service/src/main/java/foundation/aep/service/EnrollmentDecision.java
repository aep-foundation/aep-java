package foundation.aep.service;

import foundation.aep.core.AgentStatus;
import java.util.List;

public record EnrollmentDecision(
        AgentStatus status,
        boolean ownerActionRequired,
        List<String> verificationPending,
        List<String> requirementsPending) {
    public EnrollmentDecision {
        status = status == null ? AgentStatus.ACTIVE : status;
        verificationPending = verificationPending == null ? List.of() : List.copyOf(verificationPending);
        requirementsPending = requirementsPending == null ? List.of() : List.copyOf(requirementsPending);
        if (status != AgentStatus.ACTIVE && status != AgentStatus.PENDING && status != AgentStatus.REJECTED) {
            throw new IllegalArgumentException("Initial enrollment status must be active, pending, or rejected.");
        }
    }

    public static EnrollmentDecision active() {
        return new EnrollmentDecision(AgentStatus.ACTIVE, false, List.of(), List.of());
    }
}
