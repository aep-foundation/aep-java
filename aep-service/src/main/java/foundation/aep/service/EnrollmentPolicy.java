package foundation.aep.service;

import foundation.aep.core.EnrollRequest;
import java.time.Instant;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

@FunctionalInterface
public interface EnrollmentPolicy {
    CompletionStage<EnrollmentDecision> decide(EnrollRequest request, Instant now);

    static EnrollmentPolicy active() {
        return (request, now) -> CompletableFuture.completedFuture(EnrollmentDecision.active());
    }
}
