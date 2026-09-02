package foundation.aep.service;

import foundation.aep.core.AssertionOperation;
import java.time.Clock;
import java.time.Duration;
import java.util.List;

public record AssertionVerificationContext(
        String serviceDid,
        AssertionOperation operation,
        String resource,
        String idempotencyKey,
        List<String> signingAlgorithms,
        Clock clock,
        Duration clockSkew,
        boolean allowInsecureLoopback) {
    public AssertionVerificationContext {
        signingAlgorithms = List.copyOf(signingAlgorithms);
    }
}
