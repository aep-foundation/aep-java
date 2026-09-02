package foundation.aep.service;

import java.time.Instant;

public record RevokeContext(String agentDid, EnrollmentRecord enrollment, String grantType, Instant now) {}
