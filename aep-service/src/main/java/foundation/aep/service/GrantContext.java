package foundation.aep.service;

import java.time.Instant;

public record GrantContext(String agentDid, EnrollmentRecord enrollment, String grantType, Instant now) {}
