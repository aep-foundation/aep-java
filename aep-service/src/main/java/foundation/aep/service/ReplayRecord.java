package foundation.aep.service;

import java.time.Instant;

public record ReplayRecord(String subject, String jwtId, Instant expiresAt) {}
