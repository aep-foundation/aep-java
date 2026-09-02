package foundation.aep.platform;

public record PlatformIdempotencyInput(
        String principal, String idempotencyKey, PlatformIdempotentOperation operation, String requestHash) {}
