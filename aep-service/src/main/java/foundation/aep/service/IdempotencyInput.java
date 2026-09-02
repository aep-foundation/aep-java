package foundation.aep.service;

public record IdempotencyInput(String agentDid, String idempotencyKey, String command, String requestHash) {}
