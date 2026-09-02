package foundation.aep.service;

public record CommandOptions(String clientAssertion, String idempotencyKey) {
    public static CommandOptions authenticated(String clientAssertion) {
        return new CommandOptions(clientAssertion, null);
    }

    public static CommandOptions idempotent(String clientAssertion, String idempotencyKey) {
        return new CommandOptions(clientAssertion, idempotencyKey);
    }
}
