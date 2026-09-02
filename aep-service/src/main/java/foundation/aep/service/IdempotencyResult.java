package foundation.aep.service;

public record IdempotencyResult<T>(State state, ServiceResponse<T> response) {
    public enum State {
        CREATED,
        REPLAYED,
        CONFLICT
    }

    public static <T> IdempotencyResult<T> created(ServiceResponse<T> response) {
        return new IdempotencyResult<>(State.CREATED, response);
    }

    public static <T> IdempotencyResult<T> replayed(ServiceResponse<T> response) {
        return new IdempotencyResult<>(State.REPLAYED, response);
    }

    public static <T> IdempotencyResult<T> conflict() {
        return new IdempotencyResult<>(State.CONFLICT, null);
    }
}
