package foundation.aep.platform;

public record PlatformIdempotencyResult<T>(State state, PlatformResponse<T> response) {
    public enum State {
        CREATED,
        REPLAYED,
        CONFLICT
    }

    public static <T> PlatformIdempotencyResult<T> created(PlatformResponse<T> response) {
        return new PlatformIdempotencyResult<>(State.CREATED, response);
    }

    public static <T> PlatformIdempotencyResult<T> replayed(PlatformResponse<T> response) {
        return new PlatformIdempotencyResult<>(State.REPLAYED, response);
    }

    public static <T> PlatformIdempotencyResult<T> conflict() {
        return new PlatformIdempotencyResult<>(State.CONFLICT, null);
    }
}
