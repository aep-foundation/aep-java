package foundation.aep.platform;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Supplier;

@FunctionalInterface
public interface PlatformIdempotencyStore {
    <T> CompletionStage<PlatformIdempotencyResult<T>> execute(
            PlatformIdempotencyInput input, Supplier<CompletionStage<PlatformResponse<T>>> operation);

    static PlatformIdempotencyStore inMemory(Clock clock) {
        return new InMemoryPlatformIdempotencyStore(clock);
    }

    final class InMemoryPlatformIdempotencyStore implements PlatformIdempotencyStore {
        private static final Duration RETENTION = Duration.ofHours(1);
        private final Clock clock;
        private final Map<String, Entry> entries = new LinkedHashMap<>();
        private final Map<String, Pending> pending = new LinkedHashMap<>();

        InMemoryPlatformIdempotencyStore(Clock clock) {
            this.clock = java.util.Objects.requireNonNull(clock, "clock");
        }

        @Override
        public <T> CompletionStage<PlatformIdempotencyResult<T>> execute(
                PlatformIdempotencyInput input, Supplier<CompletionStage<PlatformResponse<T>>> operation) {
            requireInput(input);
            java.util.Objects.requireNonNull(operation, "operation");
            String key = input.principal() + '\0' + input.idempotencyKey();
            CompletableFuture<PlatformResponse<?>> shared;
            boolean created;
            synchronized (this) {
                expire();
                Entry existing = entries.get(key);
                if (existing != null) {
                    if (!sameRequest(existing.input, input)) {
                        return CompletableFuture.completedFuture(PlatformIdempotencyResult.conflict());
                    }
                    return CompletableFuture.completedFuture(
                            PlatformIdempotencyResult.replayed(cast(existing.response)));
                }
                Pending inFlight = pending.get(key);
                if (inFlight != null && !sameRequest(inFlight.input, input)) {
                    return CompletableFuture.completedFuture(PlatformIdempotencyResult.conflict());
                }
                created = inFlight == null;
                if (created) {
                    shared = new CompletableFuture<>();
                    pending.put(key, new Pending(input, shared));
                } else {
                    shared = inFlight.response;
                }
            }
            if (!created) {
                return shared.thenApply(response -> PlatformIdempotencyResult.replayed(cast(response)));
            }
            CompletableFuture<PlatformResponse<?>> destination = shared;
            CompletionStage<PlatformResponse<T>> source;
            try {
                source = operation.get();
            } catch (RuntimeException exception) {
                complete(key, input, destination, null, exception);
                return destination.thenApply(response -> PlatformIdempotencyResult.created(cast(response)));
            }
            source.whenComplete((response, failure) -> complete(key, input, destination, response, failure));
            return destination.thenApply(response -> PlatformIdempotencyResult.created(cast(response)));
        }

        private synchronized void complete(
                String key,
                PlatformIdempotencyInput input,
                CompletableFuture<PlatformResponse<?>> destination,
                PlatformResponse<?> response,
                Throwable failure) {
            pending.remove(key);
            if (failure != null) {
                destination.completeExceptionally(failure);
                return;
            }
            if (response == null) {
                destination.completeExceptionally(new IllegalArgumentException("Idempotent response is required."));
                return;
            }
            entries.put(key, new Entry(input, response, clock.instant()));
            destination.complete(response);
        }

        private synchronized void expire() {
            Instant cutoff = clock.instant().minus(RETENTION);
            entries.values().removeIf(entry -> !entry.createdAt.isAfter(cutoff));
        }

        private static boolean sameRequest(PlatformIdempotencyInput first, PlatformIdempotencyInput second) {
            return first.operation() == second.operation()
                    && first.requestHash().equals(second.requestHash());
        }

        private static void requireInput(PlatformIdempotencyInput input) {
            if (input == null
                    || input.principal() == null
                    || input.principal().isBlank()
                    || input.idempotencyKey() == null
                    || input.idempotencyKey().isBlank()
                    || input.operation() == null
                    || input.requestHash() == null
                    || input.requestHash().isBlank()) {
                throw new IllegalArgumentException("Platform idempotency input is invalid.");
            }
        }

        @SuppressWarnings("unchecked")
        private static <T> PlatformResponse<T> cast(PlatformResponse<?> response) {
            return (PlatformResponse<T>) response;
        }

        private record Entry(PlatformIdempotencyInput input, PlatformResponse<?> response, Instant createdAt) {}

        private record Pending(PlatformIdempotencyInput input, CompletableFuture<PlatformResponse<?>> response) {}
    }
}
