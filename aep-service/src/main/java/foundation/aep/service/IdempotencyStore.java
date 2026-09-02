package foundation.aep.service;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Supplier;

@FunctionalInterface
public interface IdempotencyStore {
    <T> CompletionStage<IdempotencyResult<T>> execute(
            IdempotencyInput input, Supplier<CompletionStage<ServiceResponse<T>>> operation);

    static IdempotencyStore inMemory(java.time.Clock clock) {
        return new InMemoryIdempotencyStore(clock);
    }

    final class InMemoryIdempotencyStore implements IdempotencyStore {
        private static final Duration RETENTION = Duration.ofHours(1);
        private final java.time.Clock clock;
        private final Map<String, Entry> entries = new LinkedHashMap<>();
        private final Map<String, Pending> pending = new LinkedHashMap<>();

        InMemoryIdempotencyStore(java.time.Clock clock) {
            this.clock = clock;
        }

        @Override
        public <T> CompletionStage<IdempotencyResult<T>> execute(
                IdempotencyInput input, Supplier<CompletionStage<ServiceResponse<T>>> operation) {
            String key = input.agentDid() + '\0' + input.idempotencyKey();
            CompletableFuture<ServiceResponse<?>> shared;
            boolean created;
            synchronized (this) {
                expire();
                Entry entry = entries.get(key);
                if (entry != null) {
                    if (!entry.input.command().equals(input.command())
                            || !entry.input.requestHash().equals(input.requestHash())) {
                        return CompletableFuture.completedFuture(IdempotencyResult.conflict());
                    }
                    return CompletableFuture.completedFuture(IdempotencyResult.replayed(cast(entry.response)));
                }
                Pending pendingEntry = pending.get(key);
                if (pendingEntry != null
                        && (!pendingEntry.input.command().equals(input.command())
                                || !pendingEntry.input.requestHash().equals(input.requestHash()))) {
                    return CompletableFuture.completedFuture(IdempotencyResult.conflict());
                }
                created = pendingEntry == null;
                if (created) {
                    shared = new CompletableFuture<>();
                    pending.put(key, new Pending(input, shared));
                } else {
                    shared = pendingEntry.response;
                }
            }
            if (!created) {
                return shared.thenApply(response -> IdempotencyResult.replayed(cast(response)));
            }
            CompletableFuture<ServiceResponse<?>> destination = shared;
            CompletionStage<ServiceResponse<T>> source;
            try {
                source = operation.get();
            } catch (RuntimeException exception) {
                complete(key, input, destination, null, exception);
                return destination.thenApply(response -> IdempotencyResult.created(cast(response)));
            }
            source.whenComplete((response, failure) -> complete(key, input, destination, response, failure));
            return destination.thenApply(response -> IdempotencyResult.created(cast(response)));
        }

        private synchronized void complete(
                String key,
                IdempotencyInput input,
                CompletableFuture<ServiceResponse<?>> destination,
                ServiceResponse<?> response,
                Throwable failure) {
            pending.remove(key);
            if (failure != null) {
                destination.completeExceptionally(failure);
                return;
            }
            entries.put(key, new Entry(input, response, clock.instant()));
            destination.complete(response);
        }

        private synchronized void expire() {
            Instant cutoff = clock.instant().minus(RETENTION);
            entries.values().removeIf(entry -> !entry.createdAt.isAfter(cutoff));
        }

        @SuppressWarnings("unchecked")
        private static <T> ServiceResponse<T> cast(ServiceResponse<?> response) {
            return (ServiceResponse<T>) response;
        }

        private record Entry(IdempotencyInput input, ServiceResponse<?> response, Instant createdAt) {}

        private record Pending(IdempotencyInput input, CompletableFuture<ServiceResponse<?>> response) {}
    }
}
